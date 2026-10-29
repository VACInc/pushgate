"""Creation-only credentials: real route authorization and online-only boundary."""
import base64
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import ApiKey, AuthRequest, ProvisionedIntegration
from qa.test_server_hardening import signed_post, signed_get

ADMIN = {"Authorization": "Bearer isolated-test-operator-0123456789"}

@pytest.fixture
def env(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}",
                              bootstrap_token=ADMIN['Authorization'][7:], trusted_session_window_seconds=3600))
    with TestClient(app) as c:
        def call(method, path, body=None, headers=ADMIN):
            r = c.request(method, '/api/admin/' + path, json=body, headers=headers)
            assert r.status_code in (200, 201), r.text
            return r.json()['data']
        principal = call('POST', 'users', {'username': 'serviceuser', 'fail_mode': 'open'})
        approver = call('POST', 'users', {'username': 'operator'})
        private = Ed25519PrivateKey.generate()
        pub = base64.b64encode(private.public_key().public_bytes_raw()).decode()
        device = call('POST', 'devices', {'user_id': approver['id'], 'name': 'real', 'public_key': pub})
        def issue():
            return call('POST', 'rbac/provisioners', dict(name='test', principal_username='serviceuser',
                                                        approver_username='operator', systems=['server01', 'other']))
        key = issue()
        scoped = {'Authorization': 'Bearer ' + key['token']}
        body = dict(name='SSH server01', principal_username='serviceuser', approver_username='operator',
                    system_name='server01', system_type='linux-pam', fail_mode='closed', enabled=True)
        yield c, app, call, principal, approver, device, pub, key, scoped, body, issue


def test_scoped_create_reuse_disable_and_ownership(env):
    c, app, call, *rest = env
    principal, approver, device, pub, key, scoped, body, issue = rest
    who = call('GET', 'whoami', headers=scoped)
    assert who['key_id'] == key['id']
    assert who['permissions'] == dict(read=False, write=False, admin=False)
    created = call('POST', 'integrations', body, scoped)
    assert created['secret']
    rows = call('GET', 'integrations', headers=scoped)
    assert len(rows) == 1 and 'secret' not in rows[0]
    assert c.post('/api/admin/integrations', json=body, headers=scoped).status_code == 409
    second = {'Authorization': 'Bearer ' + issue()['token']}
    path = 'integrations/' + created['id']
    assert c.patch('/api/admin/' + path, json={'enabled': False}, headers=second).status_code == 403
    for patch in ({'enabled': True}, {'enabled': False, 'unknown': 1}, {'enabled': False, 'name': 'x'},
                  {'approver_username': 'serviceuser'}, {'fail_mode': 'open'}):
        assert c.patch('/api/admin/' + path, json=patch, headers=scoped).status_code == 403
    assert call('PATCH', path, {'enabled': False}, scoped)['enabled'] is False
    assert call('GET', path, headers=scoped)['enabled'] is False
    assert c.post('/api/admin/integrations', json=body, headers=scoped).status_code == 409


@pytest.mark.parametrize('change', [dict(system_name='evil'), dict(principal_username='operator'),
    dict(approver_username='serviceuser'), dict(system_type='web'), dict(fail_mode='open'),
    dict(enabled=False), dict(client_id='chosen'), dict(name='arbitrary')])
def test_binding_constraints(env, change):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    assert c.post('/api/admin/integrations', headers=scoped, json=body | change).status_code == 403
    assert call('GET', 'integrations', headers=scoped) == []


def test_denies_valid_mutations_and_broad_reads(env):
    c, _, call, user, approver, device, pub, key, scoped, body, _ = env
    integration = call('POST', 'integrations', body)
    policy = call('POST', 'policies', dict(name='test-policy', subject_type='user', subject_id=user['id']))
    role = call('POST', 'rbac/roles', dict(name='test-role', permissions={'read': True}))
    actions = [
        ('POST', 'devices', dict(user_id=approver['id'], name='attacker', public_key=pub)),
        ('PATCH', 'devices/'+device['id'], dict(public_key=pub)),
        ('POST', 'devices/'+device['id']+'/rotation', {}),
        ('DELETE', 'devices/'+device['id'], None),
        ('POST', 'users', dict(username='attacker')),
        ('PATCH', 'users/'+user['id'], dict(locked=False)),
        ('DELETE', 'users/'+user['id']+'/lockout', None),
        ('POST', 'users/'+user['id']+'/totp', {}),
        ('POST', 'users/'+user['id']+'/backup-codes', {}),
        ('PATCH', 'settings/global', dict(global_fail_mode='open')),
        ('POST', 'policies', dict(name='evil', subject_type='global')),
        ('PATCH', 'policies/'+policy['id'], dict(fail_mode='open')),
        ('DELETE', 'policies/'+policy['id'], None),
        ('POST', 'rbac/api-keys', dict(name='evil', role='admin')),
        ('PATCH', 'rbac/api-keys/'+key['id'], dict(role='admin')),
        ('DELETE', 'rbac/api-keys/'+key['id'], None),
        ('POST', 'rbac/provisioners', dict(name='evil', principal_username='serviceuser', approver_username='operator', systems=['evil'])),
        ('POST', 'rbac/roles', dict(name='evil', permissions={'admin': True})),
        ('PATCH', 'rbac/roles/'+role['id'], dict(permissions={'admin': True})),
        ('DELETE', 'rbac/roles/'+role['id'], None),
        ('PATCH', 'integrations/'+integration['id'], dict(enabled=False)),
        ('DELETE', 'integrations/'+integration['id'], None),
    ]
    snapshots = {p: call('GET', p) for p in ['users', 'devices', 'policies', 'integrations', 'rbac/roles']}
    for method, path, data in actions:
        r = c.request(method, '/api/admin/'+path, json=data, headers=scoped)
        assert r.status_code == 403, (method, path, r.text)
    for path, before in snapshots.items():
        assert call('GET', path) == before
    for path in ['users', 'devices', 'policies', 'settings/global', 'rbac/roles', 'rbac/api-keys']:
        assert c.get('/api/admin/'+path, headers=scoped).status_code == 403


def test_no_factors_or_self_approval(env):
    c, app, call, user, _, device, _, _, scoped, body, _ = env
    call('POST', 'users/'+user['id']+'/totp', {})
    codes = call('POST', 'users/'+user['id']+'/backup-codes', {})
    integration = call('POST', 'integrations', body, scoped)
    path = '/api/v1/auth/requests'
    r = signed_post(c, integration, path, {'username': 'serviceuser'}, 'first')
    assert r.status_code == 201, r.text
    data = r.json()['data']
    assert data['status'] == 'pending' and data['fail_mode'] == 'closed'
    assert not {'totp_secret', 'last_totp_counter', 'backup_code_hashes'} & data['cache'].keys()
    for field, value in [('username', 'operator'), ('approver_username', 'serviceuser'), ('system', 'evil'), ('offline_code', '123456')]:
        r = signed_post(c, integration, path, {'username': 'serviceuser', field: value}, 'bad-'+field)
        assert r.status_code == 403, r.text
    assert c.post(path, json={'username': 'serviceuser'}, headers=scoped).status_code == 401
    r = c.post(path+'/'+data['id']+'/decision', headers=scoped,
               json=dict(device_id=device['id'], decision='approve', signature=base64.b64encode(b'0'*64).decode()))
    assert r.status_code == 403, r.text
    pending_device = call('POST', 'devices', dict(user_id=env[4]['id'], name='pending'))
    r = c.post('/api/v1/devices/'+pending_device['id']+'/enroll', headers=scoped,
               json=dict(enrollment_token=scoped['Authorization'][7:], public_key=env[6]))
    assert r.status_code == 403, r.text
    polled = signed_get(c, integration, path+'/'+data['id'], 'poll')
    assert 'totp_secret' not in polled.json()['data']['cache']


def test_fleet_wildcard_scope(env):
    c, _, call, *_ = env
    fleet = call('POST', 'rbac/provisioners', dict(name='fleet', principal_username='serviceuser',
                                                  approver_username='operator', systems=['*']))
    scoped = {'Authorization': 'Bearer ' + fleet['token']}
    body = dict(name='SSH newhost', principal_username='serviceuser', approver_username='operator',
                system_name='newhost', system_type='linux-pam', fail_mode='closed', enabled=True)
    created = call('POST', 'integrations', body, scoped)
    assert created['secret'] and created['system_name'] == 'newhost'
    # Same fixed binding as a listed scope: no other principal, approver, or fail mode.
    for change in (dict(principal_username='operator'), dict(approver_username='serviceuser'), dict(fail_mode='open'),
                   dict(system_type='web'), dict(client_id='chosen'), dict(name='arbitrary')):
        other = body | dict(system_name='another', name='SSH another') | change
        assert c.post('/api/admin/integrations', json=other, headers=scoped).status_code == 403
    # Non-canonical names (case, whitespace, lookalikes) are refused.
    for name in ('NEWHOST', 'newhost ', 'nеwhost', '-lead', 'a/b'):
        weird = body | dict(system_name=name, name='SSH ' + name)
        assert c.post('/api/admin/integrations', json=weird, headers=scoped).status_code == 403, name
    # Cannot take over a system that is already bound, by anyone.
    native = call('POST', 'integrations', body | dict(system_name='native', name='SSH native'))
    taken = body | dict(system_name='native', name='SSH native')
    assert c.post('/api/admin/integrations', json=taken, headers=scoped).status_code == 409
    assert c.patch('/api/admin/integrations/' + native['id'], json={'enabled': False}, headers=scoped).status_code == 403
    assert call('PATCH', 'integrations/' + created['id'], {'enabled': False}, scoped)['enabled'] is False
    # Unbound (system_name=None) integrations stay invisible.
    plain = call('POST', 'integrations', dict(name='web', system_type='web'))
    assert plain['id'] not in {i['id'] for i in call('GET', 'integrations', headers=scoped)}
    assert c.get('/api/admin/integrations/' + plain['id'], headers=scoped).status_code == 403
    # Wildcard must stand alone.
    for systems in (['*', 'server01'], ['server01', '*'], ['*', '*'], ['a*']):
        r = c.post('/api/admin/rbac/provisioners', headers=ADMIN, json=dict(
            name='bad', principal_username='serviceuser', approver_username='operator', systems=systems))
        assert r.status_code == 422, systems


def test_listed_scope_still_rejects_unlisted_system(env):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    other = body | dict(system_name='newhost', name='SSH newhost')
    assert c.post('/api/admin/integrations', json=other, headers=scoped).status_code == 403


def test_concurrent_creation_reserves_system(env):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(pool.map(lambda _: c.post('/api/admin/integrations', json=body, headers=scoped).status_code, range(4)))
    assert sorted(codes) == [201, 409, 409, 409]
    assert len(call('GET', 'integrations', headers=scoped)) == 1


def test_trust_bypass_disabled_and_scope_survives_role_edit(env):
    from server.app.models import now
    c, app, call, user, approver, _, _, key, scoped, body, _ = env
    integration = call('POST', 'integrations', body, scoped)
    r = signed_post(c, integration, '/api/v1/auth/requests', {'username': 'serviceuser'}, 'before-trust')
    request_id = r.json()['data']['id']
    with app.state.db.SessionLocal() as db:
        row = db.get(AuthRequest, request_id)
        row.status = 'approved'
        row.factor = 'push'
        row.consumed_at = now()
        row.decided_at = now()
        db.commit()
    r = signed_post(c, integration, '/api/v1/auth/requests', {'username': 'serviceuser'}, 'after-trust')
    assert r.json()['data']['status'] == 'pending'
    call('PATCH', 'rbac/api-keys/'+key['id'], {'role': 'admin'})
    assert call('GET', 'whoami', headers=scoped)['permissions']['admin'] is False
    assert c.get('/api/admin/devices', headers=scoped).status_code == 403
    call('PATCH', 'rbac/api-keys/'+key['id'], {'enabled': False})
    assert c.get('/api/admin/whoami', headers=scoped).status_code == 403


def test_reuse_visibility_missing_scope_and_reservation(env):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    legacy = call('POST', 'integrations', body)
    other = call('POST', 'integrations', body | {'system_name': 'outside'})
    assert [i['id'] for i in call('GET', 'integrations', headers=scoped)] == [legacy['id']]
    assert c.get('/api/admin/integrations/'+other['id'], headers=scoped).status_code == 403
    assert c.post('/api/admin/integrations', json=body, headers=scoped).status_code == 409
    raw = call('POST', 'rbac/api-keys', {'name': 'unscoped', 'role': 'integration-provisioner'})
    assert c.get('/api/admin/whoami', headers={'Authorization': 'Bearer '+raw['token']}).status_code == 403
    created = call('POST', 'integrations', body | {'system_name': 'other', 'name': 'SSH other'}, scoped)
    assert c.post('/api/admin/integrations', json=body | {'system_name': 'other'}, headers=ADMIN).status_code == 409
    assert c.patch('/api/admin/integrations/'+legacy['id'], json={'system_name': 'other'}, headers=ADMIN).status_code == 409
    assert c.patch('/api/admin/integrations/'+created['id'], json={'approver_username': 'serviceuser'}, headers=ADMIN).status_code == 403


def test_additive_schema_upgrade(tmp_path):
    import sqlite3
    from server.app.db import Database
    path = tmp_path / 'legacy.db'
    # Full old schema, without importing old application or touching source checkout.
    from sqlalchemy import create_engine
    from server.app.db import Base
    engine = create_engine(f'sqlite:///{path}')
    Base.metadata.create_all(engine, tables=[t for t in Base.metadata.sorted_tables
                                            if t.name not in {'provisioner_scopes', 'provisioned_integrations'}])
    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO integrations (id,name,client_id,secret,system_type,enabled,created_at) VALUES ('old','old','old-client','old-secret','linux-pam',1,CURRENT_TIMESTAMP)")
    before = sqlite3.connect(path).execute('SELECT * FROM integrations').fetchall()
    db = Database(f'sqlite:///{path}')
    db.init()
    db.init()
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT * FROM integrations').fetchall() == before
        assert conn.execute('SELECT count(*) FROM provisioner_scopes').fetchone() == (0,)
        assert conn.execute('SELECT count(*) FROM provisioned_integrations').fetchone() == (0,)


@pytest.mark.parametrize('round_number', range(12))
def test_repeated_multi_key_create_race(env, round_number):
    c, _, call, _, _, _, _, _, scoped, body, issue = env
    second = {'Authorization': 'Bearer ' + issue()['token']}
    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(lambda n: c.post('/api/admin/integrations', json=body,
                                              headers=scoped if n % 2 else second).status_code, range(8)))
    assert sorted(codes) == [201] + [409] * 7
    assert len(call('GET', 'integrations', headers=scoped)) == 1


@pytest.mark.parametrize('round_number', range(12))
def test_repeated_general_rebind_race(env, round_number):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    legacy = call('POST', 'integrations', body | {'system_name': 'outside'})
    def race(n):
        if n:
            return c.patch('/api/admin/integrations/'+legacy['id'], headers=ADMIN,
                           json={'system_name': 'server01'}).status_code
        return c.post('/api/admin/integrations', json=body, headers=scoped).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(race, range(2)))
    assert codes in ([201, 409], [409, 200])
    assert len(call('GET', 'integrations', headers=scoped)) == 1


@pytest.mark.parametrize('round_number', range(12))
def test_repeated_general_create_race(env, round_number):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(lambda headers: c.post('/api/admin/integrations', json=body,
                                                    headers=headers).status_code, [ADMIN, scoped]))
    assert sorted(codes) == [201, 409]
    assert len(call('GET', 'integrations', headers=scoped)) == 1


def test_server_attests_online_only_not_client(env):
    c, _, call, _, _, _, _, _, scoped, body, _ = env
    legacy = call('POST', 'integrations', body | {'system_name': 'other', 'online_only': True})
    created = call('POST', 'integrations', body, scoped)
    assert legacy['online_only'] is False
    assert created['online_only'] is True
    for integration in (legacy, created):
        expected = integration['id'] == created['id']
        assert call('GET', 'integrations/'+integration['id'], headers=scoped)['online_only'] is expected
        metadata = {i['id']: i for i in call('GET', 'integrations', headers=scoped)}
        assert metadata[integration['id']]['online_only'] is expected
        response = signed_post(c, integration, '/api/v1/auth/preflight', {'username': 'serviceuser'}, 'preflight-attestation')
        assert response.status_code == 200
        assert response.json()['data']['online_only'] is expected
    assert call('PATCH', 'integrations/'+created['id'], {'enabled': False}, scoped)['online_only'] is True


def test_bounded_contention_clean_503_and_loop_responsive(env):
    import time
    from sqlalchemy import text
    c, app, call, _, _, _, _, _, scoped, body, _ = env
    with app.state.db.engine.connect() as conn:
        conn.execute(text('BEGIN IMMEDIATE'))
        with ThreadPoolExecutor(max_workers=1) as pool:
            start = time.monotonic()
            pending = pool.submit(c.post, '/api/admin/integrations', json=body, headers=scoped)
            time.sleep(0.15)
            health_start = time.monotonic()
            assert c.get('/healthz').status_code == 200
            assert time.monotonic() - health_start < 1
            response = pending.result(timeout=8)
            assert response.status_code == 503, response.text
            assert response.json()['detail']['code'] == 'database_busy'
            assert time.monotonic() - start < 8
        conn.rollback()
    assert call('GET', 'integrations', headers=scoped) == []
