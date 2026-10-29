"""S1/S2 regressions, using only throwaway SQLite and in-process HTTP."""
from pathlib import Path
import re

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from server.app.config import Settings
from server.app.main import create_app
from server.app.models import User


@pytest.fixture
def admin(tmp_path):
    settings = Settings(
        _env_file=None, database_url=f"sqlite:///{tmp_path / 'csrf.db'}",
        bootstrap_token="test-admin-token-0123456789abcdef",
        trusted_proxy_auth_enabled=True, trusted_proxy_auth_secret="proxy-test-secret",
        trusted_proxy_auth_username_header="x-proxy-username",
        trusted_proxy_auth_groups_header="x-proxy-groups",
        trusted_proxy_auth_admin_groups="pushgate-admins",
        cors_allow_origins="https://admin.example.com", cors_allow_origin_regex=None,
    )
    app = create_app(settings)
    # No PUT admin route ships today. Exercise the same dependency for future ones.
    route = next(r for r in app.routes if getattr(r, 'path', None) == '/api/admin/users')
    guard = next(d.call for d in route.dependant.dependencies if d.call.__name__ == 'require_admin')
    app.add_api_route('/api/admin/users/{user_id}/csrf-probe', lambda: {},
                      methods=['PUT'], dependencies=[Depends(guard)])
    app.router.routes.insert(0, app.router.routes.pop())
    bearer = {"Authorization": "Bearer test-admin-token-0123456789abcdef"}
    proxy = {"X-Proxy-Username": "alice", "X-Proxy-Groups": "pushgate-admins",
             "X-PushGate-Proxy-Secret": "proxy-test-secret"}
    with TestClient(app) as client:
        response = client.post('/api/admin/users', headers=bearer, json={'username': 'csrf-target'})
        assert response.status_code == 201
        yield client, app, bearer, proxy, response.json()['data']['id']


@pytest.mark.parametrize('operation', ['lockout', 'totp'])
def test_hostile_form_post_cannot_change_user(admin, operation):
    client, app, bearer, proxy, uid = admin
    initial = client.post(f'/api/admin/users/{uid}/totp', headers=bearer)
    assert initial.status_code == 200
    original_seed = initial.json()['data']['secret']
    headers = {**proxy, 'Origin': 'https://evil.example.com',
               'Sec-Fetch-Site': 'same-site', 'Content-Type': 'application/x-www-form-urlencoded'}
    response = client.post(f'/api/admin/users/{uid}/{operation}', headers=headers, content='')
    assert response.status_code == 403
    assert response.json()['detail']['code'] == 'csrf_header_required'
    assert 'access-control-allow-origin' not in response.headers
    with app.state.db.SessionLocal() as db:
        user = db.get(User, uid)
        assert not user.locked
        assert user.totp_secret == original_seed
    # Same operation from the authorized UI works.
    good = client.post(f'/api/admin/users/{uid}/{operation}',
                       headers={**proxy, 'X-PushGate-CSRF': '1', 'Origin': 'https://admin.example.com'})
    assert good.status_code == 200
    with app.state.db.SessionLocal() as db:
        user = db.get(User, uid)
        assert user.locked if operation == 'lockout' else user.totp_secret != original_seed


@pytest.mark.parametrize('method,path,payload', [
    ('POST', '/lockout', None), ('DELETE', '/lockout', None),
    ('PATCH', '', {'display_name': 'Updated'}),
    ('PUT', '/csrf-probe', {}),
])
@pytest.mark.parametrize('marker', [None, '', '0'])
def test_proxy_unsafe_methods_require_exact_marker(admin, method, path, payload, marker):
    client, _, _, proxy, uid = admin
    headers = dict(proxy)
    if marker is not None:
        headers['X-PushGate-CSRF'] = marker
    response = client.request(method, f'/api/admin/users/{uid}{path}', headers=headers, json=payload)
    assert response.status_code == 403
    assert response.json()['detail']['code'] == 'csrf_header_required'
    allowed = client.request(method, f'/api/admin/users/{uid}{path}',
                             headers={**proxy, 'X-PushGate-CSRF': '1'}, json=payload)
    assert allowed.status_code == 200


def test_proxy_reads_and_bearer_api_keys_still_work(admin):
    client, _, bearer, proxy, uid = admin
    assert client.get('/api/admin/users', headers=proxy).status_code == 200
    issued = client.post('/api/admin/rbac/api-keys', headers=bearer, json={'name': 'automation', 'role': 'admin'})
    assert issued.status_code == 201
    key_auth = {'Authorization': 'Bearer ' + issued.json()['data']['token']}
    for headers in (bearer, key_auth):
        assert client.post(f'/api/admin/users/{uid}/lockout', headers=headers).status_code == 200
        assert client.delete(f'/api/admin/users/{uid}/lockout', headers=headers).status_code == 200
    # A bearer header does not exempt requests actually authenticated by the proxy.
    assert client.post(f'/api/admin/users/{uid}/lockout', headers={**bearer, **proxy}).status_code == 403


def test_cors_allows_only_explicit_admin_origin(admin):
    client, _, _, _, uid = admin
    for origin, status in [('https://evil.example.com', 400), ('https://admin.example.com', 200)]:
        response = client.options(f'/api/admin/users/{uid}/lockout', headers={
            'Origin': origin, 'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'X-PushGate-CSRF',
        })
        assert response.status_code == status
        assert response.headers.get('access-control-allow-origin') == (origin if status == 200 else None)


def test_all_certifi_locks_are_patched():
    root = Path(__file__).resolve().parents[1]
    found = 0
    for path in root.rglob('requirements*.lock'):
        for version in re.findall(r'^certifi==([\d.]+)', path.read_text(), re.M):
            assert tuple(map(int, version.split('.'))) >= (2026, 10, 18), str(path)
            found += 1
    assert found >= 2
