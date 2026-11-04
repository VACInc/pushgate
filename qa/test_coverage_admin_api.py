"""Admin API branches: RBAC, not-found/conflict mapping, filters, rate limiting and
database error mapping. Every test uses a temporary SQLite database."""
from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import event, insert
from sqlalchemy.exc import DataError, OperationalError

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import Integration, Setting

ADMIN_TOKEN = "test-admin-token-0123456789abcdef"
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def make_app(tmp_path: Path, name: str = "admin.db", **extra):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / name}", bootstrap_token=ADMIN_TOKEN, **extra))


@pytest.fixture()
def client(tmp_path: Path):
    app = make_app(tmp_path)
    with TestClient(app, raise_server_exceptions=False) as c:
        c.app_state = app.state
        yield c


def call(c: TestClient, method: str, path: str, expected: int | tuple[int, ...] = (200, 201), headers=ADMIN, **kwargs):
    response = c.request(method, path, headers=headers, **kwargs)
    expected = (expected,) if isinstance(expected, int) else expected
    assert response.status_code in expected, (method, path, response.status_code, response.text)
    return response


def code_of(response) -> str:
    return response.json()["detail"]["code"]


def ed25519_public() -> str:
    return base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()


def p256_public() -> str:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return base64.b64encode(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


# --- authentication and RBAC -------------------------------------------------------------------


def test_bearer_token_errors_and_read_write_admin_scopes(client: TestClient) -> None:
    assert code_of(call(client, "GET", "/api/admin/users", 401, headers={})) == "missing_token"
    assert code_of(call(client, "GET", "/api/admin/users", 401, headers={"Authorization": "Basic abc"})) == "missing_token"
    assert code_of(call(client, "GET", "/api/admin/users", 403, headers={"Authorization": "Bearer nope"})) == "invalid_token"

    reader = call(client, "POST", "/api/admin/rbac/api-keys", json={"name": "reader", "role": "read-only"}).json()["data"]
    writer = call(client, "POST", "/api/admin/rbac/api-keys", json={"name": "writer", "role": "read-write"}).json()["data"]
    reader_h = {"Authorization": f"Bearer {reader['token']}"}
    writer_h = {"Authorization": f"Bearer {writer['token']}"}

    call(client, "GET", "/api/admin/users", 200, headers=reader_h)
    assert code_of(call(client, "POST", "/api/admin/users", 403, headers=reader_h, json={"username": "x"})) == "insufficient_scope"
    call(client, "POST", "/api/admin/users", 201, headers=writer_h, json={"username": "x"})
    assert code_of(call(client, "POST", "/api/admin/rbac/api-keys", 403, headers=writer_h, json={"name": "k"})) == "admin_required"
    who = call(client, "GET", "/api/admin/whoami", headers=writer_h).json()["data"]
    assert who["role"] == "read-write" and "capabilities" not in who
    # The plaintext token is returned once; the stored hash never.
    listed = call(client, "GET", "/api/admin/rbac/api-keys").json()["data"]
    assert all("token" not in row and "token_hash" not in row for row in listed)
    assert call(client, "GET", f"/api/admin/rbac/api-keys/{reader['id']}").json()["data"]["name"] == "reader"

    # Disabling a key takes effect on the next request.
    call(client, "DELETE", f"/api/admin/rbac/api-keys/{reader['id']}", 204)
    assert code_of(call(client, "GET", "/api/admin/users", 403, headers=reader_h)) == "invalid_token"
    call(client, "DELETE", "/api/admin/rbac/api-keys/missing", 204)


def test_custom_roles_lifecycle_and_disabled_role_fails_closed(client: TestClient) -> None:
    assert code_of(call(client, "POST", "/api/admin/rbac/roles", 409, json={"name": "admin"})) == "built_in_role"
    role = call(client, "POST", "/api/admin/rbac/roles", json={"name": "auditor", "permissions": {"write": True}}).json()["data"]
    assert role["permissions"] == {"read": True, "write": True, "admin": False}
    assert code_of(call(client, "POST", "/api/admin/rbac/roles", 409, json={"name": "auditor"})) == "duplicate_role"

    patched = call(client, "PATCH", f"/api/admin/rbac/roles/{role['id']}", json={"permissions": {"read": True}}).json()["data"]
    assert patched["permissions"] == {"read": True, "write": False, "admin": False}
    call(client, "PATCH", f"/api/admin/rbac/roles/{role['id']}", json={"description": "audit only"})
    assert code_of(call(client, "PATCH", "/api/admin/rbac/roles/missing", 404, json={})) == "not_found"
    assert code_of(call(client, "GET", "/api/admin/rbac/roles/missing", 404)) == "not_found"
    assert call(client, "GET", f"/api/admin/rbac/roles/{role['id']}").json()["data"]["name"] == "auditor"

    roles = {row["name"]: row for row in call(client, "GET", "/api/admin/rbac/roles").json()["data"]}
    assert roles["admin"]["built_in"] is True
    assert code_of(call(client, "PATCH", f"/api/admin/rbac/roles/{roles['admin']['id']}", 409, json={"description": "x"})) == "built_in_role"
    assert code_of(call(client, "DELETE", f"/api/admin/rbac/roles/{roles['admin']['id']}", 409)) == "built_in_role"

    key = call(client, "POST", "/api/admin/rbac/api-keys", json={"name": "aud", "role": "auditor"}).json()["data"]
    key_h = {"Authorization": f"Bearer {key['token']}"}
    call(client, "GET", "/api/admin/users", 200, headers=key_h)
    call(client, "DELETE", f"/api/admin/rbac/roles/{role['id']}", 204)
    call(client, "DELETE", "/api/admin/rbac/roles/missing", 204)
    # The key still exists but its role is disabled: every request is refused.
    assert code_of(call(client, "GET", "/api/admin/users", 403, headers=key_h)) == "role_disabled"
    # A disabled or unknown role can never be assigned.
    assert code_of(call(client, "POST", "/api/admin/rbac/api-keys", 422, json={"name": "k", "role": "auditor"})) == "unknown_role"
    assert code_of(call(client, "PATCH", f"/api/admin/rbac/api-keys/{key['id']}", 422, json={"role": "ghost"})) == "unknown_role"
    call(client, "PATCH", f"/api/admin/rbac/api-keys/{key['id']}", json={"role": "read-only", "name": "renamed"})
    call(client, "GET", "/api/admin/users", 200, headers=key_h)
    assert code_of(call(client, "PATCH", "/api/admin/rbac/api-keys/missing", 404, json={})) == "not_found"
    assert code_of(call(client, "GET", "/api/admin/rbac/api-keys/missing", 404)) == "not_found"


def test_read_disabled_role_cannot_read(client: TestClient) -> None:
    call(client, "POST", "/api/admin/rbac/roles", json={"name": "write-only", "permissions": {"read": False, "write": True}})
    key = call(client, "POST", "/api/admin/rbac/api-keys", json={"name": "w", "role": "write-only"}).json()["data"]
    headers = {"Authorization": f"Bearer {key['token']}"}
    assert code_of(call(client, "GET", "/api/admin/users", 403, headers=headers)) == "insufficient_scope"
    call(client, "POST", "/api/admin/users", 201, headers=headers, json={"username": "made-by-writer"})


def test_bootstrap_disabled_when_unset(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'nob.db'}", bootstrap_token=None))
    with TestClient(app) as c:
        assert code_of(call(c, "GET", "/api/admin/users", 403, headers=ADMIN)) == "invalid_token"


def test_trusted_proxy_role_and_group_branches(tmp_path: Path) -> None:
    secret = "proxy-shared-secret-123"
    app = make_app(
        tmp_path,
        trusted_proxy_auth_enabled=True,
        trusted_proxy_auth_secret=secret,
        trusted_proxy_auth_admin_groups="ops; pushgate-admins",
        trusted_proxy_auth_role="missing-role",
    )
    base = {"x-proxy-username": "alice", "x-pushgate-proxy-secret": secret}
    with TestClient(app) as c:
        # Separators ',', '|' and ';' all split group lists.
        assert code_of(call(c, "GET", "/api/admin/users", 403, headers={**base, "x-proxy-groups": "a|b;c"})) == "proxy_group_required"
        assert code_of(call(c, "GET", "/api/admin/users", 403, headers=base)) == "proxy_group_required"
        assert code_of(call(c, "GET", "/api/admin/users", 403, headers={**base, "x-proxy-groups": "x|ops"})) == "role_disabled"
        assert code_of(call(c, "POST", "/api/admin/users", 403, headers={**base, "x-proxy-groups": "ops"}, json={"username": "u"})) == "csrf_header_required"
        bad = {**base, "x-pushgate-proxy-secret": "wrong", "x-proxy-groups": "ops"}
        assert code_of(call(c, "GET", "/api/admin/users", 403, headers=bad)) == "untrusted_proxy"
        app.state.settings.trusted_proxy_auth_role = "read-only"
        who = call(c, "GET", "/api/admin/whoami", headers={**base, "x-proxy-groups": "ops"}).json()["data"]
        assert who == {"actor": "proxy:alice", "role": "read-only", "permissions": {"read": True, "write": False, "admin": False}}
        # Without the username header the bearer path applies even when proxy auth is on.
        call(c, "GET", "/api/admin/users", 200, headers=ADMIN)


def test_trusted_proxy_without_required_groups_admits_any_group(tmp_path: Path) -> None:
    secret = "proxy-shared-secret-123"
    app = make_app(tmp_path, trusted_proxy_auth_enabled=True, trusted_proxy_auth_secret=secret, trusted_proxy_auth_admin_groups="")
    with TestClient(app) as c:
        call(c, "GET", "/api/admin/users", 200, headers={"x-proxy-username": "bob", "x-pushgate-proxy-secret": secret})


def test_trusted_proxy_requires_a_secret_at_startup(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="PUSHGATE_TRUSTED_PROXY_AUTH_SECRET"):
        make_app(tmp_path, trusted_proxy_auth_enabled=True)


# --- CRUD not-found / conflict mapping ---------------------------------------------------------


def test_user_routes_not_found_conflict_and_delete(client: TestClient) -> None:
    user = call(client, "POST", "/api/admin/users", json={"username": "alice"}).json()["data"]
    assert code_of(call(client, "POST", "/api/admin/users", 409, json={"username": "alice"})) == "duplicate_user"
    for method, path in (
        ("GET", "/api/admin/users/missing"),
        ("PATCH", "/api/admin/users/missing"),
        ("POST", "/api/admin/users/missing/lockout"),
        ("DELETE", "/api/admin/users/missing/lockout"),
        ("POST", "/api/admin/users/missing/totp"),
        ("POST", "/api/admin/users/missing/backup-codes"),
        ("GET", "/api/admin/users/missing/backup-codes"),
        ("DELETE", "/api/admin/users/missing/backup-codes"),
    ):
        kwargs = {"json": {}} if method == "PATCH" else {}
        assert code_of(call(client, method, path, 404, **kwargs)) == "not_found"
    call(client, "PATCH", f"/api/admin/users/{user['id']}", json={"display_name": "Alice", "fail_mode": "open"})
    assert call(client, "GET", f"/api/admin/users/{user['id']}").json()["data"]["display_name"] == "Alice"
    unlocked = call(client, "DELETE", f"/api/admin/users/{user['id']}/lockout").json()["data"]
    assert unlocked["locked"] is False
    totp = call(client, "POST", f"/api/admin/users/{user['id']}/totp").json()["data"]
    assert totp["uri"].startswith("otpauth://totp/") and "totp_secret" not in call(client, "GET", f"/api/admin/users/{user['id']}").json()["data"]
    codes = call(client, "POST", f"/api/admin/users/{user['id']}/backup-codes", params={"count": 2}).json()["data"]["codes"]
    assert len(codes) == 2
    rows = call(client, "GET", f"/api/admin/users/{user['id']}/backup-codes").json()["data"]
    assert len(rows) == 2 and all("code_hash" not in row for row in rows)
    call(client, "DELETE", f"/api/admin/backup-codes/{rows[0]['id']}", 204)
    call(client, "DELETE", "/api/admin/backup-codes/missing", 204)
    call(client, "DELETE", f"/api/admin/users/{user['id']}/backup-codes", 204)
    assert call(client, "GET", f"/api/admin/users/{user['id']}/backup-codes").json()["data"] == []
    call(client, "DELETE", f"/api/admin/users/{user['id']}", 204)
    call(client, "DELETE", f"/api/admin/users/{user['id']}", 204)
    assert code_of(call(client, "GET", f"/api/admin/users/{user['id']}", 404)) == "not_found"


def test_group_routes_membership_and_conflicts(client: TestClient) -> None:
    user = call(client, "POST", "/api/admin/users", json={"username": "gina"}).json()["data"]
    group = call(client, "POST", "/api/admin/groups", json={"name": "ops"}).json()["data"]
    other = call(client, "POST", "/api/admin/groups", json={"name": "dev"}).json()["data"]
    assert code_of(call(client, "POST", "/api/admin/groups", 409, json={"name": "ops"})) == "duplicate_group"
    assert code_of(call(client, "PATCH", f"/api/admin/groups/{other['id']}", 409, json={"name": "ops"})) == "duplicate_group"
    call(client, "PATCH", f"/api/admin/groups/{other['id']}", json={"description": "developers"})
    for method, path in (("GET", "/api/admin/groups/missing"), ("PATCH", "/api/admin/groups/missing"), ("GET", "/api/admin/groups/missing/users")):
        kwargs = {"json": {}} if method == "PATCH" else {}
        assert code_of(call(client, method, path, 404, **kwargs)) == "not_found"
    assert code_of(call(client, "POST", f"/api/admin/groups/missing/users/{user['id']}", 404)) == "group_not_found"
    assert code_of(call(client, "POST", f"/api/admin/groups/{group['id']}/users/missing", 404)) == "user_not_found"
    first = call(client, "POST", f"/api/admin/groups/{group['id']}/users/{user['id']}").json()["data"]
    again = call(client, "POST", f"/api/admin/groups/{group['id']}/users/{user['id']}").json()["data"]
    assert first["id"] == again["id"]
    assert [row["username"] for row in call(client, "GET", f"/api/admin/groups/{group['id']}/users").json()["data"]] == ["gina"]
    assert [row["name"] for row in call(client, "GET", "/api/admin/groups").json()["data"]] == ["dev", "ops"]
    assert call(client, "GET", f"/api/admin/groups/{group['id']}").json()["data"]["name"] == "ops"
    call(client, "DELETE", f"/api/admin/groups/{group['id']}/users/{user['id']}", 204)
    call(client, "DELETE", f"/api/admin/groups/{group['id']}/users/{user['id']}", 204)
    call(client, "POST", f"/api/admin/groups/{group['id']}/users/{user['id']}")
    # Deleting a group removes its memberships first.
    call(client, "DELETE", f"/api/admin/groups/{group['id']}", 204)
    call(client, "DELETE", f"/api/admin/groups/{group['id']}", 204)
    assert code_of(call(client, "GET", f"/api/admin/groups/{group['id']}", 404)) == "not_found"


def test_device_admin_routes_and_key_type_validation(client: TestClient) -> None:
    user = call(client, "POST", "/api/admin/users", json={"username": "dora"}).json()["data"]
    other = call(client, "POST", "/api/admin/users", json={"username": "otto"}).json()["data"]
    assert code_of(call(client, "POST", "/api/admin/devices", 404, json={"user_id": "missing", "name": "x"})) == "user_not_found"
    device = call(client, "POST", "/api/admin/devices", json={"user_id": user["id"], "name": "phone", "public_key": ed25519_public()}).json()["data"]
    call(client, "POST", "/api/admin/devices", json={"user_id": other["id"], "name": "pending"})
    assert [d["name"] for d in call(client, "GET", "/api/admin/devices", params={"user_id": user["id"]}).json()["data"]] == ["phone"]
    assert len(call(client, "GET", "/api/admin/devices").json()["data"]) == 2
    for method, path in (("GET", "/api/admin/devices/missing"), ("PATCH", "/api/admin/devices/missing"), ("POST", "/api/admin/devices/missing/rotation")):
        kwargs = {"json": {}} if method == "PATCH" else {}
        assert code_of(call(client, method, path, 404, **kwargs)) == "not_found"
    call(client, "DELETE", "/api/admin/devices/missing", 204)

    path = f"/api/admin/devices/{device['id']}"
    assert code_of(call(client, "PATCH", path, 422, json={"key_type": None})) == "bad_key_type"
    # Changing only the key type re-validates the stored key against it.
    assert code_of(call(client, "PATCH", path, 422, json={"key_type": "ecdsa_p256"})) == "bad_public_key"
    assert code_of(call(client, "PATCH", path, 422, json={"public_key": "not-base64!"})) == "bad_public_key"
    switched = call(client, "PATCH", path, json={"key_type": "ecdsa_p256", "public_key": p256_public()}).json()["data"]
    assert switched["key_type"] == "ecdsa_p256" and switched["enrolled_at"]
    cleared = call(client, "PATCH", path, json={"public_key": None}).json()["data"]
    assert cleared["public_key"] is None and cleared["enrolled_at"] is None
    patched = call(client, "PATCH", path, json={"name": "renamed", "push_token": "fcm-token", "require_biometric": True}).json()["data"]
    assert patched["push_token_configured"] is True and "push_token" not in patched
    audits = call(client, "GET", "/api/admin/audit-logs", params={"resource_id": device["id"], "action": "device.update"}).json()["data"]
    assert all("push_token" not in row["detail"] for row in audits)
    assert any(row["detail"].get("push_token_configured") is True for row in audits)


def test_integration_routes_not_found_and_client_id_conflicts(client: TestClient) -> None:
    created = call(client, "POST", "/api/admin/integrations", json={"name": "a", "client_id": "client-a"}).json()["data"]
    assert created["secret"] and created["online_only"] is False
    assert code_of(call(client, "POST", "/api/admin/integrations", 409, json={"name": "b", "client_id": "client-a"})) == "duplicate_client_id"
    assert code_of(call(client, "GET", "/api/admin/integrations/missing", 404)) == "not_found"
    assert code_of(call(client, "PATCH", "/api/admin/integrations/missing", 404, json={})) == "not_found"
    call(client, "DELETE", "/api/admin/integrations/missing", 204)
    call(client, "DELETE", f"/api/admin/integrations/{created['id']}", 204)
    fetched = call(client, "GET", f"/api/admin/integrations/{created['id']}").json()["data"]
    assert fetched["enabled"] is False and "secret" not in fetched


def test_integration_client_id_race_maps_to_409(client: TestClient) -> None:
    """A concurrent create that wins between the duplicate check and the insert is a 409, not a 500."""
    engine = client.app_state.db.engine
    fired = []

    def concurrent_insert(session, _ctx, _instances):
        if fired or not any(isinstance(row, Integration) for row in session.new):
            return
        fired.append(True)
        with engine.begin() as conn:
            conn.execute(insert(Integration).values(id="racer", name="racer", client_id="raced-id", secret="s" * 32,
                                                    system_type="linux-pam", enabled=True))

    from sqlalchemy.orm import Session

    event.listen(Session, "before_flush", concurrent_insert)
    try:
        response = call(client, "POST", "/api/admin/integrations", 409, json={"name": "mine", "client_id": "raced-id"})
    finally:
        event.remove(Session, "before_flush", concurrent_insert)
    assert code_of(response) == "duplicate_client_id"


# --- policies and effective fail mode ----------------------------------------------------------


def test_policy_subject_validation_crud_and_filters(client: TestClient) -> None:
    user = call(client, "POST", "/api/admin/users", json={"username": "pat"}).json()["data"]
    integration = call(client, "POST", "/api/admin/integrations", json={"name": "i", "client_id": "pol-i"}).json()["data"]
    base = {"name": "p"}
    assert code_of(call(client, "POST", "/api/admin/policies", 422, json={**base, "subject_type": "global", "subject_id": user["id"]})) == "bad_policy_subject"
    assert code_of(call(client, "POST", "/api/admin/policies", 422, json={**base, "subject_type": "user"})) == "bad_policy_subject"
    assert code_of(call(client, "POST", "/api/admin/policies", 404, json={**base, "subject_type": "user", "subject_id": "nope"})) == "user_not_found"
    assert code_of(call(client, "POST", "/api/admin/policies", 404, json={**base, "subject_type": "integration", "subject_id": "nope"})) == "integration_not_found"
    user_policy = call(client, "POST", "/api/admin/policies", json={"name": "u", "subject_type": "user", "subject_id": user["id"], "fail_mode": "open"}).json()["data"]
    int_policy = call(client, "POST", "/api/admin/policies", json={"name": "i", "subject_type": "integration", "subject_id": integration["id"]}).json()["data"]
    call(client, "POST", "/api/admin/policies", json={"name": "g", "subject_type": "global"})
    assert code_of(call(client, "POST", "/api/admin/policies", 409, json={"name": "u2", "subject_type": "user", "subject_id": user["id"]})) == "duplicate_policy"
    assert code_of(call(client, "PATCH", f"/api/admin/policies/{int_policy['id']}", 409, json={"name": "u"})) == "duplicate_policy"
    assert [p["name"] for p in call(client, "GET", "/api/admin/policies", params={"subject_type": "user"}).json()["data"]] == ["u"]
    assert [p["name"] for p in call(client, "GET", "/api/admin/policies", params={"subject_id": integration["id"]}).json()["data"]] == ["i"]
    assert code_of(call(client, "GET", "/api/admin/policies/missing", 404)) == "not_found"
    assert code_of(call(client, "PATCH", "/api/admin/policies/missing", 404, json={})) == "not_found"
    assert call(client, "GET", f"/api/admin/policies/{user_policy['id']}").json()["data"]["fail_mode"] == "open"
    call(client, "DELETE", f"/api/admin/policies/{user_policy['id']}", 204)
    call(client, "DELETE", f"/api/admin/policies/{user_policy['id']}", 204)


def test_global_settings_patch_persists_across_restarts(tmp_path: Path) -> None:
    app = make_app(tmp_path, "settings.db")
    with TestClient(app) as c:
        patched = call(c, "PATCH", "/api/admin/settings/global", json={"global_fail_mode": "open", "auth_ttl_seconds": 30, "push_retry_count": None}).json()["data"]
        assert patched["global_fail_mode"] == "open" and patched["push_retry_count"] == 1
        call(c, "PATCH", "/api/admin/settings/global", 422, json={"auth_ttl_seconds": 1})
    restarted = make_app(tmp_path, "settings.db")
    with TestClient(restarted) as c:
        stored = call(c, "GET", "/api/admin/settings/global").json()["data"]
    assert stored["global_fail_mode"] == "open" and stored["auth_ttl_seconds"] == 30


def test_default_settings_race_uses_the_row_another_worker_created(client: TestClient) -> None:
    engine = client.app_state.db.engine
    fired = []

    def concurrent_insert(session, _ctx, _instances):
        if fired or not any(isinstance(row, Setting) for row in session.new):
            return
        fired.append(True)
        with engine.begin() as conn:
            conn.execute(insert(Setting).values(key="global", value={"global_fail_mode": "open", "auth_ttl_seconds": 42,
                                                                     "push_retry_count": 0, "require_biometric": False,
                                                                     "trusted_session_window_seconds": 0}))

    from sqlalchemy.orm import Session

    event.listen(Session, "before_flush", concurrent_insert)
    try:
        data = call(client, "GET", "/api/admin/settings/global").json()["data"]
    finally:
        event.remove(Session, "before_flush", concurrent_insert)
    assert fired and data["auth_ttl_seconds"] == 42


# --- log filters and datetime parsing ----------------------------------------------------------


def test_log_filters_and_datetime_parsing(client: TestClient) -> None:
    call(client, "POST", "/api/admin/users", json={"username": "logan"})
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    past_naive = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    rows = call(client, "GET", "/api/admin/audit-logs", params={"actor": "bootstrap", "action": "user.create", "resource_type": "user",
                                                                 "from": past_naive, "to": future.replace("+00:00", "Z")}).json()
    assert rows["meta"]["count"] == 1 and rows["data"][0]["detail"] == {"username": "logan"}
    assert call(client, "GET", "/api/admin/audit-logs", params={"from": future}).json()["data"] == []
    for path in ("/api/admin/audit-logs", "/api/admin/auth-logs"):
        assert code_of(call(client, "GET", path, 422, params={"from": "yesterday"})) == "bad_datetime"
        assert code_of(call(client, "GET", path, 422, params={"to": "2026-13-01"})) == "bad_datetime"
    logs = call(client, "GET", "/api/admin/auth-logs", params={"user": "logan", "system": "h", "result": "denied", "from": past_naive, "to": future}).json()
    assert logs == {"data": [], "meta": {"limit": 100, "offset": 0, "count": 0}}


# --- rate limiting -----------------------------------------------------------------------------


def test_rate_limit_window_resets_prunes_and_skips_cache_header_off_api(tmp_path: Path) -> None:
    app = make_app(tmp_path, rate_limit_per_minute=1, rate_limit_window_seconds=1)
    with TestClient(app) as c:
        assert c.get("/api/v1/devices/x/ws-not-a-route").status_code == 404
        limited = c.get("/api/v1/devices/x/ws-not-a-route")
        assert limited.status_code == 429
        assert "cache-control" not in {k.lower() for k in limited.headers}
        sensitive = c.get("/api/admin/users", headers=ADMIN)
        assert sensitive.status_code == 429 and sensitive.headers["cache-control"] == "no-store"
        time.sleep(1.1)
        assert c.get("/api/admin/users", headers=ADMIN).status_code == 200
        # Over 1024 buckets: expired ones are dropped before a new client is counted.
        expired = time.time() - 5
        app.state.rate_limits = {f"ip:203.0.113.{i}": (expired, 1) for i in range(1100)}
        assert c.get("/api/admin/users", headers=ADMIN).status_code == 200
        assert set(app.state.rate_limits) == {"ip:testclient"}


def test_rate_limit_ignores_unparseable_forwarded_address(tmp_path: Path) -> None:
    secret = "proxy-shared-secret-123"
    app = make_app(tmp_path, trusted_proxy_auth_secret=secret)
    with TestClient(app) as c:
        c.get("/api/admin/users", headers={**ADMIN, "x-pushgate-proxy-secret": secret, "x-forwarded-for": "1.2.3.4, not-an-ip"})
        c.get("/api/admin/users", headers={**ADMIN, "x-pushgate-proxy-secret": secret, "x-forwarded-for": "2001:db8:0:0::1"})
    assert set(app.state.rate_limits) == {"ip:testclient", "ip:2001:db8::1"}


def test_healthz_and_readyz_bypass_rate_limits(tmp_path: Path) -> None:
    app = make_app(tmp_path, rate_limit_per_minute=1)
    with TestClient(app) as c:
        for _ in range(3):
            assert c.get("/healthz").json() == {"ok": True, "service": "pushgate"}
            assert c.get("/readyz").status_code == 200
    assert app.state.rate_limits == {}


# --- database error mapping --------------------------------------------------------------------


class RaiseOn:
    """Raise a chosen DBAPI-level error when a users SELECT runs."""

    def __init__(self, engine, factory) -> None:
        self.factory = factory
        self.armed = False
        event.listen(engine, "before_cursor_execute", self._before)

    def _before(self, _conn, _cursor, statement, params, _context, _many) -> None:
        if self.armed and statement.lstrip().upper().startswith("SELECT") and "FROM users" in statement:
            self.armed = False
            raise self.factory(statement, params)


class PgLockOrig(Exception):
    sqlstate = "55P03"


class PgOtherOrig(Exception):
    pgcode = "42000"


@pytest.mark.parametrize(
    ("factory", "status", "expected_code"),
    [
        (lambda s, p: OperationalError(s, p, Exception("database is locked")), 503, "database_busy"),
        (lambda s, p: OperationalError(s, p, PgLockOrig("lock timeout")), 503, "database_busy"),
        (lambda s, p: OperationalError(s, p, Exception("server closed the connection"), connection_invalidated=True), 503, "database_unavailable"),
        (lambda s, p: DataError(s, p, Exception("value too long")), 422, "invalid_request_data"),
        (lambda s, p: OperationalError(s, p, PgOtherOrig("disk I/O error")), 500, None),
    ],
)
def test_database_errors_map_to_retryable_or_client_statuses(client: TestClient, factory, status: int, expected_code: str | None) -> None:
    probe = RaiseOn(client.app_state.db.engine, factory)
    probe.armed = True
    response = client.get("/api/admin/users", headers=ADMIN)
    assert response.status_code == status
    if expected_code:
        assert code_of(response) == expected_code
        # The driver message never reaches the client.
        assert "locked" not in response.json()["detail"]["message"].replace("database_busy", "")
        assert "too long" not in response.text


def test_static_dir_that_does_not_exist_is_not_mounted(tmp_path: Path) -> None:
    app = make_app(tmp_path, static_dir=str(tmp_path / "absent"))
    with TestClient(app) as c:
        assert c.get("/").status_code == 404


def test_api_docs_are_opt_in(tmp_path: Path) -> None:
    with TestClient(make_app(tmp_path, "a.db")) as c:
        assert c.get("/openapi.json").status_code == 404
    with TestClient(make_app(tmp_path, "b.db", api_docs_enabled=True)) as c:
        assert c.get("/openapi.json").json()["info"]["title"] == "PushGate API"
