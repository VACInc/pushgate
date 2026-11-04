"""SDK: argument validation and every admin method against the real server app."""
from __future__ import annotations

import base64
import ssl
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from pushgate import PushGateAdminClient, PushGateProtocolError
from pushgate import client as client_module
from server.app.config import Settings
from server.app.main import create_app

TOKEN = "test-admin-token-0123456789abcdef"


@pytest.mark.parametrize("base_url", [None, "", "not a url ::", "ftp://pushgate.example", "https://", "//pushgate.example"])
def test_base_url_must_be_an_http_origin(base_url) -> None:
    with pytest.raises(ValueError):
        PushGateAdminClient(base_url, "token")


@pytest.mark.parametrize("host", ["localhost", "api.localhost", "[::1]", "127.0.0.2"])
def test_plain_http_is_allowed_for_loopback_names(host: str) -> None:
    with PushGateAdminClient(f"http://{host}:8000", "token") as admin:
        assert admin.client.base_url.scheme == "http"
        assert repr(admin) == f"PushGateAdminClient(base_url='http://{host}:8000')"


def test_token_and_transport_options_are_validated() -> None:
    for token in (None, "", " leading", "tab\t"):
        with pytest.raises(ValueError):
            PushGateAdminClient("https://pushgate.example", token)
    for timeout in (True, "5"):
        with pytest.raises(ValueError):
            PushGateAdminClient("https://pushgate.example", "token", timeout=timeout)
    with pytest.raises(TypeError):
        PushGateAdminClient("https://pushgate.example", "token", allow_insecure=1)
    with pytest.raises(TypeError):
        PushGateAdminClient("https://pushgate.example", "token", ssl_context=object())
    lax = ssl.create_default_context()
    lax.check_hostname = False
    with pytest.raises(ValueError, match="hostname verification"):
        PushGateAdminClient("https://pushgate.example", "token", ssl_context=lax)
    with PushGateAdminClient("https://pushgate.example", "token", timeout=2, ssl_context=ssl.create_default_context()) as admin:
        assert admin.client.timeout.connect == 2.0


def test_role_permissions_are_validated_before_sending() -> None:
    admin = PushGateAdminClient("https://pushgate.example", "token")
    try:
        with pytest.raises(TypeError):
            admin.create_role("r", ["read"])
        with pytest.raises(TypeError):
            admin.create_role("r", {1: True})
        with pytest.raises(ValueError, match="unknown permissions: delete"):
            admin.create_role("r", {"delete": True})
        with pytest.raises(TypeError):
            admin.create_role("r", {"read": 1})
        with pytest.raises(TypeError):
            admin.update_role("role-1", permissions={"read": "yes"})
    finally:
        admin.close()


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="<html>"), "non-JSON"),
        (httpx.Response(200, headers={"content-type": "application/json"}, content=b"{"), "malformed JSON"),
        (httpx.Response(200, json=[1]), "data envelope"),
    ],
)
def test_success_responses_outside_the_contract_raise_protocol_errors(response, message) -> None:
    admin = PushGateAdminClient("https://pushgate.example", "token")
    admin.client.close()
    admin.client = httpx.Client(base_url="https://pushgate.example", transport=httpx.MockTransport(lambda _r: response))
    try:
        with pytest.raises(PushGateProtocolError, match=message):
            admin.global_settings()
    finally:
        admin.close()


@pytest.fixture()
def admin(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'sdk.db'}", bootstrap_token=TOKEN))
    with TestClient(app, base_url="https://testserver") as test_client:
        sdk = PushGateAdminClient("https://pushgate.example", TOKEN)
        sdk.client.close()
        test_client.headers["Authorization"] = f"Bearer {TOKEN}"
        sdk.client = test_client
        yield sdk


def test_every_admin_method_round_trips_against_the_server(admin: PushGateAdminClient) -> None:
    alice = admin.create_user("alice", "Alice", fail_mode="open")
    assert admin.get_user(alice["id"])["display_name"] == "Alice"
    assert [u["username"] for u in admin.users()] == ["alice"]
    assert admin.set_user_fail_mode(alice["id"], "closed")["fail_mode"] == "closed"
    assert admin.lock_user(alice["id"])["locked"] is True
    assert admin.unlock_user(alice["id"])["locked"] is False
    assert admin.enroll_totp(alice["id"])["uri"].startswith("otpauth://")
    assert len(admin.create_backup_codes(alice["id"], count=2)["codes"]) == 2
    codes = admin.backup_codes(alice["id"])
    admin.delete_backup_code(codes[0]["id"])
    admin.delete_backup_codes(alice["id"])
    assert admin.backup_codes(alice["id"]) == []

    group = admin.create_group("ops", "Operators")
    assert admin.get_group(group["id"])["description"] == "Operators"
    assert admin.update_group(group["id"], description="Ops")["description"] == "Ops"
    admin.add_group_user(group["id"], alice["id"])
    assert [u["username"] for u in admin.group_users(group["id"])] == ["alice"]
    admin.remove_group_user(group["id"], alice["id"])
    admin.delete_group(group["id"])

    public = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    phone = admin.create_device(alice["id"], "phone", public_key=public, push_token="fcm-token")
    pending = admin.create_device(alice["id"], "watch", kind="wear")
    assert "enrollment_qr_payload" in pending and "enrollment_qr_payload" not in phone
    assert {d["name"] for d in admin.devices()} == {"phone", "watch"}
    assert len(admin.devices(alice["id"])) == 2
    assert admin.get_device(phone["id"])["push_token_configured"] is True
    assert admin.update_device(phone["id"], name="Phone")["name"] == "Phone"
    assert admin.rotate_device_key(phone["id"])["public_key"] is None
    admin.revoke_device(pending["id"])
    assert admin.get_device(pending["id"])["revoked"] is True

    integration = admin.create_integration("host", client_id="host", fail_mode="closed", principal_username="alice",
                                           approver_username="alice", system_name="host01")
    assert (integration["principal_username"], integration["system_name"]) == ("alice", "host01")
    assert admin.get_integration(integration["id"])["approver_username"] == "alice"
    assert [i["client_id"] for i in admin.integrations()] == ["host"]
    assert admin.update_integration(integration["id"], name="Host")["name"] == "Host"
    admin.delete_integration(integration["id"])
    assert admin.get_integration(integration["id"])["enabled"] is False

    policy = admin.create_policy("user", "user", alice["id"], fail_mode="open", auth_ttl_seconds=30)
    assert admin.get_policy(policy["id"])["auth_ttl_seconds"] == 30
    assert [p["name"] for p in admin.policies("user", alice["id"])] == ["user"]
    assert admin.policies() and admin.update_policy(policy["id"], enabled=False)["enabled"] is False
    admin.delete_policy(policy["id"])

    role = admin.create_role("auditor", {"read": True}, description="Audit")
    assert role["permissions"] == {"read": True, "write": False, "admin": False}
    assert admin.get_role(role["id"])["description"] == "Audit"
    assert admin.update_role(role["id"], permissions={"read": True, "write": True})["permissions"]["write"] is True
    assert "auditor" in {r["name"] for r in admin.roles()}
    key = admin.create_api_key("reader", "auditor")
    assert key["token"] and admin.get_api_key(key["id"])["role"] == "auditor"
    assert admin.update_api_key(key["id"], role="read-only")["role"] == "read-only"
    assert key["id"] in {k["id"] for k in admin.api_keys()}
    admin.delete_api_key(key["id"])
    admin.delete_role(role["id"])

    assert admin.update_global_settings(auth_ttl_seconds=45)["auth_ttl_seconds"] == 45
    assert admin.global_settings()["auth_ttl_seconds"] == 45
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    assert admin.auth_logs(user="alice", system="host01", result="approved", from_time=since,
                           to_time=datetime.now(timezone.utc) + timedelta(minutes=1)) == []
    assert admin.denials_last_24h() == []
    audit = admin.audit_logs(action="device.revoke", resource_type="device", resource_id=pending["id"], limit=5)
    assert [row["action"] for row in audit] == ["device.revoke"]


def test_http_errors_propagate_as_status_errors(admin: PushGateAdminClient) -> None:
    with pytest.raises(httpx.HTTPStatusError) as raised:
        admin.get_user("missing")
    assert raised.value.response.status_code == 404
    assert client_module._segment("abc-1", "id") == "abc-1"
