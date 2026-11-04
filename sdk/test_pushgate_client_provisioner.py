"""The SDK can create an integration with a scoped provisioner key.

create_integration() used to send "client_id": null and "fail_mode": null. A scoped
key may not send client_id at all, so every SDK call with a provisioner token was
refused with 403 binding_outside_scope.
"""
from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from pushgate import PushGateAdminClient
from server.app.config import Settings
from server.app.main import create_app

TOKEN = "test-admin-token-0123456789abcdef"


def sdk_on(test_client: TestClient, token: str) -> PushGateAdminClient:
    sdk = PushGateAdminClient("https://pushgate.example", token)
    sdk.client.close()
    test_client.headers["Authorization"] = f"Bearer {token}"
    sdk.client = test_client
    return sdk


def test_provisioner_key_creates_its_integration_through_the_sdk(tmp_path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'sdk-provisioner.db'}", bootstrap_token=TOKEN))
    with TestClient(app, base_url="https://testserver") as client:
        admin = sdk_on(client, TOKEN)
        admin.create_user("serviceuser")
        admin.create_user("operator")
        issued = client.post("/api/admin/rbac/provisioners", json={
            "name": "automation", "principal_username": "serviceuser", "approver_username": "operator", "systems": ["server01"],
        }).json()["data"]
        provisioner = sdk_on(client, issued["token"])
        created = provisioner.create_integration("SSH server01", fail_mode="closed", principal_username="serviceuser",
                                                 approver_username="operator", system_name="server01")
        assert created["secret"] and created["online_only"] is True
        assert [row["system_name"] for row in provisioner.integrations()] == ["server01"]
        assert provisioner.update_integration(created["id"], enabled=False)["enabled"] is False


def test_unset_options_are_omitted_not_sent_as_null() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(201, json={"data": {}})

    admin = PushGateAdminClient("https://pushgate.example", "token")
    admin.client.close()
    admin.client = httpx.Client(base_url="https://pushgate.example", transport=httpx.MockTransport(handler))
    try:
        admin.create_integration("plain")
        admin.create_integration("full", client_id="cid", fail_mode="open", system_type="proxy", enabled=False,
                                 principal_username="p", approver_username="a", system_name="s")
    finally:
        admin.close()
    assert bodies[0] == {"name": "plain", "system_type": "linux-pam", "enabled": True}
    assert bodies[1] == {"name": "full", "client_id": "cid", "fail_mode": "open", "system_type": "proxy", "enabled": False,
                         "principal_username": "p", "approver_username": "a", "system_name": "s"}
