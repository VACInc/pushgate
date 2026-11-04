"""A locked account gets no outage access and no offline material.

Each login answer carries a cache snapshot the PAM helper stores for later
outages. A lockout denial still sent the account's fail mode (for example
"open"), its TOTP secret and its backup-code hashes with a new timestamp, so a
locked user who kept trying to log in kept the cache fresh, then got in during
the next outage, either through the fail-open cache or with an offline code.
"""
from __future__ import annotations

import httpx
import pyotp
import pytest
from fastapi.testclient import TestClient

from pam import pushgate_pam
from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import (
    ADMIN_TOKEN,
    admin_request,
    create_device,
    create_integration,
    create_user,
    signed_get,
    start_auth,
)

SECRET_FIELDS = ("totp_secret", "backup_code_hashes", "last_totp_counter")


def app_for(tmp_path):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 'lock.db'}", bootstrap_token=ADMIN_TOKEN))


def open_user_with_offline_factors(client: TestClient, name: str) -> dict:
    user = create_user(client, name)
    assert admin_request(client, "PATCH", f"/api/admin/users/{user['id']}", json={"fail_mode": "open"}).status_code == 200
    assert admin_request(client, "POST", f"/api/admin/users/{user['id']}/totp").status_code == 200
    assert admin_request(client, "POST", f"/api/admin/users/{user['id']}/backup-codes", params={"count": 2}).status_code == 200
    return user


@pytest.mark.parametrize("who", ["principal", "approver"])
def test_lockout_denial_carries_a_closed_cache_without_offline_material(tmp_path, who) -> None:
    with TestClient(app_for(tmp_path)) as client:
        user = open_user_with_offline_factors(client, "lock-user")
        approver = create_user(client, "lock-approver")
        integration = create_integration(client, "lock-client", principal_username="lock-user", approver_username="lock-approver")
        before = start_auth(client, integration, "lock-user", "lock-0").json()["data"]
        assert before["cache"]["fail_mode"] == "open" and before["cache"]["totp_secret"]
        locked = user if who == "principal" else approver
        assert admin_request(client, "POST", f"/api/admin/users/{locked['id']}/lockout").status_code == 200

        denied = start_auth(client, integration, "lock-user", "lock-1").json()["data"]
        assert denied["status"] == "denied"
        assert denied["cache"]["fail_mode"] == "closed"
        assert not any(field in denied["cache"] for field in SECRET_FIELDS)
        polled = signed_get(client, integration, f"/api/v1/auth/requests/{denied['id']}", "lock-2").json()["data"]
        assert polled["cache"]["fail_mode"] == "closed"
        assert not any(field in polled["cache"] for field in SECRET_FIELDS)

        assert admin_request(client, "DELETE", f"/api/admin/users/{locked['id']}/lockout").status_code == 200
        after = start_auth(client, integration, "lock-user", "lock-3").json()["data"]
        assert after["cache"]["fail_mode"] == "open" and after["cache"]["totp_secret"]


def test_request_pending_when_the_lockout_lands_polls_a_closed_cache(tmp_path) -> None:
    with TestClient(app_for(tmp_path)) as client:
        user = open_user_with_offline_factors(client, "lock-user")
        create_device(client, user["id"])
        integration = create_integration(client, "lock-client", principal_username="lock-user")
        pending = start_auth(client, integration, "lock-user", "p-0").json()["data"]
        assert pending["status"] == "pending"
        assert admin_request(client, "POST", f"/api/admin/users/{user['id']}/lockout").status_code == 200
        polled = signed_get(client, integration, f"/api/v1/auth/requests/{pending['id']}", "p-1").json()["data"]
        assert polled["status"] == "denied"
        assert polled["cache"]["fail_mode"] == "closed"
        assert not any(field in polled["cache"] for field in SECRET_FIELDS)


@pytest.mark.parametrize("outage_login", ["fail_open", "offline_totp"])
def test_locked_user_cannot_pass_the_next_outage_through_the_pam_helper(tmp_path, monkeypatch, outage_login) -> None:
    """End to end: real helper, real server. Lock, try once, then the server goes down."""
    app = app_for(tmp_path)
    with TestClient(app, base_url="https://pushgate.example") as client:
        user = open_user_with_offline_factors(client, "lock-user")
        integration = create_integration(client, "lock-client", principal_username="lock-user")
        secret = admin_request(client, "POST", f"/api/admin/users/{user['id']}/totp").json()["data"]["secret"]
        cache_dir = tmp_path / "cache"
        cfg = pushgate_pam.AuthConfig(
            "https://pushgate.example", integration["client_id"], integration["secret"], str(cache_dir),
            timeout=5, system_name="labbox", require_cache_binding=True,
        )
        server_up = {"value": True}

        def handler(request: httpx.Request) -> httpx.Response:
            if not server_up["value"]:
                raise httpx.ConnectError("server down", request=request)
            response = client.request(request.method, request.url.path, content=request.content, headers=request.headers)
            return httpx.Response(response.status_code, content=response.content, headers=response.headers)

        real_client = httpx.Client
        transport = httpx.MockTransport(handler)
        monkeypatch.setattr(
            pushgate_pam.httpx, "Client",
            lambda **kwargs: real_client(base_url=kwargs["base_url"], transport=transport, timeout=kwargs.get("timeout")),
        )
        monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)

        assert admin_request(client, "POST", f"/api/admin/users/{user['id']}/lockout").status_code == 200
        assert pushgate_pam.authenticate("lock-user", cfg=cfg) == 1  # denied while the server is up

        server_up["value"] = False
        code = pyotp.TOTP(secret).now() if outage_login == "offline_totp" else None
        assert pushgate_pam.authenticate("lock-user", offline_code=code, cfg=cfg) == 1
