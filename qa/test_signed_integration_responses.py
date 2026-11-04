"""Answers to signed integration requests are MACed, and the PAM helper can require it.

Without a response MAC the PAM helper's only proof that a login was approved is
TLS. Anyone who can present a trusted certificate for the server name (a TLS
interception proxy, a mis-issued certificate, a compromised edge that only
terminates TLS) could answer "approved" and "consumed" for any login.
"""
import json
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from pam import pushgate_pam
from qa.test_server_hardening import (
    ADMIN_TOKEN,
    consume_auth,
    create_device,
    create_integration,
    create_user,
    decide,
    preflight,
    signed_get,
    start_auth,
)
from server.app.config import Settings
from server.app.main import create_app
from server.app.models import AuthRequest
from server.app.security import RESPONSE_SIGNATURE_HEADER, integration_response_signature


def assert_signed(response: httpx.Response, secret: str) -> None:
    nonce = response.request.headers["X-PushGate-Nonce"]
    expected = integration_response_signature(secret, nonce, response.status_code, response.content)
    assert response.headers.get(RESPONSE_SIGNATURE_HEADER) == expected


def make_app(tmp_path: Path, name: str):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / name}", bootstrap_token=ADMIN_TOKEN))


def test_every_authenticated_integration_answer_is_bound_to_its_nonce(tmp_path: Path) -> None:
    with TestClient(make_app(tmp_path, "signed.db")) as client:
        user = create_user(client, "signed-user")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "signed-host")
        secret = integration["secret"]

        pre = preflight(client, integration, user["username"], "signed-preflight")
        assert pre.status_code == 200
        assert_signed(pre, secret)

        started = start_auth(client, integration, user["username"], "signed-start")
        assert started.status_code == 201
        assert_signed(started, secret)
        request_id = started.json()["data"]["id"]

        polled = signed_get(client, integration, f"/api/v1/auth/requests/{request_id}", "signed-poll")
        assert_signed(polled, secret)

        early = consume_auth(client, integration, request_id, "signed-early")
        assert early.status_code == 409
        assert_signed(early, secret)

        assert decide(client, request_id, device["id"], key).json()["data"]["status"] == "approved"
        consumed = consume_auth(client, integration, request_id, "signed-consume")
        assert consumed.status_code == 200
        assert_signed(consumed, secret)
        # The same body under another nonce has a different MAC: no response replay.
        assert consumed.headers[RESPONSE_SIGNATURE_HEADER] != integration_response_signature(
            secret, "another-nonce", consumed.status_code, consumed.content
        )

        replay = consume_auth(client, integration, request_id, "signed-consume")
        assert replay.status_code == 409 and replay.json()["detail"]["code"] == "replay"
        assert_signed(replay, secret)

        # Unauthenticated callers and admin routes get no integration MAC.
        forged = start_auth(client, {**integration, "secret": "wrong"}, user["username"], "signed-forged")
        assert forged.status_code == 403
        assert RESPONSE_SIGNATURE_HEADER not in forged.headers
        admin = client.get("/api/admin/users", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        assert RESPONSE_SIGNATURE_HEADER not in admin.headers
        assert RESPONSE_SIGNATURE_HEADER not in client.get("/healthz").headers


class _Entered:
    """Hand an already-started TestClient to code that opens httpx.Client(...) itself."""

    def __init__(self, client: TestClient, transport: httpx.BaseTransport | None = None):
        self.client = client
        self.transport = transport

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def _send(self, method: str, path: str, **kwargs):
        kwargs.pop("timeout", None)
        request = self.client.build_request(method, path, **kwargs)
        if self.transport is not None:
            return self.transport.handle_request(request)
        return self.client.send(request)

    def post(self, path, **kwargs):
        return self._send("POST", path, **kwargs)

    def get(self, path, **kwargs):
        return self._send("GET", path, **kwargs)


class Impersonator(httpx.BaseTransport):
    """Holds a trusted certificate for the server name: relays requests and rewrites answers."""

    def __init__(self, client: TestClient):
        self.client = client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        real = self.client.send(request)
        if request.url.path == "/api/v1/auth/requests" and real.status_code == 201:
            data = real.json()["data"]
            data.update(status="approved", allowed=True)
            return httpx.Response(201, json={"data": data}, request=request)
        if request.url.path.endswith("/consume"):
            request_id = request.url.path.split("/")[-2]
            return httpx.Response(200, request=request, json={"data": {
                "id": request_id, "status": "approved", "allowed": True, "consumed": True,
                "consumed_at": "2026-01-01T00:00:00+00:00",
            }})
        return real


def pam_config(tmp_path: Path, integration: dict, require: bool) -> pushgate_pam.AuthConfig:
    cache = tmp_path / ("cache-strict" if require else "cache-lax")
    return pushgate_pam.AuthConfig(
        "https://pushgate.example", integration["client_id"], integration["secret"], str(cache),
        timeout=10, require_signed_responses=require,
    )


@pytest.mark.parametrize("require", [False, True])
def test_pam_helper_completes_a_real_signed_approval(tmp_path: Path, monkeypatch, require: bool) -> None:
    app = make_app(tmp_path, f"pam-real-{require}.db")
    with TestClient(app, base_url="https://pushgate.example") as client:
        user = create_user(client, "pam-real")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "pam-real-host")
        monkeypatch.setattr(pushgate_pam.httpx, "Client", lambda **_kwargs: _Entered(client))

        def approve_when_pending():
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                with app.state.db.SessionLocal() as db:
                    row = db.query(AuthRequest).filter_by(status="pending").first()
                if row is not None:
                    decide(client, row.id, device["id"], key)
                    return
                time.sleep(0.05)

        approver = threading.Thread(target=approve_when_pending)
        approver.start()
        try:
            assert pushgate_pam.authenticate(user["username"], cfg=pam_config(tmp_path, integration, require)) == 0
        finally:
            approver.join(10)


@pytest.mark.parametrize("require, expected", [(False, 0), (True, 1)])
def test_tls_impersonator_cannot_approve_when_signatures_are_required(
    tmp_path: Path, monkeypatch, require: bool, expected: int
) -> None:
    app = make_app(tmp_path, f"pam-mitm-{require}.db")
    with TestClient(app, base_url="https://pushgate.example") as client:
        user = create_user(client, "pam-mitm")
        create_device(client, user["id"])
        integration = create_integration(client, "pam-mitm-host")
        monkeypatch.setattr(pushgate_pam.httpx, "Client", lambda **_kwargs: _Entered(client, Impersonator(client)))
        # Nobody approves. Without required signatures the forged answers log in
        # (the gap this closes); with them the helper denies.
        assert pushgate_pam.authenticate(user["username"], cfg=pam_config(tmp_path, integration, require)) == expected


def test_tampered_signature_is_rejected_even_when_not_required(tmp_path: Path, monkeypatch) -> None:
    app = make_app(tmp_path, "pam-tamper.db")
    with TestClient(app, base_url="https://pushgate.example") as client:
        user = create_user(client, "pam-tamper")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "pam-tamper-host")
        started = start_auth(client, integration, user["username"], "tamper-start").json()["data"]
        assert decide(client, started["id"], device["id"], key).json()["data"]["status"] == "approved"
        cfg = pam_config(tmp_path, integration, require=False)
        headers = pushgate_pam._headers(cfg, "POST", f"/api/v1/auth/requests/{started['id']}/consume", b"")
        genuine = client.post(f"/api/v1/auth/requests/{started['id']}/consume", content=b"", headers=headers)
        pushgate_pam.verify_response(cfg, headers, genuine)
        altered = httpx.Response(200, headers=dict(genuine.headers), content=json.dumps(
            {**genuine.json(), "extra": True}).encode())
        with pytest.raises(ValueError):
            pushgate_pam.verify_response(cfg, headers, altered)
        other_nonce = {**headers, "X-PushGate-Nonce": "f" * 32}
        with pytest.raises(ValueError):
            pushgate_pam.verify_response(cfg, other_nonce, genuine)


def test_require_signed_responses_setting_is_strict_boolean() -> None:
    assert pushgate_pam.parse_bool_setting("X", "") is False
    assert pushgate_pam.parse_bool_setting("X", "true") is True
    assert pushgate_pam.parse_bool_setting("X", " ON ") is True
    assert pushgate_pam.parse_bool_setting("X", "0") is False
    with pytest.raises(ValueError):
        pushgate_pam.parse_bool_setting("X", "sometimes")
