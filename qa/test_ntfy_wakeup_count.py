"""The ntfy wake-up is one notification per enrolled device per push attempt.

Pins the documented count (docs/push-delivery-recovery.md): an approver with two
enrolled devices and one retry gets four wake-ups for one login, all to the
same topic. Revoked devices and answered requests get none.
"""
from __future__ import annotations

import time

import httpx
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, admin_request, create_device, create_integration, create_user, start_auth

TOPIC = "https://ntfy.example/pushgate"


def wait_for(predicate, timeout: float = 6.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.05)


def test_one_wakeup_per_enrolled_device_per_attempt(tmp_path, monkeypatch) -> None:
    posts: list[str] = []
    real_async_client = httpx.AsyncClient

    def handle(request: httpx.Request) -> httpx.Response:
        posts.append(str(request.url))
        return httpx.Response(200, json={"id": "ntfy"})

    monkeypatch.setattr(
        "server.app.push.httpx.AsyncClient",
        lambda *a, **k: real_async_client(*a, transport=httpx.MockTransport(handle), **k),
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'ntfy.db'}",
        bootstrap_token=ADMIN_TOKEN,
        ntfy_url=TOPIC,
        push_retry_count=1,
        auth_ttl_seconds=4,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        user = create_user(client, "ntfy-user")
        create_device(client, user["id"])
        create_device(client, user["id"])
        revoked, _key = create_device(client, user["id"])
        assert admin_request(client, "DELETE", f"/api/admin/devices/{revoked['id']}").status_code == 204
        integration = create_integration(client, "ntfy-integration")

        assert start_auth(client, integration, "ntfy-user", "ntfy-nonce").status_code == 201
        # Two enrolled devices x two attempts (one retry), delay min(2s, ttl / attempts).
        wait_for(lambda: len(posts) >= 4)
        time.sleep(0.5)

    assert posts == [TOPIC] * 4
