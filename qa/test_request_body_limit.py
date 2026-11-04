"""Request bodies are bounded before any route reads them.

Login, consume, proxy and decision routes read the whole body before they can
check a signature, and nothing capped it: an anonymous client could make the
server buffer gigabytes per request, and an out-of-memory server reads as an
outage to every PAM helper.
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, admin_request, create_integration, create_user, start_auth

LIMIT = 4096


def sqlite_app(tmp_path, **extra):
    return create_app(
        Settings(database_url=f"sqlite:///{tmp_path / 'body.db'}", bootstrap_token=ADMIN_TOKEN, **extra)
    )


def chunks(total: int, size: int = 1024):
    sent = 0
    while sent < total:
        part = min(size, total - sent)
        sent += part
        yield b" " * part


ROUTES = [
    "/api/v1/auth/requests",
    "/api/v1/auth/preflight",
    "/api/v1/proxy/verify",
    "/api/v1/auth/requests/00000000-0000-0000-0000-000000000000/consume",
    "/api/v1/auth/requests/00000000-0000-0000-0000-000000000000/decision",
    "/api/v1/devices/00000000-0000-0000-0000-000000000000/enroll",
    "/api/admin/users",
]


@pytest.mark.parametrize("path", ROUTES)
def test_declared_oversized_body_is_413_before_the_route_runs(tmp_path, path) -> None:
    with TestClient(sqlite_app(tmp_path, max_request_body_bytes=LIMIT), raise_server_exceptions=False) as client:
        response = client.post(path, content=b"{" + b" " * LIMIT + b"}", headers={"Content-Type": "application/json"})
        assert response.status_code == 413, response.text
        assert response.json()["detail"]["code"] == "body_too_large"


@pytest.mark.parametrize("path", ROUTES)
def test_streamed_oversized_body_is_413(tmp_path, path) -> None:
    with TestClient(sqlite_app(tmp_path, max_request_body_bytes=LIMIT), raise_server_exceptions=False) as client:
        response = client.post(path, content=chunks(LIMIT * 4), headers={"Content-Type": "application/json"})
        assert "content-length" not in {name.lower() for name in response.request.headers}
        assert response.status_code == 413, response.text
        assert response.json()["detail"]["code"] == "body_too_large"


def test_bodies_within_the_limit_work(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path, max_request_body_bytes=LIMIT)) as client:
        create_user(client, "body-user")
        integration = create_integration(client, "body-client")
        response = start_auth(client, integration, "body-user", "body-nonce", geolocation="g" * 64)
        assert response.status_code == 201, response.text
        streamed = client.post(
            "/api/admin/users",
            content=iter([json.dumps({"username": "streamed-user"}).encode()]),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert streamed.status_code == 201, streamed.text


def test_default_limit_fits_the_largest_admin_payload(tmp_path) -> None:
    """A provisioner allowlist of 512 names of 128 characters is the largest legitimate body."""
    with TestClient(sqlite_app(tmp_path)) as client:
        create_user(client, "prov-user")
        systems = [f"{index:03d}" + "a" * 125 for index in range(512)]
        payload = {"name": "fleet", "principal_username": "prov-user", "approver_username": "prov-user", "systems": systems}
        assert len(json.dumps(payload)) > 64 * 1024
        response = admin_request(client, "POST", "/api/admin/rbac/provisioners", json=payload)
        assert response.status_code == 201, response.text
        assert client.app.state.settings.max_request_body_bytes >= len(json.dumps(payload))


def test_get_and_websocket_routes_are_unaffected(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path, max_request_body_bytes=LIMIT)) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200
        assert admin_request(client, "GET", "/api/admin/users").status_code == 200


def test_the_limit_is_bounded_in_configuration() -> None:
    with pytest.raises(ValueError):
        Settings(database_url="sqlite://", max_request_body_bytes=100)
    with pytest.raises(ValueError):
        Settings(database_url="sqlite://", max_request_body_bytes=1024 * 1024 * 1024)


def test_oversized_body_answers_quickly(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        started = time.monotonic()
        response = client.post(
            "/api/v1/auth/requests",
            content=chunks(64 * 1024 * 1024, 1024 * 1024),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert time.monotonic() - started < 10
