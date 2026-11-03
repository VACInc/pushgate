"""Untrusted request text and numbers get a 4xx answer, never an unhandled 500.

A 5xx reads as "server down" to a PAM helper, so every caller-controlled value
the server stores or parses must be checked before it reaches the database or
the standard library.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from server.app.config import Settings
from server.app.main import create_app
from server.app.security import constant_eq, hash_value, integration_signature

from test_server_hardening import (
    ADMIN_TOKEN,
    create_integration,
    create_user,
    signed_post,
    start_auth,
)

POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")
PROXY_SECRET = "proxy-secret-0123456789abcdef"


def sqlite_app(tmp_path, **extra):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 'input.db'}", bootstrap_token=ADMIN_TOKEN, **extra))


def detail_code(response) -> str:
    return response.json()["detail"]["code"]


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("source_ip", "a" * 65, "invalid_source_ip"),
        ("source_ip", 12345, "invalid_source_ip"),
        ("source_ip", {"nested": "x"}, "invalid_source_ip"),
        ("source_ip", "10.0.0.1\x00", "invalid_source_ip"),
        ("pam_service", "s" * 65, "invalid_pam_service"),
        ("pam_service", ["ssh"], "invalid_pam_service"),
        ("system", "h" * 129, "invalid_system"),
        ("system", 123, "invalid_system"),
        ("system", "box\x00", "invalid_system"),
    ],
)
def test_bad_request_text_is_422(tmp_path, field, value, code) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "input-user")
        integration = create_integration(client, "input-integration")
        response = start_auth(client, integration, "input-user", "input-nonce", **{field: value})
        assert response.status_code == 422, response.text
        assert detail_code(response) == code


def test_text_at_the_column_limit_is_accepted(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "limit-user")
        integration = create_integration(client, "limit-integration")
        response = start_auth(
            client, integration, "limit-user", "limit-nonce",
            source_ip="a" * 64, pam_service="s" * 64, system="h" * 128,
        )
        assert response.status_code == 201, response.text
        # Absent optional fields keep their defaults.
        response = start_auth(client, integration, "limit-user", "limit-nonce-2", source_ip=None)
        assert response.status_code == 201, response.text


def test_preflight_checks_the_system_length(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "pre-user")
        integration = create_integration(client, "pre-integration")
        response = signed_post(
            client, integration, "/api/v1/auth/preflight", {"username": "pre-user", "system": "h" * 129}, "pre-nonce"
        )
        assert response.status_code == 422
        assert detail_code(response) == "invalid_system"


def test_constant_eq_handles_any_text() -> None:
    assert constant_eq("abc", "abc") is True
    assert constant_eq("abc", "abd") is False
    assert constant_eq("café", "café") is True
    assert constant_eq("café", "cafe") is False
    assert constant_eq("\ud800", "x") is False
    assert constant_eq(None, "x") is False  # type: ignore[arg-type]
    assert hash_value("\ud800")


def _signed_headers(integration: dict, path: str, body: bytes, timestamp: str, nonce: str) -> dict:
    return {
        "Content-Type": "application/json",
        "X-PushGate-Client-Id": integration["client_id"],
        "X-PushGate-Timestamp": timestamp,
        "X-PushGate-Nonce": nonce,
        "X-PushGate-Signature": integration_signature(integration["secret"], "POST", path, body, timestamp, nonce),
    }


def test_non_ascii_signature_is_403(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "sig-user")
        integration = create_integration(client, "sig-integration")
        path = "/api/v1/auth/requests"
        body = json.dumps({"username": "sig-user", "system": "box"}).encode()
        headers = _signed_headers(integration, path, body, str(int(time.time())), "sig-nonce")
        headers["X-PushGate-Signature"] = "é".encode("latin-1")
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 403
        assert detail_code(response) == "bad_signature"


@pytest.mark.parametrize("timestamp", ["9" * 30, "-" + "9" * 30, "99999999999999"])
def test_out_of_range_timestamp_is_401(tmp_path, timestamp) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "ts-user")
        integration = create_integration(client, "ts-integration")
        path = "/api/v1/auth/requests"
        body = json.dumps({"username": "ts-user", "system": "box"}).encode()
        response = client.post(path, content=body, headers=_signed_headers(integration, path, body, timestamp, "ts-nonce"))
        assert response.status_code == 401
        assert detail_code(response) == "bad_timestamp"


def test_out_of_range_push_token_timestamp_is_401(tmp_path) -> None:
    from test_server_hardening import create_device

    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        user = create_user(client, "tok-user")
        device, _key = create_device(client, user["id"])
        response = client.post(
            f"/api/v1/devices/{device['id']}/push-token",
            json={"push_token": "t", "timestamp": "9" * 30, "nonce": "n", "signature": "s"},
        )
        assert response.status_code == 401
        assert detail_code(response) == "bad_timestamp"


def test_huge_wait_seconds_is_422(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "wait-user")
        integration = create_integration(client, "wait-integration")
        path = "/api/v1/proxy/verify"
        body = b'{"username":"wait-user","system":"box","wait_seconds":1e400}'
        response = client.post(path, content=body, headers=_signed_headers(integration, path, body, str(int(time.time())), "w-n"))
        assert response.status_code == 422
        assert detail_code(response) == "bad_wait_seconds"


def test_non_ascii_proxy_secret_is_not_a_500(tmp_path) -> None:
    app = sqlite_app(tmp_path, trusted_proxy_auth_secret=PROXY_SECRET)
    with TestClient(app, raise_server_exceptions=False) as client:
        headers = {"X-PushGate-Proxy-Secret": "été".encode("latin-1"), "X-Forwarded-For": "203.0.113.9"}
        response = client.get("/api/admin/whoami", headers=headers)
        assert 400 <= response.status_code < 500, response.text


@pytest.fixture()
def postgres_url():
    if not POSTGRES_URL:
        pytest.skip("set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
    name = "pgin_" + uuid.uuid4().hex[:12]
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = POSTGRES_URL.rsplit("/", 1)[0] + "/" + name
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_postgres_long_source_is_422_not_500(postgres_url) -> None:
    app = create_app(Settings(database_url=postgres_url, bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "pg-user")
        integration = create_integration(client, "pg-integration")
        response = start_auth(client, integration, "pg-user", "pg-nonce-1", source_ip="x" * 65)
        assert response.status_code == 422
        assert detail_code(response) == "invalid_source_ip"
        # A value only the database refuses is still a 4xx.
        response = start_auth(client, integration, "pg-\x00user", "pg-nonce-2")
        assert response.status_code == 422, response.text
        assert detail_code(response) == "invalid_request_data"
        # The server keeps working afterwards.
        response = start_auth(client, integration, "pg-user", "pg-nonce-3", source_ip="10.0.0.9")
        assert response.status_code == 201, response.text


def test_postgres_lost_connection_is_503(postgres_url) -> None:
    app = create_app(Settings(database_url=postgres_url, bootstrap_token=ADMIN_TOKEN))
    handler = app.exception_handlers[OperationalError]
    lost = OperationalError("SELECT 1", {}, Exception("connection refused"))
    response = asyncio.run(handler(None, lost))
    assert response.status_code == 503
    assert json.loads(response.body)["detail"]["code"] == "database_unavailable"
    app.state.db.engine.dispose()
