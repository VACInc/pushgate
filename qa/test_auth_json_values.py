"""Signed request bodies cannot plant values that later break the admin API.

`geolocation` is the one free-form value a login request stores: it goes into
the auth request and into the append-only auth log. Python's JSON parser
accepts NaN and Infinity; the response encoder refuses them, so one signed
request with `"geolocation": NaN` turned GET /api/admin/auth-logs into a 500
for good (the log row cannot be edited). Oversized integers and deep nesting
were plain 500s as well.
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import AuthLogEntry
from server.app.security import integration_signature

from test_server_hardening import ADMIN_TOKEN, admin_request, create_integration, create_user, start_auth

PATH = "/api/v1/auth/requests"


def sqlite_app(tmp_path):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 'json.db'}", bootstrap_token=ADMIN_TOKEN))


def raw_signed_start(client: TestClient, integration: dict, body: bytes, nonce: str):
    timestamp = str(int(time.time()))
    return client.post(
        PATH,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": integration_signature(integration["secret"], "POST", PATH, body, timestamp, nonce),
        },
    )


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_non_finite_geolocation_is_422_and_auth_logs_stay_readable(tmp_path, literal) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "geo-user")
        integration = create_integration(client, "geo-client")
        body = ('{"username":"geo-user","system":"box","geolocation":%s}' % literal).encode()
        response = raw_signed_start(client, integration, body, "geo-nonce")
        assert response.status_code == 422, response.text
        assert response.json()["detail"]["code"] == "invalid_geolocation"
        logs = admin_request(client, "GET", "/api/admin/auth-logs")
        assert logs.status_code == 200, logs.text


@pytest.mark.parametrize(
    "value",
    [{"city": "Paris"}, ["Paris"], 12.5, True, "x" * 129, "Paris\x00"],
    ids=["object", "list", "number", "bool", "too-long", "nul"],
)
def test_geolocation_must_be_short_text(tmp_path, value) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "geo-user")
        integration = create_integration(client, "geo-client")
        response = start_auth(client, integration, "geo-user", "geo-nonce", geolocation=value)
        assert response.status_code == 422, response.text
        assert response.json()["detail"]["code"] == "invalid_geolocation"


def test_geolocation_text_is_kept(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path)) as client:
        create_user(client, "geo-user")
        integration = create_integration(client, "geo-client")
        response = start_auth(client, integration, "geo-user", "geo-nonce-1", geolocation="Paris, FR")
        assert response.status_code == 201, response.text
        response = start_auth(client, integration, "geo-user", "geo-nonce-2", geolocation="g" * 128)
        assert response.status_code == 201, response.text
        response = start_auth(client, integration, "geo-user", "geo-nonce-3", geolocation=None)
        assert response.status_code == 201, response.text
        logs = admin_request(client, "GET", "/api/admin/auth-logs").json()["data"]
        assert sorted(str(row["detail"].get("geolocation")) for row in logs) == sorted(["Paris, FR", "g" * 128, "None"])


@pytest.mark.parametrize(
    "body",
    [
        b'{"username":"geo-user","system":"box","offline_code":' + b"9" * 5000 + b"}",
        b"[" * 100000 + b"]" * 100000,
        b'{"username":"geo-user","system":"box","extra":' + b"[" * 100000 + b"]" * 100000 + b"}",
    ],
    ids=["huge-integer", "deep-array", "deep-field"],
)
def test_unparseable_bodies_are_422_not_500(tmp_path, body) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        create_user(client, "geo-user")
        integration = create_integration(client, "geo-client")
        response = raw_signed_start(client, integration, body, "deep-nonce")
        assert response.status_code == 422, response.text[:200]
        assert response.json()["detail"]["code"] == "invalid_json"


def test_auth_logs_already_holding_non_finite_values_still_render(tmp_path) -> None:
    """Rows written before this check cannot be deleted; reading them must work."""
    app = sqlite_app(tmp_path)
    with TestClient(app) as client:
        user = create_user(client, "old-user")
        with app.state.db.SessionLocal() as db:
            db.add(
                AuthLogEntry(
                    auth_request_id="00000000-0000-0000-0000-000000000000",
                    user_id=user["id"],
                    integration_id="legacy",
                    username="old-user",
                    system="box",
                    status="pending",
                    detail={"geolocation": float("nan"), "nested": [float("inf"), {"x": float("-inf")}], "ok": 1.5},
                )
            )
            db.commit()
        logs = admin_request(client, "GET", "/api/admin/auth-logs")
        assert logs.status_code == 200, logs.text
        detail = logs.json()["data"][0]["detail"]
        assert detail == {"geolocation": None, "nested": [None, {"x": None}], "ok": 1.5}
        json.dumps(logs.json(), allow_nan=False)
