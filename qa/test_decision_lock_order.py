"""A device decision proves who sent it before it takes any database lock.

The decision route is reachable without an API key or integration secret: the
device signature is the only credential. Before this check, every POST took
SQLite's single write lock (BEGIN IMMEDIATE) and, on PostgreSQL, row locks on
the principal and approver, before looking at the signature. Anyone on the
network could then queue on the locks every login needs; a login that waited
past the busy or lock timeout got 503, which a PAM helper reads as an outage.
"""
from __future__ import annotations

import base64
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import (
    ADMIN_TOKEN,
    create_device,
    create_integration,
    create_user,
    decide,
    start_auth,
)

POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")
# Well under SQLite's 5 s busy timeout and PostgreSQL's 5 s lock timeout.
PROMPT_SECONDS = 2.0


def sqlite_app(tmp_path: Path):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 'decide.db'}", bootstrap_token=ADMIN_TOKEN))


def forged_decision(client: TestClient, request_id: str, device_id: str):
    return client.post(
        f"/api/v1/auth/requests/{request_id}/decision",
        json={
            "device_id": device_id,
            "decision": "approve",
            "signature": base64.b64encode(b"\x00" * 64).decode(),
            "biometric_verified": False,
        },
    )


def pending_request(client: TestClient, name: str) -> tuple[str, dict, object]:
    user = create_user(client, name)
    device, key = create_device(client, user["id"])
    integration = create_integration(client, f"{name}-client")
    started = start_auth(client, integration, name, f"{name}-start-nonce")
    assert started.status_code == 201, started.text
    return started.json()["data"]["id"], device, key


@pytest.fixture()
def sqlite_write_lock(tmp_path):
    """Hold SQLite's write lock from another connection, like a busy writer."""
    holder: dict[str, sqlite3.Connection] = {}

    def hold() -> None:
        connection = sqlite3.connect(str(tmp_path / "decide.db"), timeout=0, isolation_level=None)
        connection.execute("BEGIN IMMEDIATE")
        holder["connection"] = connection

    yield hold
    if "connection" in holder:
        holder["connection"].execute("ROLLBACK")
        holder["connection"].close()


@pytest.mark.parametrize("which", ["unknown_request", "forged_signature", "unknown_device"])
def test_unauthenticated_decision_never_waits_for_the_sqlite_write_lock(tmp_path, sqlite_write_lock, which) -> None:
    with TestClient(sqlite_app(tmp_path), raise_server_exceptions=False) as client:
        request_id, device, _key = pending_request(client, "lock-user")
        target = str(uuid.uuid4()) if which == "unknown_request" else request_id
        device_id = str(uuid.uuid4()) if which == "unknown_device" else device["id"]
        sqlite_write_lock()
        started = time.monotonic()
        response = forged_decision(client, target, device_id)
        elapsed = time.monotonic() - started
        assert response.status_code in (403, 404), response.text
        assert elapsed < PROMPT_SECONDS


def test_signed_decision_still_serializes_and_approves(tmp_path) -> None:
    with TestClient(sqlite_app(tmp_path)) as client:
        request_id, device, key = pending_request(client, "ok-user")
        approved = decide(client, request_id, device["id"], key)
        assert approved.status_code == 200, approved.text
        assert approved.json()["data"]["status"] == "approved"
        # The first answer wins; a replayed signed decision changes nothing.
        again = decide(client, request_id, device["id"], key)
        assert again.status_code == 200
        assert again.json()["data"] == {"id": request_id, "status": "approved", "first_response_wins": True}


def test_device_revoked_after_the_signature_check_is_still_rejected(tmp_path, monkeypatch) -> None:
    """The early check is only a filter: the locked re-check decides."""
    app = sqlite_app(tmp_path)
    with TestClient(app, raise_server_exceptions=False) as client:
        request_id, device, key = pending_request(client, "race-user")
        import server.app.main as main_module

        real_verify = main_module.verify_device_signature
        calls = {"count": 0}

        def verify_then_revoke(*args, **kwargs):
            calls["count"] += 1
            result = real_verify(*args, **kwargs)
            if calls["count"] == 1:
                engine = create_engine(f"sqlite:///{tmp_path / 'decide.db'}")
                with engine.begin() as connection:
                    connection.execute(text("UPDATE devices SET revoked = 1 WHERE id = :id"), {"id": device["id"]})
                engine.dispose()
            return result

        monkeypatch.setattr(main_module, "verify_device_signature", verify_then_revoke)
        response = decide(client, request_id, device["id"], key)
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "device_rejected"


@pytest.mark.skipif(not POSTGRES_URL, reason="set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
def test_forged_decision_never_waits_on_postgres_user_row_locks() -> None:
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "pushgate_decide_" + uuid.uuid4().hex[:12]
    url = POSTGRES_URL.rsplit("/", 1)[0] + "/" + name
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        app = create_app(Settings(database_url=url, bootstrap_token=ADMIN_TOKEN))
        with TestClient(app, raise_server_exceptions=False) as client:
            request_id, device, _key = pending_request(client, "pg-lock-user")
            holder = create_engine(url)
            with holder.connect() as connection:
                connection.execute(text("SELECT id FROM users WHERE username = 'pg-lock-user' FOR UPDATE"))
                release = threading.Timer(8, connection.rollback)
                release.start()
                try:
                    started = time.monotonic()
                    response = forged_decision(client, request_id, device["id"])
                    elapsed = time.monotonic() - started
                finally:
                    release.cancel()
                    connection.rollback()
            holder.dispose()
            assert response.status_code == 403, response.text
            assert elapsed < PROMPT_SECONDS
            app.state.db.engine.dispose()
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()
