"""Regression tests for the 2026-10-28 adversarial review findings F1-F4."""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from server.app.config import Settings
from server.app.db import Database
from server.app.main import create_app
from server.app.models import AuthRequest
from qa.test_server_hardening import (
    ADMIN_TOKEN,
    admin_request,
    consume_auth,
    create_device,
    create_integration,
    create_user,
    decide,
    signed_ws_path,
    start_auth,
)


POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")


def make_app(tmp_path: Path, name: str, **overrides):
    # With a disposable PostgreSQL configured, F1/F2 also run on its row locks.
    database_url = POSTGRES_URL or f"sqlite:///{tmp_path / name}"
    return create_app(Settings(database_url=database_url, bootstrap_token=ADMIN_TOKEN, **overrides))


def bound_setup(client: TestClient, name: str):
    user = create_user(client, name)
    device, key = create_device(client, user["id"])
    integration = create_integration(client, name, principal_username=user["username"])
    return user, device, key, integration


# F1: one approval admits exactly one login attempt.


def test_separate_login_attempts_with_same_context_get_separate_approvals(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f1-separate.db")
    with TestClient(app) as client:
        user, device, key, integration = bound_setup(client, "f1-separate")
        # Two concurrent PAM processes for the same account, host and source.
        first = start_auth(client, integration, user["username"], "f1-a", source_ip="10.0.0.9")
        second = start_auth(client, integration, user["username"], "f1-b", source_ip="10.0.0.9")
        assert first.status_code == second.status_code == 201
        first_id = first.json()["data"]["id"]
        second_id = second.json()["data"]["id"]
        assert first_id != second_id

        assert decide(client, first_id, device["id"], key).json()["data"]["status"] == "approved"
        assert consume_auth(client, integration, first_id, "f1-consume-a").status_code == 200
        # The one tap never admits the other login.
        other = consume_auth(client, integration, second_id, "f1-consume-b")
        assert other.status_code == 409
        assert other.json()["detail"]["status"] == "pending"


def test_consumed_approval_is_never_consumed_again_even_after_expiry(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f1-single.db")
    with TestClient(app) as client:
        user, device, key, integration = bound_setup(client, "f1-single")
        request_id = start_auth(client, integration, user["username"], "f1-single-start").json()["data"]["id"]
        decide(client, request_id, device["id"], key)
        first = consume_auth(client, integration, request_id, "f1-single-1")
        assert first.status_code == 200 and first.json()["data"]["consumed"] is True

        again = consume_auth(client, integration, request_id, "f1-single-2")
        assert again.status_code == 409
        assert again.json()["detail"] == {"code": "auth_not_consumable", "status": "approved"}

        with app.state.db.SessionLocal() as db:
            row = db.get(AuthRequest, request_id)
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=30)
            db.commit()
        expired = consume_auth(client, integration, request_id, "f1-single-3")
        assert expired.status_code == 409


def test_same_attempt_retry_shares_and_invalid_attempt_id_is_rejected(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f1-attempt.db")
    with TestClient(app) as client:
        user, _device, _key, integration = bound_setup(client, "f1-attempt")
        first = start_auth(client, integration, user["username"], "f1-att-1", attempt_id="attempt-aaaaaaaaaaaa")
        retry = start_auth(client, integration, user["username"], "f1-att-2", attempt_id="attempt-aaaaaaaaaaaa")
        other = start_auth(client, integration, user["username"], "f1-att-3", attempt_id="attempt-bbbbbbbbbbbb")
        assert retry.json()["data"]["id"] == first.json()["data"]["id"]
        assert retry.json()["data"]["duplicate"] is True
        assert other.json()["data"]["id"] != first.json()["data"]["id"]
        for bad in ("short", "x" * 129, "has space in it!!", 12345678901234567):
            rejected = start_auth(client, integration, user["username"], f"f1-bad-{bad!s:.8}", attempt_id=bad)
            assert rejected.status_code == 422
            assert rejected.json()["detail"]["code"] == "invalid_attempt_id"


# F2: revocation after approval but before consumption denies the login.


@pytest.mark.parametrize("who", ["principal", "approver"])
def test_lockout_cancels_pending_and_approved_unconsumed_requests(tmp_path: Path, who: str) -> None:
    app = make_app(tmp_path, f"f2-lock-{who}.db")
    with TestClient(app) as client:
        principal = create_user(client, f"f2-{who}-principal")
        approver = create_user(client, f"f2-{who}-approver")
        device, key = create_device(client, approver["id"])
        integration = create_integration(
            client, f"f2-{who}", principal_username=principal["username"], approver_username=approver["username"]
        )
        approved_id = start_auth(client, integration, principal["username"], "f2-approved").json()["data"]["id"]
        assert decide(client, approved_id, device["id"], key).json()["data"]["status"] == "approved"
        pending_id = start_auth(client, integration, principal["username"], "f2-pending").json()["data"]["id"]

        target = principal if who == "principal" else approver
        assert admin_request(client, "POST", f"/api/admin/users/{target['id']}/lockout").status_code == 200

        expected_factor = "lockout" if who == "principal" else "approver_lockout"
        with app.state.db.SessionLocal() as db:
            for request_id in (approved_id, pending_id):
                row = db.get(AuthRequest, request_id)
                assert (row.status, row.factor, row.consumed_at) == ("denied", expected_factor, None)
        refused = consume_auth(client, integration, approved_id, "f2-consume")
        assert refused.status_code == 409
        assert refused.json()["detail"]["status"] == "denied"
        # Unlocking never revives a cancelled approval.
        admin_request(client, "DELETE", f"/api/admin/users/{target['id']}/lockout")
        assert consume_auth(client, integration, approved_id, "f2-consume-2").status_code == 409


def test_patch_lock_also_cancels_approved_unconsumed(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f2-patch.db")
    with TestClient(app) as client:
        user, device, key, integration = bound_setup(client, "f2-patch")
        request_id = start_auth(client, integration, user["username"], "f2-patch-start").json()["data"]["id"]
        decide(client, request_id, device["id"], key)
        assert admin_request(client, "PATCH", f"/api/admin/users/{user['id']}", json={"locked": True}).status_code == 200
        assert consume_auth(client, integration, request_id, "f2-patch-consume").status_code == 409


def test_consume_revalidates_locked_users_and_revoked_approving_device(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f2-revalidate.db")
    with TestClient(app) as client:
        user, device, key, integration = bound_setup(client, "f2-reval")

        # A lock written without the lockout endpoint (any other writer).
        locked_id = start_auth(client, integration, user["username"], "f2-r1").json()["data"]["id"]
        decide(client, locked_id, device["id"], key)
        from server.app.models import User

        with app.state.db.SessionLocal() as db:
            db.get(User, user["id"]).locked = True
            db.commit()
        refused = consume_auth(client, integration, locked_id, "f2-r1-consume")
        assert refused.status_code == 409 and refused.json()["detail"]["status"] == "denied"
        with app.state.db.SessionLocal() as db:
            assert db.get(AuthRequest, locked_id).factor == "lockout"
            db.get(User, user["id"]).locked = False
            db.commit()

        # Approving device lost its key (re-enrollment) after approving.
        rekeyed_id = start_auth(client, integration, user["username"], "f2-r3").json()["data"]["id"]
        decide(client, rekeyed_id, device["id"], key)
        from server.app.models import Device

        with app.state.db.SessionLocal() as db:
            saved_material = db.get(Device, device["id"]).public_key
            db.get(Device, device["id"]).public_key = None
            db.commit()
        refused = consume_auth(client, integration, rekeyed_id, "consume-3")
        assert refused.status_code == 409 and refused.json()["detail"]["status"] == "denied"
        with app.state.db.SessionLocal() as db:
            assert db.get(AuthRequest, rekeyed_id).factor == "device_revoked"
            db.get(Device, device["id"]).public_key = saved_material
            db.commit()

        revoked_id = start_auth(client, integration, user["username"], "f2-r2").json()["data"]["id"]
        decide(client, revoked_id, device["id"], key)
        patched = admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"revoked": True})
        assert patched.status_code == 200
        refused = consume_auth(client, integration, revoked_id, "f2-r2-consume")
        assert refused.status_code == 409 and refused.json()["detail"]["status"] == "denied"
        with app.state.db.SessionLocal() as db:
            assert db.get(AuthRequest, revoked_id).factor == "device_revoked"


def test_consume_revalidates_a_separately_locked_approver(tmp_path: Path) -> None:
    app = make_app(tmp_path, "f2-approver-reval.db")
    with TestClient(app) as client:
        principal = create_user(client, "f2-reval-principal")
        approver = create_user(client, "f2-reval-approver")
        device, key = create_device(client, approver["id"])
        integration = create_integration(
            client, "f2-reval-bound", principal_username=principal["username"], approver_username=approver["username"]
        )
        request_id = start_auth(client, integration, principal["username"], "f2-ra").json()["data"]["id"]
        assert decide(client, request_id, device["id"], key).json()["data"]["status"] == "approved"
        from server.app.models import User

        with app.state.db.SessionLocal() as db:
            db.get(User, approver["id"]).locked = True
            db.commit()
        refused = consume_auth(client, integration, request_id, "f2-ra-consume")
        assert refused.status_code == 409 and refused.json()["detail"]["status"] == "denied"
        with app.state.db.SessionLocal() as db:
            assert db.get(AuthRequest, request_id).factor == "approver_lockout"


# F3: a socket on one edge sees another edge's requests and decisions.


def receive_json_within(websocket, seconds: float) -> dict:
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = websocket.receive_json()
        except BaseException as exc:  # pragma: no cover - surfaced below
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise AssertionError(f"no WebSocket event within {seconds}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def test_websocket_on_one_edge_receives_other_edge_request_and_decision(tmp_path: Path) -> None:
    settings = dict(
        database_url=f"sqlite:///{tmp_path / 'f3-shared.db'}",
        bootstrap_token=ADMIN_TOKEN,
        ws_reconcile_seconds=0.2,
    )
    edge_a = create_app(Settings(**settings))
    edge_b = create_app(Settings(**settings))
    with TestClient(edge_a) as client_a, TestClient(edge_b) as client_b:
        user, device, key, integration = bound_setup(client_a, "f3-user")
        with client_a.websocket_connect(signed_ws_path(device["id"], key, "f3-ws")) as ws:
            assert ws.receive_json() == {"type": "pending", "data": []}
            # The request lands on edge B; edge A's in-process fan-out never hears it.
            request_id = start_auth(client_b, integration, user["username"], "f3-start").json()["data"]["id"]
            announced = receive_json_within(ws, 3)
            assert announced["type"] == "auth_request" and announced["data"]["id"] == request_id

            # Several reconcile ticks pass: an announced request is never re-sent.
            time.sleep(1.0)
            assert decide(client_b, request_id, device["id"], key).json()["data"]["status"] == "approved"
            settled = receive_json_within(ws, 3)
            assert settled["type"] == "auth_decided"
            assert settled["data"]["id"] == request_id and settled["data"]["status"] == "approved"
            ws.close()


# F4: bounded statement and lock waits on PostgreSQL sessions.


def test_postgres_sessions_get_statement_and_lock_timeouts() -> None:
    url = "postgresql+psycopg://pushgate:secret@db.invalid:5432/pushgate"
    options = Database.engine_options(url)["connect_args"]["options"]
    assert options == "-c statement_timeout=15000 -c lock_timeout=5000"
    assert Database.engine_options(url, 2000, 0)["connect_args"]["options"] == "-c statement_timeout=2000"
    assert "options" not in Database.engine_options(url, 0, 0)["connect_args"]
    # An explicit libpq options parameter is an operator override.
    override = url + "?options=-c%20statement_timeout%3D1"
    assert "options" not in Database.engine_options(override)["connect_args"]
    assert "options" not in Database.engine_options("sqlite:////tmp/x.db").get("connect_args", {})


def test_settings_feed_database_timeouts(monkeypatch) -> None:
    seen = {}
    real_options = Database.engine_options

    def recording(url, statement_timeout_ms=None, lock_timeout_ms=None):
        seen["args"] = (statement_timeout_ms, lock_timeout_ms)
        return real_options(url, statement_timeout_ms, lock_timeout_ms)

    monkeypatch.setattr(Database, "engine_options", staticmethod(recording))
    create_app(Settings(database_url="sqlite://", bootstrap_token=ADMIN_TOKEN,
                        db_statement_timeout_ms=1234, db_lock_timeout_ms=567))
    assert seen["args"] == (1234, 567)


@pytest.mark.skipif(not POSTGRES_URL, reason="set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
def test_live_postgres_lock_and_statement_waits_are_bounded() -> None:
    db = Database(POSTGRES_URL, 1500, 400)
    db.init()  # schema install still works with timeouts set
    holder = Database(POSTGRES_URL, 0, 0)
    with holder.engine.connect() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS f4_lock_probe (id int primary key)"))
        conn.execute(text("INSERT INTO f4_lock_probe VALUES (1) ON CONFLICT DO NOTHING"))
        conn.commit()
        conn.execute(text("SELECT id FROM f4_lock_probe WHERE id = 1 FOR UPDATE"))
        release = threading.Timer(6, conn.rollback)
        release.start()
        try:
            started = time.monotonic()
            with pytest.raises(OperationalError, match="lock timeout"):
                with db.engine.connect() as waiter:
                    waiter.execute(text("SELECT id FROM f4_lock_probe WHERE id = 1 FOR UPDATE"))
            assert time.monotonic() - started < 3
        finally:
            release.cancel()
            conn.rollback()
    started = time.monotonic()
    with pytest.raises(OperationalError, match="statement timeout"):
        with db.engine.connect() as slow:
            slow.execute(text("SELECT pg_sleep(6)"))
    assert time.monotonic() - started < 4
