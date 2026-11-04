"""Time cutoffs must not depend on the PostgreSQL session time zone.

The cutoffs for replay-nonce pruning, trusted sessions, source-name prewarm
and the auth/audit log filters were naive datetimes holding UTC digits. The
columns are timestamptz, so PostgreSQL read those cutoffs in the session time
zone. West of UTC the nonce cutoff landed hours in the future, so every
signed request first deleted every stored nonce and any replay was accepted;
east of UTC a trusted session outlived its window by the UTC offset.
"""
from __future__ import annotations

import os
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import Nonce
from server.app.security import utcnow

from test_server_hardening import (
    ADMIN_TOKEN,
    admin_request,
    consume_auth,
    create_device,
    create_integration,
    create_user,
    decide,
    signed_get,
    start_auth,
)

POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")
ZONES = ["America/New_York", "Asia/Tokyo", "Pacific/Kiritimati", "Etc/GMT+12"]


@pytest.fixture()
def zoned_postgres():
    if not POSTGRES_URL:
        pytest.skip("set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    created: list[str] = []

    def make(zone: str) -> str:
        name = "pgtz_" + uuid.uuid4().hex[:12]
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
            conn.execute(text(f"ALTER DATABASE \"{name}\" SET timezone = '{zone}'"))
        created.append(name)
        return POSTGRES_URL.rsplit("/", 1)[0] + "/" + name

    try:
        yield make
    finally:
        with admin.connect() as conn:
            for name in created:
                conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.mark.parametrize("zone", ZONES)
def test_signed_request_replay_is_refused_in_any_session_time_zone(zoned_postgres, zone) -> None:
    app = create_app(Settings(database_url=zoned_postgres(zone), bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "tz-user")
        integration = create_integration(client, "tz-client")
        request_id = start_auth(client, integration, "tz-user", "tz-start").json()["data"]["id"]
        path = f"/api/v1/auth/requests/{request_id}"
        assert signed_get(client, integration, path, "tz-poll").status_code == 200
        replay = signed_get(client, integration, path, "tz-poll")
        assert replay.status_code == 409, replay.text
        assert start_auth(client, integration, "tz-user", "tz-start").status_code == 409
    app.state.db.engine.dispose()


@pytest.mark.parametrize("zone", ZONES)
def test_old_nonces_are_still_pruned(zoned_postgres, zone) -> None:
    app = create_app(Settings(database_url=zoned_postgres(zone), bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "tz-user")
        integration = create_integration(client, "tz-client")
        with app.state.db.SessionLocal() as db:
            db.add(Nonce(integration_id=integration["id"], nonce="stale", created_at=utcnow() - timedelta(hours=1)))
            db.add(Nonce(integration_id=integration["id"], nonce="recent", created_at=utcnow() - timedelta(seconds=30)))
            db.commit()
        assert start_auth(client, integration, "tz-user", "tz-prune").status_code == 201
        with app.state.db.SessionLocal() as db:
            kept = set(db.scalars(select(Nonce.nonce)).all())
        assert "stale" not in kept
        assert {"recent", "tz-prune"} <= kept
    app.state.db.engine.dispose()


@pytest.mark.parametrize("zone", ZONES)
def test_trusted_session_ends_with_its_window_in_any_session_time_zone(zoned_postgres, zone) -> None:
    app = create_app(
        Settings(database_url=zoned_postgres(zone), bootstrap_token=ADMIN_TOKEN, trusted_session_window_seconds=60)
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        user = create_user(client, "tz-user")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "tz-client")
        request_id = start_auth(client, integration, "tz-user", "tz-1").json()["data"]["id"]
        assert decide(client, request_id, device["id"], key).status_code == 200
        assert consume_auth(client, integration, request_id, "tz-2").status_code == 200
        # Within the window the trusted session applies.
        assert start_auth(client, integration, "tz-user", "tz-3").json()["data"]["status"] == "approved"
        with app.state.db.engine.begin() as conn:
            conn.execute(
                text("UPDATE auth_requests SET consumed_at = consumed_at - interval '3 hours' WHERE consumed_at IS NOT NULL")
            )
        later = start_auth(client, integration, "tz-user", "tz-4").json()["data"]
        assert later["status"] == "pending", later
    app.state.db.engine.dispose()


@pytest.mark.parametrize("zone", ["Asia/Tokyo", "America/New_York"])
def test_log_time_filters_mean_utc_in_any_session_time_zone(zoned_postgres, zone) -> None:
    app = create_app(Settings(database_url=zoned_postgres(zone), bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "tz-user")
        integration = create_integration(client, "tz-client")
        assert start_auth(client, integration, "tz-user", "tz-log").status_code == 201
        with app.state.db.SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(Nonce)) >= 1
        before = (utcnow() - timedelta(minutes=5)).isoformat()
        after = (utcnow() + timedelta(minutes=5)).isoformat()
        rows = admin_request(client, "GET", "/api/admin/auth-logs", params={"from": before, "to": after}).json()["data"]
        assert len(rows) == 1
        assert admin_request(client, "GET", "/api/admin/auth-logs", params={"from": after}).json()["data"] == []
        audits = admin_request(client, "GET", "/api/admin/audit-logs", params={"from": before, "to": after}).json()["data"]
        assert audits
    app.state.db.engine.dispose()


def test_sqlite_replay_and_trusted_window_still_hold(tmp_path) -> None:
    app = create_app(
        Settings(database_url=f"sqlite:///{tmp_path / 'tz.db'}", bootstrap_token=ADMIN_TOKEN, trusted_session_window_seconds=60)
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        user = create_user(client, "tz-user")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "tz-client")
        request_id = start_auth(client, integration, "tz-user", "s-1").json()["data"]["id"]
        assert start_auth(client, integration, "tz-user", "s-1").status_code == 409
        assert decide(client, request_id, device["id"], key).status_code == 200
        assert consume_auth(client, integration, request_id, "s-2").status_code == 200
        assert start_auth(client, integration, "tz-user", "s-3").json()["data"]["status"] == "approved"
        with app.state.db.SessionLocal() as db:
            from server.app.models import AuthRequest

            row = db.get(AuthRequest, request_id)
            row.consumed_at = utcnow() - timedelta(hours=3)
            db.commit()
        assert start_auth(client, integration, "tz-user", "s-4").json()["data"]["status"] == "pending"
