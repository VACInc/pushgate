"""A PostgreSQL server that only reads is not ready and is an outage.

During a failover a pooled connection, a stale VIP or a misrouted proxy can
land on a hot standby or a demoted leader. It answers `SELECT 1`, so
/readyz said ready and kept traffic coming, while every login (each one
writes its replay nonce) failed with 500 "cannot execute INSERT in a
read-only transaction".
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import InternalError

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, create_integration, create_user, start_auth

POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")


class FakeDriverError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("driver error")
        self.sqlstate = sqlstate


def test_read_only_transaction_error_is_503_database_unavailable(tmp_path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'ro.db'}", bootstrap_token=ADMIN_TOKEN))
    handler = app.exception_handlers[InternalError]
    response = asyncio.run(handler(None, InternalError("INSERT", {}, FakeDriverError("25006"))))
    assert response.status_code == 503
    assert json.loads(response.body)["detail"]["code"] == "database_unavailable"


def test_other_internal_errors_stay_unhandled(tmp_path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'ro.db'}", bootstrap_token=ADMIN_TOKEN))
    handler = app.exception_handlers[InternalError]
    other = InternalError("INSERT", {}, FakeDriverError("XX000"))
    with pytest.raises(InternalError):
        asyncio.run(handler(None, other))


@pytest.fixture()
def postgres_database():
    if not POSTGRES_URL:
        pytest.skip("set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
    name = "pgro_" + uuid.uuid4().hex[:12]
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))

    def read_only(enabled: bool) -> None:
        with admin.connect() as conn:
            conn.execute(text(f'ALTER DATABASE "{name}" SET default_transaction_read_only = {"on" if enabled else "off"}'))

    try:
        yield POSTGRES_URL.rsplit("/", 1)[0] + "/" + name, read_only
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_postgres_read_only_database_is_not_ready_and_logins_get_503(postgres_database) -> None:
    url, read_only = postgres_database
    app = create_app(Settings(database_url=url, bootstrap_token=ADMIN_TOKEN))
    app.state.readiness["reuse"] = 0.0
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "ro-user")
        integration = create_integration(client, "ro-client")
        assert client.get("/readyz").status_code == 200

        read_only(True)
        app.state.db.engine.dispose()  # new sessions pick up the setting
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["database"] == "unavailable"
        login = start_auth(client, integration, "ro-user", "ro-nonce-1")
        assert login.status_code == 503, login.text
        assert login.json()["detail"]["code"] == "database_unavailable"

        read_only(False)
        app.state.db.engine.dispose()
        assert client.get("/readyz").status_code == 200
        assert start_auth(client, integration, "ro-user", "ro-nonce-2").status_code == 201
    app.state.db.engine.dispose()
