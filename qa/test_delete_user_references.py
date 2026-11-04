"""Deleting a user never orphans rows (SQLite) or fails with a 500 (PostgreSQL).

A user with devices or authentication history can only be locked: those rows are
kept for the append-only logs. Group memberships and backup codes are removed with
the user.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import BackupCode, UserGroup
from qa.test_server_hardening import ADMIN_TOKEN, admin_request, create_device, create_integration, create_user, start_auth

POSTGRES_URL = os.environ.get("PUSHGATE_TEST_POSTGRES_URL")


@pytest.fixture(params=["sqlite", "postgresql"])
def database_url(request, tmp_path: Path):
    if request.param == "sqlite":
        yield f"sqlite:///{tmp_path / 'delete-user.db'}"
        return
    if not POSTGRES_URL:
        pytest.skip("set PUSHGATE_TEST_POSTGRES_URL to a disposable database")
    name = "pgdel_" + uuid.uuid4().hex[:12]
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield POSTGRES_URL.rsplit("/", 1)[0] + "/" + name
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_user_with_devices_or_history_is_kept_and_reported(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url, bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        with_device = create_user(client, "with-device")
        create_device(client, with_device["id"])
        with_history = create_user(client, "with-history")
        integration = create_integration(client, "delete-user-host")
        assert start_auth(client, integration, "with-history", "del-1").status_code == 201
        approver = create_user(client, "approver-only")
        delegated = create_integration(client, "delete-user-delegated", principal_username="with-history",
                                       approver_username="approver-only")
        assert start_auth(client, delegated, "with-history", "del-2").status_code == 201

        for user in (with_device, with_history, approver):
            response = admin_request(client, "DELETE", f"/api/admin/users/{user['id']}")
            assert response.status_code == 409, response.text
            assert response.json()["detail"]["code"] == "user_in_use"
            assert admin_request(client, "GET", f"/api/admin/users/{user['id']}").status_code == 200
    app.state.db.engine.dispose()


def test_user_delete_removes_memberships_and_backup_codes(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url, bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        user = create_user(client, "leaver")
        group = admin_request(client, "POST", "/api/admin/groups", json={"name": "ops"}).json()["data"]
        assert admin_request(client, "POST", f"/api/admin/groups/{group['id']}/users/{user['id']}").status_code == 201
        assert admin_request(client, "POST", f"/api/admin/users/{user['id']}/backup-codes", params={"count": 2}).status_code == 200

        response = admin_request(client, "DELETE", f"/api/admin/users/{user['id']}")
        assert response.status_code == 204, response.text
        assert admin_request(client, "GET", f"/api/admin/users/{user['id']}").status_code == 404
        assert admin_request(client, "GET", f"/api/admin/groups/{group['id']}/users").json()["data"] == []
        with app.state.db.SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(UserGroup).where(UserGroup.user_id == user["id"])) == 0
            assert db.scalar(select(func.count()).select_from(BackupCode).where(BackupCode.user_id == user["id"])) == 0
        audit = admin_request(client, "GET", "/api/admin/audit-logs", params={"action": "user.delete", "resource_id": user["id"]})
        assert audit.json()["meta"]["count"] == 1
        # Deleting again is still a quiet no-op.
        assert admin_request(client, "DELETE", f"/api/admin/users/{user['id']}").status_code == 204
    app.state.db.engine.dispose()
