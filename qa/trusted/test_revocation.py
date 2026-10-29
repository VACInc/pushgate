"""Push-derived trust follows its device through creation and consumption."""
from datetime import timedelta

import pyotp
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from qa.test_audit_2026_10_28 import make_app
from qa.test_server_hardening import (
    admin_request, consume_auth, create_device, create_integration, create_user, decide, start_auth,
)
from server.app.models import AuthRequest, Device
from server.app.security import utcnow


def setup(client):
    assert admin_request(client, "PATCH", "/api/admin/settings/global",
                         json={"trusted_session_window_seconds": 600}).status_code == 200
    suffix = uuid4().hex[:12]
    principal = create_user(client, "trust-principal-" + suffix)
    approver = create_user(client, "trust-approver-" + suffix)
    device, key = create_device(client, approver["id"])
    integration = create_integration(client, "trust-" + suffix, principal_username=principal["username"],
                                     approver_username=approver["username"])
    return principal, approver, device, key, integration


def consumed_push(client, principal, device, key, integration, nonce="initial"):
    response = start_auth(client, integration, principal["username"], nonce)
    assert response.status_code == 201
    request_id = response.json()["data"]["id"]
    assert decide(client, request_id, device["id"], key).json()["data"]["status"] == "approved"
    assert consume_auth(client, integration, request_id, nonce + "-consume").status_code == 200
    return request_id


def invalidate(app, device, request_id, mode):
    with app.state.db.SessionLocal() as db:
        row = db.get(Device, device["id"])
        if mode == "revoked":
            row.revoked = True
        elif mode == "key_missing":
            row.public_key = None
        elif mode == "wrong_owner":
            row.user_id = db.get(AuthRequest, request_id).user_id
        elif mode == "id_missing":
            db.get(AuthRequest, request_id).approved_by_device_id = None
        db.commit()


@pytest.mark.parametrize("mode", ["api_delete", "api_patch", "revoked", "key_missing", "wrong_owner", "id_missing"])
def test_invalid_push_device_cannot_seed_trust(tmp_path, mode):
    app = make_app(tmp_path, mode + ".db", trusted_session_window_seconds=600)
    with TestClient(app) as client:
        principal, _, device, key, integration = setup(client)
        request_id = consumed_push(client, principal, device, key, integration)
        if mode == "api_delete":
            assert admin_request(client, "DELETE", f"/api/admin/devices/{device['id']}").status_code == 204
        elif mode == "api_patch":
            assert admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"revoked": True}).status_code == 200
        else:
            invalidate(app, device, request_id, mode)
        response = start_auth(client, integration, principal["username"], "after-revoke")
        assert response.status_code == 201
        assert response.json()["data"]["status"] == "pending"
        assert consume_auth(client, integration, response.json()["data"]["id"], "consume-revoked").status_code == 409


@pytest.mark.parametrize("revoke", [False, True])
def test_derived_push_trust_preserves_device_and_rechecks_at_consume(tmp_path, revoke):
    app = make_app(tmp_path, "between.db", trusted_session_window_seconds=600)
    with TestClient(app) as client:
        principal, _, device, key, integration = setup(client)
        consumed_push(client, principal, device, key, integration)
        response = start_auth(client, integration, principal["username"], "reuse")
        assert response.json()["data"]["status"] == "approved"
        request_id = response.json()["data"]["id"]
        with app.state.db.SessionLocal() as db:
            row = db.get(AuthRequest, request_id)
            assert (row.factor, row.approved_by_device_id) == ("trusted_session", device["id"])
        if revoke:
            assert admin_request(client, "DELETE", f"/api/admin/devices/{device['id']}").status_code == 204
        consumed = consume_auth(client, integration, request_id, "reuse-consume")
        assert consumed.status_code == (409 if revoke else 200)
        with app.state.db.SessionLocal() as db:
            row = db.get(AuthRequest, request_id)
            assert row.factor == ("device_revoked" if revoke else "trusted_session")
            assert (row.consumed_at is None) == revoke


@pytest.mark.parametrize("factor", ["totp", "backup_code"])
def test_offline_factor_trust_survives_unrelated_device_revocation(tmp_path, factor):
    app = make_app(tmp_path, factor + ".db", trusted_session_window_seconds=600)
    with TestClient(app) as client:
        principal, _, device, _, integration = setup(client)
        if factor == "totp":
            secret = admin_request(client, "POST", f"/api/admin/users/{principal['id']}/totp").json()["data"]["secret"]
            code = pyotp.TOTP(secret).now()
        else:
            code = admin_request(client, "POST", f"/api/admin/users/{principal['id']}/backup-codes", params={"count": 1}).json()["data"]["codes"][0]
        original = start_auth(client, integration, principal["username"], "offline", offline_code=code).json()["data"]["id"]
        assert consume_auth(client, integration, original, "offline-consume").status_code == 200
        assert admin_request(client, "DELETE", f"/api/admin/devices/{device['id']}").status_code == 204
        response = start_auth(client, integration, principal["username"], "offline-reuse")
        assert response.json()["data"]["status"] == "approved"
        request_id = response.json()["data"]["id"]
        with app.state.db.SessionLocal() as db:
            row = db.get(AuthRequest, request_id)
            assert (row.factor, row.approved_by_device_id) == ("trusted_session", None)
        assert consume_auth(client, integration, request_id, "offline-reuse-consume").status_code == 200


def test_skip_revoked_newest_grant_but_do_not_extend_original_window(tmp_path):
    app = make_app(tmp_path, "fallback.db", trusted_session_window_seconds=600)
    with TestClient(app) as client:
        principal, approver, device, key, integration = setup(client)
        original = consumed_push(client, principal, device, key, integration)
        other, other_key = create_device(client, approver["id"])
        # Explicit fresh approval alongside an older consumed approval.
        # Temporarily disable reuse so a second real push can be consumed.
        admin_request(client, "PATCH", "/api/admin/settings/global", json={"trusted_session_window_seconds": 0})
        latest = consumed_push(client, principal, other, other_key, integration, "latest")
        admin_request(client, "PATCH", "/api/admin/settings/global", json={"trusted_session_window_seconds": 600})
        admin_request(client, "DELETE", f"/api/admin/devices/{other['id']}")
        response = start_auth(client, integration, principal["username"], "fallback")
        request_id = response.json()["data"]["id"]
        assert response.json()["data"]["status"] == "approved"
        with app.state.db.SessionLocal() as db:
            assert db.get(AuthRequest, request_id).approved_by_device_id == device["id"]
        assert consume_auth(client, integration, request_id, "fallback-consume").status_code == 200
        with app.state.db.SessionLocal() as db:
            for rid in (original, latest):
                db.get(AuthRequest, rid).consumed_at = utcnow() - timedelta(seconds=601)
            db.commit()
        # The just-consumed derived request must not extend trust indefinitely.
        assert start_auth(client, integration, principal["username"], "expired").json()["data"]["status"] == "pending"
