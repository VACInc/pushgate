"""Approvals and trusted sessions belong to the device key that signed them.

Replacing a device's key (admin PATCH, rotation plus re-enrollment) or
re-admitting a revoked device starts a new trust epoch. Anything decided under
the previous key must stop admitting logins, while approvals signed with the
new key keep working normally.
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from qa.test_audit_2026_10_28 import make_app
from qa.test_server_hardening import admin_request, consume_auth, decide, start_auth
from qa.trusted.test_revocation import consumed_push, setup
from server.app.models import AuthRequest


def new_key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    return key, base64.b64encode(key.public_key().public_bytes_raw()).decode()


def rekey(client: TestClient, device: dict, mode: str) -> Ed25519PrivateKey | None:
    """Apply one re-key mode; return the key that now signs for the device."""
    if mode == "patch_public_key":
        key, public_key = new_key()
        response = admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"public_key": public_key})
        assert response.status_code == 200
        return key
    if mode == "rotate_and_reenroll":
        rotated = admin_request(client, "POST", f"/api/admin/devices/{device['id']}/rotation")
        assert rotated.status_code == 200
        token = json.loads(rotated.json()["data"]["enrollment_qr_payload"])["enrollment_token"]
        key, public_key = new_key()
        enrolled = client.post(
            f"/api/v1/devices/{device['id']}/enroll",
            json={"enrollment_token": token, "public_key": public_key},
        )
        assert enrolled.status_code == 200
        return key
    if mode == "revoke_then_readmit":
        assert admin_request(client, "DELETE", f"/api/admin/devices/{device['id']}").status_code == 204
        readmitted = admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"revoked": False})
        assert readmitted.status_code == 200
        return None
    raise AssertionError(mode)


MODES = ["patch_public_key", "rotate_and_reenroll", "revoke_then_readmit"]


@pytest.mark.parametrize("mode", MODES)
def test_unconsumed_approval_signed_by_replaced_key_cannot_be_consumed(tmp_path, mode):
    app = make_app(tmp_path, f"rekey-grant-{mode}.db")
    with TestClient(app) as client:
        principal, _, device, key, integration = setup(client)
        # setup() enables trusted sessions; this test is about one fresh grant.
        admin_request(client, "PATCH", "/api/admin/settings/global", json={"trusted_session_window_seconds": 0})
        started = start_auth(client, integration, principal["username"], "rekey-grant")
        request_id = started.json()["data"]["id"]
        assert decide(client, request_id, device["id"], key).json()["data"]["status"] == "approved"

        current_key = rekey(client, device, mode) or key

        consumed = consume_auth(client, integration, request_id, "rekey-grant-consume")
        assert consumed.status_code == 409
        assert consumed.json()["detail"]["status"] == "denied"
        with app.state.db.SessionLocal() as db:
            row = db.get(AuthRequest, request_id)
            assert row.consumed_at is None
            assert row.factor == "device_rekeyed"

        # The device keeps working with whatever key it holds now.
        fresh = start_auth(client, integration, principal["username"], "rekey-fresh")
        fresh_id = fresh.json()["data"]["id"]
        assert decide(client, fresh_id, device["id"], current_key).json()["data"]["status"] == "approved"
        assert consume_auth(client, integration, fresh_id, "rekey-fresh-consume").status_code == 200


@pytest.mark.parametrize("mode", MODES)
def test_trusted_session_from_replaced_key_does_not_survive_rekey(tmp_path, mode):
    app = make_app(tmp_path, f"rekey-trust-{mode}.db", trusted_session_window_seconds=600)
    with TestClient(app) as client:
        principal, _, device, key, integration = setup(client)
        consumed_push(client, principal, device, key, integration, "rekey-trust")
        # Control: without a re-key the consumed approval does seed trust.
        reused = start_auth(client, integration, principal["username"], "rekey-trust-control")
        assert reused.json()["data"]["status"] == "approved"
        derived_id = reused.json()["data"]["id"]

        current_key = rekey(client, device, mode) or key

        # A trusted-session grant derived before the re-key is not consumable.
        derived = consume_auth(client, integration, derived_id, "rekey-derived-consume")
        assert derived.status_code == 409
        # And the old approval no longer seeds new trusted sessions.
        after = start_auth(client, integration, principal["username"], "rekey-trust-after")
        assert after.json()["data"]["status"] == "pending"
        after_id = after.json()["data"]["id"]

        # An approval signed under the current key seeds trust again.
        assert decide(client, after_id, device["id"], current_key).json()["data"]["status"] == "approved"
        assert consume_auth(client, integration, after_id, "rekey-trust-after-consume").status_code == 200
        again = start_auth(client, integration, principal["username"], "rekey-trust-again")
        assert again.json()["data"]["status"] == "approved"
        assert consume_auth(client, integration, again.json()["data"]["id"], "rekey-trust-again-consume").status_code == 200


def test_unrelated_device_patch_keeps_existing_grants(tmp_path):
    app = make_app(tmp_path, "rekey-rename.db")
    with TestClient(app) as client:
        principal, _, device, key, integration = setup(client)
        admin_request(client, "PATCH", "/api/admin/settings/global", json={"trusted_session_window_seconds": 0})
        started = start_auth(client, integration, principal["username"], "rename-grant")
        request_id = started.json()["data"]["id"]
        assert decide(client, request_id, device["id"], key).json()["data"]["status"] == "approved"
        renamed = admin_request(
            client, "PATCH", f"/api/admin/devices/{device['id']}", json={"name": "renamed", "revoked": False}
        )
        assert renamed.status_code == 200
        assert consume_auth(client, integration, request_id, "rename-grant-consume").status_code == 200
