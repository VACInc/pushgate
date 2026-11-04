"""Enrollment and admin writes apply the same UnifiedPush host allowlist as the signed route."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from qa.test_server_hardening import ADMIN_TOKEN, admin_request, create_device, create_device_keypair, create_user
from server.app.config import Settings
from server.app.main import create_app
from server.app.models import Device


def pending_device(client: TestClient, user_id: str) -> tuple[str, str]:
    created = admin_request(client, "POST", "/api/admin/devices", json={"user_id": user_id, "name": "new phone"})
    assert created.status_code == 201
    payload = json.loads(created.json()["data"]["enrollment_qr_payload"])
    return payload["device_id"], payload["enrollment_token"]


def enroll(client: TestClient, device_id: str, token: str, push_token: str | None):
    _key, public_key = create_device_keypair()
    return client.post(
        f"/api/v1/devices/{device_id}/enroll",
        json={"enrollment_token": token, "public_key": public_key, "push_token": push_token},
    )


def test_enrollment_refuses_foreign_endpoint_and_keeps_token_usable(tmp_path: Path) -> None:
    app = create_app(Settings(
        database_url=f"sqlite:///{tmp_path / 'enroll-up.db'}", bootstrap_token=ADMIN_TOKEN,
        unifiedpush_allowed_hosts="ntfy.example",
    ))
    with TestClient(app) as client:
        user = create_user(client, "enroll-up")
        device_id, token = pending_device(client, user["id"])

        refused = enroll(client, device_id, token, "https://attacker.example/upX?up=1")
        assert refused.status_code == 422
        assert refused.json()["detail"]["code"] == "push_endpoint_not_allowed"
        with app.state.db.SessionLocal() as db:
            row = db.get(Device, device_id)
            assert row.public_key is None and row.push_token is None
            assert row.enrollment_token_hash is not None

        accepted = enroll(client, device_id, token, "https://ntfy.example/upA?up=1")
        assert accepted.status_code == 200
        assert accepted.json()["data"]["push_token_configured"] is True

        fcm_id, fcm_token = pending_device(client, user["id"])
        assert enroll(client, fcm_id, fcm_token, "plain-fcm-registration-token").status_code == 200
        bare_id, bare_token = pending_device(client, user["id"])
        assert enroll(client, bare_id, bare_token, None).status_code == 200


def test_default_config_refuses_any_unifiedpush_endpoint_at_enrollment(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'enroll-default.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app) as client:
        user = create_user(client, "enroll-default")
        device_id, token = pending_device(client, user["id"])
        assert enroll(client, device_id, token, "https://ntfy.example/upA").status_code == 422


def test_admin_device_writes_apply_the_allowlist(tmp_path: Path) -> None:
    app = create_app(Settings(
        database_url=f"sqlite:///{tmp_path / 'admin-up.db'}", bootstrap_token=ADMIN_TOKEN,
        unifiedpush_allowed_hosts="ntfy.example",
    ))
    with TestClient(app) as client:
        user = create_user(client, "admin-up")
        refused = admin_request(client, "POST", "/api/admin/devices", json={
            "user_id": user["id"], "name": "x", "push_token": "https://attacker.example/up",
        })
        assert refused.status_code == 422
        device, _key = create_device(client, user["id"])
        path = f"/api/admin/devices/{device['id']}"
        assert admin_request(client, "PATCH", path, json={"push_token": "https://attacker.example/up"}).status_code == 422
        assert admin_request(client, "PATCH", path, json={"push_token": "https://ntfy.example/up"}).status_code == 200
        assert admin_request(client, "PATCH", path, json={"push_token": None}).status_code == 200
