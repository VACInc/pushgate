from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pyotp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.db import Database
from server.app.main import create_app
from server.app.models import AuthRequest
from server.app.push import FcmPushProvider
from server.app.security import hash_value, integration_signature


ADMIN_TOKEN = "test-admin-token-0123456789abcdef"


class RecordingSyslog:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, event_type: str, payload: dict) -> None:
        self.events.append((event_type, payload))


class RecordingPushProvider:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls: list[tuple[list[str], dict]] = []

    async def notify_auth_request(self, devices, payload):
        target_ids = [device["id"] for device in devices if device.get("push_token")]
        if target_ids:
            with self._lock:
                self.calls.append((target_ids, json.loads(json.dumps(payload))))
        return {"sent": len(target_ids)}

    def payloads_for(self, device_id: str) -> list[dict]:
        with self._lock:
            return [payload for target_ids, payload in self.calls if device_id in target_ids]


def test_fcm_messages_bind_each_token_to_its_device_id(monkeypatch) -> None:
    requests: list[dict] = []
    real_async_client = httpx.AsyncClient

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"name": "sent"})

    def mock_async_client(*args, **kwargs):
        return real_async_client(
            *args,
            transport=httpx.MockTransport(handle),
            **kwargs,
        )

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", mock_async_client)
    provider = FcmPushProvider(
        "fcm-access-token",
        "fcm-project",
        "https://fcm.example/v1/projects/{project_id}/messages:send",
    )
    payload = {"id": "request-1", "status": "pending"}

    result = asyncio.run(
        provider.notify_auth_request(
            [
                {"id": "phone-1", "push_token": "token-1"},
                {"id": "wear-2", "push_token": "token-2"},
                {"id": "no-token"},
                {"push_token": "missing-device-id"},
            ],
            payload,
        )
    )

    assert result == {"sent": 2}
    outbound = {
        request["message"]["token"]: request["message"]["data"]
        for request in requests
    }
    assert outbound == {
        "token-1": {
            "type": "auth_request",
            "device_id": "phone-1",
            "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        },
        "token-2": {
            "type": "auth_request",
            "device_id": "wear-2",
            "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        },
    }


def admin_request(client: TestClient, method: str, path: str, **kwargs):
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    return client.request(method, path, headers=headers, **kwargs)


def create_user(client: TestClient, username: str) -> dict:
    response = admin_request(
        client,
        "POST",
        "/api/admin/users",
        json={"username": username, "fail_mode": "closed"},
    )
    assert response.status_code == 201
    return response.json()["data"]


def create_device(client: TestClient, user_id: str) -> tuple[dict, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    response = admin_request(
        client,
        "POST",
        "/api/admin/devices",
        json={"user_id": user_id, "name": "test phone", "public_key": public_key},
    )
    assert response.status_code == 201
    return response.json()["data"], private_key


def create_integration(
    client: TestClient,
    client_id: str,
    principal_username: str | None = None,
    approver_username: str | None = None,
) -> dict:
    payload = {"name": client_id, "client_id": client_id, "fail_mode": "closed"}
    if principal_username:
        payload["principal_username"] = principal_username
    if approver_username:
        payload["approver_username"] = approver_username
    response = admin_request(client, "POST", "/api/admin/integrations", json=payload)
    assert response.status_code == 201
    return response.json()["data"]


def signed_post(
    client: TestClient,
    integration: dict,
    path: str,
    payload: dict,
    nonce: str,
    timestamp_offset_seconds: int = 0,
):
    body = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time() + timestamp_offset_seconds))
    signature = integration_signature(
        integration["secret"], "POST", path, body, timestamp, nonce
    )
    return client.post(
        path,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
        },
    )


def signed_get(client: TestClient, integration: dict, path: str, nonce: str):
    timestamp = str(int(time.time()))
    signature = integration_signature(
        integration["secret"], "GET", path, b"", timestamp, nonce
    )
    return client.get(
        path,
        headers={
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
        },
    )


def signed_empty_post(client: TestClient, integration: dict, path: str, nonce: str):
    timestamp = str(int(time.time()))
    signature = integration_signature(
        integration["secret"], "POST", path, b"", timestamp, nonce
    )
    return client.post(
        path,
        content=b"",
        headers={
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
        },
    )


def consume_auth(
    client: TestClient,
    integration: dict,
    request_id: str,
    nonce: str,
):
    return signed_empty_post(
        client,
        integration,
        f"/api/v1/auth/requests/{request_id}/consume",
        nonce,
    )


def start_auth(
    client: TestClient,
    integration: dict,
    username: str,
    nonce: str,
    signed_timestamp_offset_seconds: int = 0,
    **extra: object,
):
    payload = {
        "username": username,
        "system": "test-host",
        "pam_service": "ssh",
        **extra,
    }
    return signed_post(
        client,
        integration,
        "/api/v1/auth/requests",
        payload,
        nonce,
        signed_timestamp_offset_seconds,
    )


def preflight(client: TestClient, integration: dict, username: str, nonce: str):
    return signed_post(
        client,
        integration,
        "/api/v1/auth/preflight",
        {"username": username, "system": "test-host"},
        nonce,
    )


def decide(
    client: TestClient,
    request_id: str,
    device_id: str,
    private_key: Ed25519PrivateKey,
):
    signature = base64.b64encode(
        private_key.sign(f"{request_id}.approve.false".encode())
    ).decode()
    return client.post(
        f"/api/v1/auth/requests/{request_id}/decision",
        json={
            "device_id": device_id,
            "decision": "approve",
            "signature": signature,
            "biometric_verified": False,
        },
    )


def signed_ws_path(device_id: str, private_key: Ed25519PrivateKey, nonce: str) -> str:
    timestamp = str(int(time.time()))
    signature = base64.b64encode(
        private_key.sign(f"ws.{device_id}.{timestamp}.{nonce}".encode())
    ).decode()
    return f"/api/v1/devices/{device_id}/ws?{urlencode({'timestamp': timestamp, 'nonce': nonce, 'signature': signature})}"


def wait_for_push_count(
    provider: RecordingPushProvider,
    device_id: str,
    count: int,
    timeout_seconds: float = 4.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        payloads = provider.payloads_for(device_id)
        if len(payloads) >= count:
            return payloads
        time.sleep(0.02)
    return provider.payloads_for(device_id)


def test_bound_approver_lockout_preserves_normal_approval_flows(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'bound-approver.db'}",
            bootstrap_token=ADMIN_TOKEN,
        )
    )
    with TestClient(app) as client:
        self_user = create_user(client, "self-user")
        self_device, self_key = create_device(client, self_user["id"])
        self_integration = create_integration(client, "self-integration")

        self_request = start_auth(
            client, self_integration, self_user["username"], "self-request"
        )
        assert self_request.status_code == 201
        self_request_id = self_request.json()["data"]["id"]
        assert self_request.json()["data"]["status"] == "pending"
        self_decision = decide(client, self_request_id, self_device["id"], self_key)
        assert self_decision.status_code == 200
        assert self_decision.json()["data"]["status"] == "approved"

        principal = create_user(client, "principal")
        approver = create_user(client, "approver")
        approver_device, approver_key = create_device(client, approver["id"])
        bound_integration = create_integration(
            client,
            "bound-integration",
            principal_username=principal["username"],
            approver_username=approver["username"],
        )

        normal_request = start_auth(
            client, bound_integration, principal["username"], "normal-bound-request"
        )
        assert normal_request.status_code == 201
        normal_request_id = normal_request.json()["data"]["id"]
        assert normal_request.json()["data"]["status"] == "pending"
        normal_decision = decide(
            client, normal_request_id, approver_device["id"], approver_key
        )
        assert normal_decision.status_code == 200
        assert normal_decision.json()["data"]["status"] == "approved"

        pending_request = start_auth(
            client, bound_integration, principal["username"], "pending-before-lock"
        )
        assert pending_request.status_code == 201
        pending_request_id = pending_request.json()["data"]["id"]
        assert pending_request.json()["data"]["status"] == "pending"

        locked = admin_request(
            client, "POST", f"/api/admin/users/{approver['id']}/lockout"
        )
        assert locked.status_code == 200

        locked_preflight = preflight(
            client, bound_integration, principal["username"], "preflight-after-lock"
        )
        assert locked_preflight.status_code == 200
        assert locked_preflight.json()["data"]["approver_locked"] is True
        assert locked_preflight.json()["data"]["active_approver_devices"] == 0

        rejected_decision = decide(
            client, pending_request_id, approver_device["id"], approver_key
        )
        assert rejected_decision.status_code == 403
        assert rejected_decision.json()["detail"]["code"] == "approver_locked"

        locked_request = start_auth(
            client, bound_integration, principal["username"], "request-after-lock"
        )
        assert locked_request.status_code == 201
        assert locked_request.json()["data"]["status"] == "denied"

        logs = admin_request(
            client, "GET", "/api/admin/auth-logs", params={"user": principal["username"]}
        )
        assert logs.status_code == 200
        assert logs.json()["data"][0]["factor"] == "approver_lockout"

        unlocked = admin_request(
            client, "DELETE", f"/api/admin/users/{approver['id']}/lockout"
        )
        assert unlocked.status_code == 200
        pending_for_principal_lock = start_auth(
            client, bound_integration, principal["username"], "pending-principal-lock"
        )
        assert pending_for_principal_lock.status_code == 201
        pending_for_principal_lock_id = pending_for_principal_lock.json()["data"]["id"]
        assert pending_for_principal_lock.json()["data"]["status"] == "pending"

        principal_locked = admin_request(
            client, "POST", f"/api/admin/users/{principal['id']}/lockout"
        )
        assert principal_locked.status_code == 200
        principal_rejected = decide(
            client,
            pending_for_principal_lock_id,
            approver_device["id"],
            approver_key,
        )
        assert principal_rejected.status_code == 403
        assert principal_rejected.json()["detail"]["code"] == "principal_locked"


def test_client_timeout_shortens_duplicate_and_blocks_late_approval(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'client-deadline.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=5,
        )
    )
    with TestClient(app) as client:
        trusted_window = admin_request(
            client,
            "PATCH",
            "/api/admin/settings/global",
            json={"trusted_session_window_seconds": 60},
        )
        assert trusted_window.status_code == 200
        user = create_user(client, "deadline-user")
        device, private_key = create_device(client, user["id"])
        integration = create_integration(
            client,
            "deadline-integration",
            principal_username=user["username"],
        )

        original = start_auth(
            client, integration, user["username"], "deadline-original", attempt_id="deadline-attempt-0001"
        )
        assert original.status_code == 201
        original_data = original.json()["data"]
        assert original_data["status"] == "pending"

        retry_started_at = datetime.now(timezone.utc)
        retry = start_auth(
            client,
            integration,
            user["username"],
            "deadline-retry",
            client_timeout_seconds=1,
            attempt_id="deadline-attempt-0001",
        )
        assert retry.status_code == 201
        retry_data = retry.json()["data"]
        assert retry_data["duplicate"] is True
        assert retry_data["id"] == original_data["id"]
        persisted_expiry = datetime.fromisoformat(retry_data["expires_at"])
        assert retry_started_at < persisted_expiry <= retry_started_at + timedelta(seconds=1.25)

        delay = max(0.0, (persisted_expiry - datetime.now(timezone.utc)).total_seconds())
        time.sleep(delay + 0.05)
        late_decision = decide(client, retry_data["id"], device["id"], private_key)
        assert late_decision.status_code == 200
        assert late_decision.json()["data"]["status"] == "timeout"

        next_request = start_auth(
            client,
            integration,
            user["username"],
            "deadline-next",
            client_timeout_seconds=1,
        )
        assert next_request.status_code == 201
        assert next_request.json()["data"]["status"] == "pending"

        unobserved = start_auth(
            client,
            integration,
            user["username"],
            "unobserved-start",
            system="unobserved-host",
            client_timeout_seconds=1,
        )
        assert unobserved.status_code == 201
        unobserved_id = unobserved.json()["data"]["id"]
        approved_but_unconsumed = decide(
            client, unobserved_id, device["id"], private_key
        )
        assert approved_but_unconsumed.status_code == 200
        assert approved_but_unconsumed.json()["data"]["status"] == "approved"
        with app.state.db.SessionLocal() as db:
            approved_decided_at = db.get(AuthRequest, unobserved_id).decided_at
        time.sleep(1.05)

        no_reuse = start_auth(
            client,
            integration,
            user["username"],
            "unobserved-next",
            system="unobserved-host",
            client_timeout_seconds=1,
        )
        assert no_reuse.status_code == 201
        assert no_reuse.json()["data"]["status"] == "pending"

        late_consume = consume_auth(
            client, integration, unobserved_id, "unobserved-late-consume"
        )
        assert late_consume.status_code == 409
        assert late_consume.json()["detail"] == {
            "code": "auth_not_consumable",
            "status": "timeout",
        }
        with app.state.db.SessionLocal() as db:
            expired = db.get(AuthRequest, unobserved_id)
            assert expired.status == "timeout"
            assert expired.decided_at == approved_decided_at


def test_sqlite_pending_recovery_and_shortened_duplicate_refresh_all_channels(
    tmp_path: Path,
) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'deadline-channels.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=5,
        )
    )
    push_provider = RecordingPushProvider()
    with TestClient(app) as client:
        app.state.push_provider = push_provider
        retry_settings = admin_request(
            client,
            "PATCH",
            "/api/admin/settings/global",
            json={"push_retry_count": 2},
        )
        assert retry_settings.status_code == 200

        user = create_user(client, "deadline-channels-user")
        websocket_device, websocket_key = create_device(client, user["id"])
        fcm_device, _ = create_device(client, user["id"])
        fcm_update = admin_request(
            client,
            "PATCH",
            f"/api/admin/devices/{fcm_device['id']}",
            json={"push_token": "fcm-only-token"},
        )
        assert fcm_update.status_code == 200
        integration = create_integration(
            client,
            "deadline-channels-integration",
            principal_username=user["username"],
        )

        original = start_auth(
            client,
            integration,
            user["username"],
            "deadline-channels-original",
            attempt_id="deadline-channels-attempt",
        )
        assert original.status_code == 201
        original_data = original.json()["data"]
        initial_pushes = wait_for_push_count(push_provider, fcm_device["id"], 1)
        assert len(initial_pushes) >= 1
        assert initial_pushes[0]["data"]["expires_at"] == original_data["expires_at"]

        with client.websocket_connect(
            signed_ws_path(websocket_device["id"], websocket_key, "deadline-channels-ws")
        ) as websocket:
            snapshot = websocket.receive_json()
            assert snapshot["type"] == "pending"
            recovered = next(
                row for row in snapshot["data"] if row["id"] == original_data["id"]
            )
            for timestamp_key in ("created_at", "requested_at", "expires_at"):
                emitted = recovered[timestamp_key]
                parsed = datetime.fromisoformat(emitted)
                assert parsed.utcoffset() == timedelta(0)
                assert emitted.endswith("+00:00")

            retry = start_auth(
                client,
                integration,
                user["username"],
                "deadline-channels-retry",
                client_timeout_seconds=4,
                attempt_id="deadline-channels-attempt",
            )
            assert retry.status_code == 201
            retry_data = retry.json()["data"]
            assert retry_data["duplicate"] is True
            assert retry_data["id"] == original_data["id"]
            assert datetime.fromisoformat(retry_data["expires_at"]).utcoffset() == timedelta(0)
            assert retry_data["expires_at"] < original_data["expires_at"]

            refreshed = websocket.receive_json()
            assert refreshed["type"] == "auth_request"
            assert refreshed["data"]["id"] == original_data["id"]
            assert refreshed["data"]["expires_at"] == retry_data["expires_at"]

        deadline = time.monotonic() + 4.0
        fcm_pushes = push_provider.payloads_for(fcm_device["id"])
        while (
            sum(
                payload["data"]["expires_at"] == retry_data["expires_at"]
                for payload in fcm_pushes
            )
            < 2
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
            fcm_pushes = push_provider.payloads_for(fcm_device["id"])
        refreshed_push_indexes = [
            index
            for index, payload in enumerate(fcm_pushes)
            if payload["data"]["expires_at"] == retry_data["expires_at"]
        ]
        assert len(refreshed_push_indexes) >= 2
        assert all(
            payload["data"]["expires_at"] == retry_data["expires_at"]
            for payload in fcm_pushes[refreshed_push_indexes[0] :]
        )


def test_concurrent_duplicate_shortening_cannot_be_overwritten_by_decision(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'deadline-decision-race.db'}"
    settings = {
        "database_url": database_url,
        "bootstrap_token": ADMIN_TOKEN,
        "auth_ttl_seconds": 5,
    }
    app_a = create_app(Settings(**settings))
    app_b = create_app(Settings(**settings))
    with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
        user = create_user(client_a, "deadline-race-user")
        device, private_key = create_device(client_a, user["id"])
        integration = create_integration(
            client_a,
            "deadline-race-integration",
            principal_username=user["username"],
        )
        same_request_races = 0

        for index in range(12):
            system = f"deadline-race-{index}"
            original = start_auth(
                client_a,
                integration,
                user["username"],
                f"deadline-race-original-{index}",
                system=system,
                attempt_id=f"deadline-race-attempt-{index:04}",
            )
            assert original.status_code == 201
            request_id = original.json()["data"]["id"]
            barrier = threading.Barrier(2)

            def shorten() -> object:
                barrier.wait(timeout=5)
                return start_auth(
                    client_b,
                    integration,
                    user["username"],
                    f"deadline-race-retry-{index}",
                    system=system,
                    client_timeout_seconds=0.000001,
                    attempt_id=f"deadline-race-attempt-{index:04}",
                )

            def approve() -> object:
                barrier.wait(timeout=5)
                time.sleep(0.005)
                return decide(client_a, request_id, device["id"], private_key)

            with ThreadPoolExecutor(max_workers=2) as pool:
                retry_future = pool.submit(shorten)
                decision_future = pool.submit(approve)
                retry = retry_future.result()
                decision = decision_future.result()

            assert retry.status_code == 201
            assert decision.status_code == 200
            if retry.json()["data"]["id"] == request_id:
                same_request_races += 1
                assert decision.json()["data"]["status"] == "timeout"

        assert same_request_races > 0


def test_consumed_push_totp_and_backup_approvals_seed_trusted_sessions(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'consume-trusted.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=5,
        )
    )
    with TestClient(app) as client:
        trusted_window = admin_request(
            client,
            "PATCH",
            "/api/admin/settings/global",
            json={"trusted_session_window_seconds": 60},
        )
        assert trusted_window.status_code == 200
        user = create_user(client, "consume-user")
        device, private_key = create_device(client, user["id"])
        integration = create_integration(
            client,
            "consume-integration",
            principal_username=user["username"],
        )
        foreign_integration = create_integration(client, "consume-foreign")

        push = start_auth(
            client,
            integration,
            user["username"],
            "consume-push-start",
            system="consume-push-host",
            client_timeout_seconds=4,
        )
        push_id = push.json()["data"]["id"]
        pending_consume = consume_auth(
            client, integration, push_id, "consume-push-pending"
        )
        assert pending_consume.status_code == 409
        assert pending_consume.json()["detail"]["status"] == "pending"
        push_decision = decide(client, push_id, device["id"], private_key)
        assert push_decision.status_code == 200
        assert push_decision.json()["data"]["status"] == "approved"

        consumed_push = consume_auth(client, integration, push_id, "consume-push")
        assert consumed_push.status_code == 200
        consumed_data = consumed_push.json()["data"]
        assert consumed_data["consumed"] is True
        first_consumed_at = consumed_data["consumed_at"]
        assert datetime.fromisoformat(first_consumed_at).utcoffset() == timedelta(0)
        repeated = consume_auth(client, integration, push_id, "consume-push-repeat")
        assert repeated.status_code == 409
        assert repeated.json()["detail"] == {"code": "auth_not_consumable", "status": "approved"}
        foreign = consume_auth(
            client, foreign_integration, push_id, "consume-push-foreign"
        )
        assert foreign.status_code == 404

        push_reuse = start_auth(
            client,
            integration,
            user["username"],
            "consume-push-reuse",
            system="consume-push-host",
            client_timeout_seconds=4,
        )
        assert push_reuse.status_code == 201
        assert push_reuse.json()["data"]["status"] == "approved"

        totp_response = admin_request(
            client, "POST", f"/api/admin/users/{user['id']}/totp"
        )
        assert totp_response.status_code == 200
        totp_code = pyotp.TOTP(totp_response.json()["data"]["secret"]).now()
        totp = start_auth(
            client,
            integration,
            user["username"],
            "consume-totp-start",
            system="consume-totp-host",
            offline_code=totp_code,
            client_timeout_seconds=4,
        )
        assert totp.json()["data"]["status"] == "approved"
        assert consume_auth(
            client, integration, totp.json()["data"]["id"], "consume-totp"
        ).status_code == 200
        totp_reuse = start_auth(
            client,
            integration,
            user["username"],
            "consume-totp-reuse",
            system="consume-totp-host",
            client_timeout_seconds=4,
        )
        assert totp_reuse.json()["data"]["status"] == "approved"

        backup_response = admin_request(
            client,
            "POST",
            f"/api/admin/users/{user['id']}/backup-codes",
            params={"count": 1},
        )
        assert backup_response.status_code == 200
        backup_code = backup_response.json()["data"]["codes"][0]
        backup = start_auth(
            client,
            integration,
            user["username"],
            "consume-backup-start",
            system="consume-backup-host",
            offline_code=backup_code,
            client_timeout_seconds=4,
        )
        assert backup.json()["data"]["status"] == "approved"
        assert consume_auth(
            client, integration, backup.json()["data"]["id"], "consume-backup"
        ).status_code == 200
        backup_reuse = start_auth(
            client,
            integration,
            user["username"],
            "consume-backup-reuse",
            system="consume-backup-host",
            client_timeout_seconds=4,
        )
        assert backup_reuse.json()["data"]["status"] == "approved"

        logs = admin_request(
            client,
            "GET",
            "/api/admin/auth-logs",
            params={"user": user["username"], "limit": 100},
        )
        assert logs.status_code == 200
        trusted_systems = {
            row["system"]
            for row in logs.json()["data"]
            if row["factor"] == "trusted_session" and row["status"] == "approved"
        }
        assert {
            "consume-push-host",
            "consume-totp-host",
            "consume-backup-host",
        }.issubset(trusted_systems)


def test_client_timeout_validation_clock_skew_and_server_ttl_cap(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'client-deadline-validation.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=5,
        )
    )
    with TestClient(app) as client:
        user = create_user(client, "deadline-validation")
        integration = create_integration(
            client,
            "deadline-validation",
            principal_username=user["username"],
        )
        invalid_values = (0, -1, 601, True, "1", float("inf"))
        for index, value in enumerate(invalid_values):
            response = start_auth(
                client,
                integration,
                user["username"],
                f"invalid-deadline-{index}",
                system=f"invalid-host-{index}",
                client_timeout_seconds=value,
            )
            assert response.status_code == 422
            assert response.json()["detail"]["code"] == "invalid_client_timeout"

        absolute_deadline = start_auth(
            client,
            integration,
            user["username"],
            "absolute-deadline-rejected",
            system="absolute-deadline-host",
            client_expires_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
        )
        assert absolute_deadline.status_code == 422
        assert absolute_deadline.json()["detail"]["code"] == "invalid_client_timeout"

        for offset in (-25, 25):
            received_at = datetime.now(timezone.utc)
            skewed = start_auth(
                client,
                integration,
                user["username"],
                f"skewed-timeout-{offset}",
                signed_timestamp_offset_seconds=offset,
                system=f"skewed-host-{offset}",
                client_timeout_seconds=1,
            )
            assert skewed.status_code == 201
            skewed_expiry = datetime.fromisoformat(skewed.json()["data"]["expires_at"])
            assert received_at < skewed_expiry <= received_at + timedelta(seconds=1.25)

        before = datetime.now(timezone.utc)
        capped = start_auth(
            client,
            integration,
            user["username"],
            "capped-deadline",
            system="capped-host",
            client_timeout_seconds=60,
        )
        assert capped.status_code == 201
        expires_at = datetime.fromisoformat(capped.json()["data"]["expires_at"])
        assert before < expires_at <= before + timedelta(seconds=5.5)


def test_sensitive_auth_responses_and_device_audits_do_not_leak_secrets(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'secret-redaction.db'}",
            bootstrap_token=ADMIN_TOKEN,
        )
    )
    syslog = RecordingSyslog()
    app.state.syslog = syslog
    with TestClient(app) as client:
        user = create_user(client, "secret-user")
        device, _private_key = create_device(client, user["id"])
        integration = create_integration(
            client,
            "secret-integration",
            principal_username=user["username"],
        )

        blank_create = admin_request(
            client,
            "POST",
            "/api/admin/devices",
            json={"user_id": user["id"], "name": "blank key", "public_key": ""},
        )
        assert blank_create.status_code == 422
        blank_patch = admin_request(
            client,
            "PATCH",
            f"/api/admin/devices/{device['id']}",
            json={"public_key": ""},
        )
        assert blank_patch.status_code == 422

        raw_push_token = "private-fcm-registration-token"
        patched = admin_request(
            client,
            "PATCH",
            f"/api/admin/devices/{device['id']}",
            json={"push_token": raw_push_token},
        )
        assert patched.status_code == 200
        assert raw_push_token not in patched.text

        audits = admin_request(
            client,
            "GET",
            "/api/admin/audit-logs",
            params={"action": "device.update"},
        )
        assert audits.status_code == 200
        update_detail = audits.json()["data"][0]["detail"]
        assert update_detail == {"push_token_configured": True}
        assert raw_push_token not in json.dumps(syslog.events)

        started = start_auth(client, integration, user["username"], "no-store-start")
        assert started.status_code == 201
        assert started.headers["cache-control"] == "no-store"
        request_id = started.json()["data"]["id"]
        polled = signed_get(
            client,
            integration,
            f"/api/v1/auth/requests/{request_id}",
            "no-store-poll",
        )
        assert polled.status_code == 200
        assert polled.headers["cache-control"] == "no-store"


def test_duplicate_proxy_wait_handles_sqlite_timestamp(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'proxy-duplicate.db'}",
            bootstrap_token=ADMIN_TOKEN,
        )
    )
    with TestClient(app) as client:
        user = create_user(client, "proxy-duplicate")
        integration = create_integration(client, "proxy-duplicate")
        payload = {
            "username": user["username"],
            "system": "proxy-test",
            "pam_service": "proxy",
            "wait_seconds": 0,
            "attempt_id": "proxy-attempt-0001",
        }
        first = signed_post(
            client,
            integration,
            "/api/v1/proxy/verify",
            payload,
            "proxy-duplicate-first",
        )
        second = signed_post(
            client,
            integration,
            "/api/v1/proxy/verify",
            payload,
            "proxy-duplicate-second",
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["data"]["id"] == second.json()["data"]["id"]


def test_successful_proxy_verify_is_consumed_and_survives_expiry(
    tmp_path: Path,
) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'proxy-consume.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=1,
        )
    )
    with TestClient(app) as client:
        user = create_user(client, "proxy-consume")
        integration = create_integration(client, "proxy-consume")
        totp = admin_request(client, "POST", f"/api/admin/users/{user['id']}/totp")
        assert totp.status_code == 200
        response = signed_post(
            client,
            integration,
            "/api/v1/proxy/verify",
            {
                "username": user["username"],
                "system": "proxy-consume",
                "pam_service": "proxy",
                "offline_code": pyotp.TOTP(totp.json()["data"]["secret"]).now(),
                "wait_seconds": 0,
            },
            "proxy-consume-verify",
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "approved"
        assert data["allowed"] is True

        with app.state.db.SessionLocal() as db:
            auth_req = db.get(AuthRequest, data["id"])
            consumed_at = auth_req.consumed_at
            decided_at = auth_req.decided_at
        assert consumed_at is not None

        audits = admin_request(
            client,
            "GET",
            "/api/admin/audit-logs",
            params={"action": "auth.consume", "resource_id": data["id"]},
        )
        assert audits.status_code == 200
        assert len(audits.json()["data"]) == 1

        time.sleep(1.05)
        poll = signed_get(
            client,
            integration,
            f"/api/v1/auth/requests/{data['id']}",
            "proxy-consume-poll",
        )
        assert poll.status_code == 200
        assert poll.json()["data"]["status"] == "approved"
        with app.state.db.SessionLocal() as db:
            retained = db.get(AuthRequest, data["id"])
            assert retained.status == "approved"
            assert retained.consumed_at == consumed_at
            assert retained.decided_at == decided_at


def test_proxy_long_polls_release_connections_between_checks(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'proxy-pool.db'}",
            bootstrap_token=ADMIN_TOKEN,
            auth_ttl_seconds=5,
        )
    )
    app.state.db.engine.pool._timeout = 0.2
    with TestClient(app) as client:
        user = create_user(client, "proxy-pool")
        integration = create_integration(
            client,
            "proxy-pool",
            principal_username=user["username"],
        )
        barrier = threading.Barrier(16)

        def wait(index: int):
            barrier.wait(timeout=5)
            return signed_post(
                client,
                integration,
                "/api/v1/proxy/verify",
                {
                    "username": user["username"],
                    "system": "proxy-pool",
                    "pam_service": "proxy",
                    "wait_seconds": 1,
                },
                f"proxy-pool-{index}",
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            responses = [future.result() for future in [pool.submit(wait, i) for i in range(16)]]
        assert all(response.status_code == 200 for response in responses)


def test_schema_upgrade_adds_consumed_at_to_auth_requests(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy-auth-history.db"
    created_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    decided_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with sqlite3.connect(database_path) as conn:
        conn.execute(
            """
            CREATE TABLE auth_requests (
                id VARCHAR(36) PRIMARY KEY,
                status VARCHAR(32),
                created_at DATETIME,
                decided_at DATETIME
            )
            """
        )
        conn.execute(
            "INSERT INTO auth_requests VALUES (?, ?, ?, ?)",
            ("legacy-approved", "approved", created_at, decided_at),
        )
    database = Database(f"sqlite:///{database_path}")
    database.init()
    database.engine.dispose()
    with sqlite3.connect(database_path) as conn:
        request_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(auth_requests)")
        }
        legacy_approval = conn.execute(
            "SELECT status, decided_at, consumed_at FROM auth_requests WHERE id = ?",
            ("legacy-approved",),
        ).fetchone()
    assert "consumed_at" in request_columns
    assert legacy_approval == ("approved", decided_at, decided_at)


def test_legacy_unbounded_enrollment_token_is_invalidated(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy-enrollment.db"
    old_token = "legacy-unbounded-token"
    created_at = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path) as conn:
        conn.execute(
            """
            CREATE TABLE users (
                id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(128) UNIQUE,
                display_name VARCHAR(255),
                fail_mode VARCHAR(16),
                totp_secret VARCHAR(64),
                locked BOOLEAN,
                created_at DATETIME
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE devices (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36),
                name VARCHAR(128),
                kind VARCHAR(32),
                public_key TEXT,
                push_token TEXT,
                enrollment_token_hash VARCHAR(128),
                revoked BOOLEAN,
                require_biometric BOOLEAN,
                created_at DATETIME,
                enrolled_at DATETIME
            )
            """
        )
        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy-user", "legacy-user", None, "closed", None, 0, created_at),
        )
        conn.execute(
            "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-device",
                "legacy-user",
                "Legacy phone",
                "phone",
                None,
                None,
                hash_value(old_token),
                0,
                0,
                created_at,
                None,
            ),
        )

    database = Database(f"sqlite:///{database_path}")
    database.init()
    database.engine.dispose()
    with sqlite3.connect(database_path) as conn:
        migrated = conn.execute(
            "SELECT enrollment_token_hash, enrollment_expires_at FROM devices WHERE id = ?",
            ("legacy-device",),
        ).fetchone()
    assert migrated == (None, None)

    app = create_app(
        Settings(database_url=f"sqlite:///{database_path}", bootstrap_token=ADMIN_TOKEN)
    )
    with TestClient(app) as client:
        _private_key, public_key = create_device_keypair()
        rejected = client.post(
            "/api/v1/devices/legacy-device/enroll",
            json={"enrollment_token": old_token, "public_key": public_key},
        )
        assert rejected.status_code == 403
        assert rejected.json()["detail"]["code"] == "bad_enrollment_token"

        rotated = admin_request(
            client, "POST", "/api/admin/devices/legacy-device/rotation"
        )
        assert rotated.status_code == 200
        replacement_token = json.loads(
            rotated.json()["data"]["enrollment_qr_payload"]
        )["enrollment_token"]
        enrolled = client.post(
            "/api/v1/devices/legacy-device/enroll",
            json={"enrollment_token": replacement_token, "public_key": public_key},
        )
        assert enrolled.status_code == 200


def create_device_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    return private_key, public_key
