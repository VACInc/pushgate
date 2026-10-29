from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import threading
import time
import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pyotp
import pytest
import uvicorn
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from pam.pushgate_pam import AuthConfig, authenticate, preflight, read_cache, write_cache
from sdk.pushgate import PushGateAdminClient
from sdk.examples.admin_automation import run as automation_run
from server.app.config import Settings
from server.app.db import AppendOnlyLogViolation, Database
from server.app.ephemeral import RedisAuthState
from server.app import main as server_main
from server.app.main import create_app
from server.app.models import AuditLog, AuthLogEntry, AuthRequest, DeviceNonce, Nonce
from server.app.security import hash_value, integration_signature


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def live_server(tmp_path: Path):
    server, thread, base_url = start_live_server(Settings(database_url=f"sqlite:///{tmp_path / 'pushgate.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8))
    yield base_url
    server.should_exit = True
    thread.join(timeout=5)


def start_live_server(settings: Settings):
    return start_app_server(create_app(settings))


def start_app_server(app):
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            if httpx.get(f"{base_url}/healthz", timeout=0.2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    else:
        raise RuntimeError("server did not start")
    return server, thread, base_url


class RecordingPushProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[list[dict], dict]] = []

    async def notify_auth_request(self, devices, payload):
        self.calls.append((list(devices), payload))
        return {"sent": len(self.calls[-1][0])}


class FailingPushProvider:
    async def notify_auth_request(self, devices, payload):
        raise RuntimeError("fcm unavailable")


class CountingPushProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[list[dict], dict]] = []

    async def notify_auth_request(self, devices, payload):
        self.calls.append((list(devices), payload))
        return {"sent": len(self.calls[-1][0])}


class RecordingAuthState:
    def __init__(self) -> None:
        self.pending: dict[str, dict] = {}
        self.deleted: list[str] = []

    def put_pending(self, request_id: str, payload: dict, ttl_seconds: int) -> None:
        self.pending[request_id] = {"payload": payload, "ttl_seconds": ttl_seconds}

    def get(self, request_id: str) -> dict | None:
        item = self.pending.get(request_id)
        return item["payload"] if item else None

    def delete(self, request_id: str) -> None:
        self.deleted.append(request_id)
        self.pending.pop(request_id, None)


class FakeRedisClient:
    def __init__(self) -> None:
        self.items: dict[str, tuple[int, str]] = {}
        self.deleted: list[str] = []

    def setex(self, key: str, ttl: int, value: str) -> None:
        self.items[key] = (ttl, value)

    def get(self, key: str) -> str | None:
        item = self.items.get(key)
        return item[1] if item else None

    def delete(self, key: str) -> None:
        self.deleted.append(key)
        self.items.pop(key, None)


@pytest.fixture()
def seeded(live_server: str, tmp_path: Path):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    user = admin.create_user("alice", "Alice Operator", fail_mode="closed")
    integration = admin.create_integration("lab-linux", client_id="lab-linux", fail_mode="open", principal_username="alice")
    phone_key, phone_public = device_keypair()
    wear_key, wear_public = device_keypair()
    phone = admin.create_device(user["id"], "Pixel", "phone", require_biometric=True, public_key=phone_public)
    wear = admin.create_device(user["id"], "Pixel Watch", "wear", public_key=wear_public)
    phone["private_key"] = phone_key
    wear["private_key"] = wear_key
    cfg = AuthConfig(live_server, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)
    try:
        yield admin, user, phone, wear, cfg
    finally:
        admin.close()


def device_keypair(key_type: str = "ed25519"):
    if key_type == "ecdsa_p256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_key, base64.b64encode(public_key).decode()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, base64.b64encode(public_key).decode()


def sign_device_message(device: dict, message: str) -> str:
    body = message.encode("utf-8")
    if device.get("key_type", "ed25519") == "ecdsa_p256":
        signature = device["private_key"].sign(body, ec.ECDSA(hashes.SHA256()))
    else:
        signature = device["private_key"].sign(body)
    return base64.b64encode(signature).decode()


def signed_decision(device: dict, request_id: str, decision: str, biometric_verified: bool | None = None) -> str:
    if biometric_verified is None:
        biometric_verified = decision == "approve"
    return sign_device_message(device, f"{request_id}.{decision}.{str(biometric_verified).lower()}")


def signed_ws_url(base_url: str, device: dict, nonce: str = "ws-nonce-1", timestamp: str | None = None) -> str:
    timestamp = timestamp or str(int(time.time()))
    signature = sign_device_message(device, f"ws.{device['id']}.{timestamp}.{nonce}")
    params = urlencode({"timestamp": timestamp, "nonce": nonce, "signature": signature})
    return base_url.replace("http://", "ws://") + f"/api/v1/devices/{device['id']}/ws?{params}"


def signed_push_token_update(base_url: str, device: dict, push_token: str, nonce: str = "push-token-nonce-1", timestamp: str | None = None) -> httpx.Response:
    timestamp = timestamp or str(int(time.time()))
    signature = sign_device_message(device, f"push_token.{device['id']}.{timestamp}.{nonce}.{push_token}")
    return httpx.post(
        f"{base_url}/api/v1/devices/{device['id']}/push-token",
        json={
            "push_token": push_token,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        },
        timeout=5,
    )


def wait_pending(admin: PushGateAdminClient, service: str, user: str = "alice") -> str:
    for _ in range(40):
        terminal_ids = set()
        rows = admin.auth_logs(user=user, limit=20)
        for row in rows:
            if row["status"] != "pending":
                terminal_ids.add(row["id"])
                continue
            if row["id"] in terminal_ids:
                continue
            if row["pam_service"] == service and row["status"] == "pending":
                return row["id"]
        time.sleep(0.1)
    raise AssertionError(f"no pending {service} auth request")


def decision_response(base_url: str, request_id: str, device: dict, decision: str, biometric_verified: bool | None = None) -> httpx.Response:
    if biometric_verified is None:
        biometric_verified = decision == "approve"
    return httpx.post(
        f"{base_url}/api/v1/auth/requests/{request_id}/decision",
        json={
            "device_id": device["id"],
            "decision": decision,
            "biometric_verified": biometric_verified,
            "signature": signed_decision(device, request_id, decision, biometric_verified),
        },
        timeout=5,
    )


def decide(base_url: str, request_id: str, device: dict, decision: str, biometric_verified: bool | None = None) -> None:
    response = decision_response(base_url, request_id, device, decision, biometric_verified)
    response.raise_for_status()


def signed_integration_post(base_url: str, integration: dict, path: str, payload: dict, nonce: str, timestamp: str | None = None) -> httpx.Response:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = timestamp or str(int(time.time()))
    signature = integration_signature(integration["secret"], "POST", path, body, timestamp, nonce)
    return httpx.post(
        f"{base_url}{path}",
        content=body,
        headers={
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
        },
        timeout=5,
    )


def signed_integration_get(base_url: str, integration: dict, path: str, nonce: str, timestamp: str | None = None) -> httpx.Response:
    timestamp = timestamp or str(int(time.time()))
    signature = integration_signature(integration["secret"], "GET", path, b"", timestamp, nonce)
    return httpx.get(
        f"{base_url}{path}",
        headers={
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
        },
        timeout=5,
    )


def signed_auth_start(base_url: str, integration: dict, payload: dict, nonce: str, timestamp: str | None = None) -> httpx.Response:
    return signed_integration_post(base_url, integration, "/api/v1/auth/requests", payload, nonce, timestamp)


def run_auth_thread(cfg: AuthConfig, service: str, username: str = "alice") -> tuple[threading.Thread, dict]:
    result: dict[str, int | None] = {"code": None}

    def target() -> None:
        result["code"] = authenticate(username, pam_service=service, source_ip="10.0.0.5", system_name="labbox", cfg=cfg)

    thread = threading.Thread(target=target)
    thread.start()
    return thread, result


def test_push_gates_ssh_sudo_console_and_wear(live_server: str, seeded):
    admin, _user, phone, wear, cfg = seeded
    assert "decision_secret" not in phone
    assert phone["public_key"]

    thread, result = run_auth_thread(cfg, "ssh")
    decide(live_server, wait_pending(admin, "ssh"), phone, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0

    thread, result = run_auth_thread(cfg, "sudo")
    decide(live_server, wait_pending(admin, "sudo"), phone, "deny")
    thread.join(timeout=8)
    assert result["code"] == 1

    thread, result = run_auth_thread(cfg, "login")
    decide(live_server, wait_pending(admin, "login"), wear, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0


def test_trusted_session_window_auto_approves_same_context(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded
    admin.update_global_settings(trusted_session_window_seconds=60)

    thread, result = run_auth_thread(cfg, "ssh")
    decide(live_server, wait_pending(admin, "ssh"), phone, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0

    assert authenticate("alice", pam_service="ssh", source_ip="10.0.0.5", system_name="labbox", offline_code="bad-code", cfg=cfg) == 1

    thread, result = run_auth_thread(cfg, "ssh")
    thread.join(timeout=8)
    assert result["code"] == 0

    trusted = [row for row in admin.auth_logs(user="alice", limit=5) if row["factor"] == "trusted_session"]
    assert trusted
    assert trusted[0]["status"] == "approved"
    assert trusted[0]["system"] == "labbox"
    assert trusted[0]["source_ip"] == "10.0.0.5"


def test_trusted_session_cannot_cross_integration_boundary(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("trusted-boundary", fail_mode="closed")
        secret = admin.enroll_totp(user["id"])["secret"]
        integration_a = admin.create_integration(
            "trusted-a", client_id="trusted-a", principal_username="trusted-boundary", fail_mode="closed"
        )
        integration_b = admin.create_integration(
            "trusted-b", client_id="trusted-b", principal_username="trusted-boundary", fail_mode="closed"
        )
        admin.update_global_settings(trusted_session_window_seconds=60)
        context = {"username": "trusted-boundary", "system": "same-host", "pam_service": "ssh", "source_ip": "10.0.0.9"}
        approved = signed_auth_start(
            live_server,
            integration_a,
            {**context, "offline_code": pyotp.TOTP(secret).now()},
            nonce="trusted-boundary-a",
        )
        approved.raise_for_status()
        assert approved.json()["data"]["status"] == "approved"

        isolated = signed_auth_start(live_server, integration_b, context, nonce="trusted-boundary-b")
        isolated.raise_for_status()
        assert isolated.json()["data"]["status"] == "pending"
    finally:
        admin.close()


def test_websocket_push_fanout_delivers_auth_request(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded

    async def scenario() -> None:
        unsigned_url = live_server.replace("http://", "ws://") + f"/api/v1/devices/{phone['id']}/ws"
        with pytest.raises(Exception):
            async with websockets.connect(unsigned_url):
                pass

        ws_url = signed_ws_url(live_server, phone)
        async with websockets.connect(ws_url) as ws:
            snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert snapshot == {"type": "pending", "data": []}
            thread, result = run_auth_thread(cfg, "ssh")
            event = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert event["type"] == "auth_request"
            assert event["data"]["username"] == "alice"
            assert event["data"]["pam_service"] == "ssh"
            assert event["data"]["require_biometric"] is True
            decide(live_server, event["data"]["id"], phone, "approve")
            thread.join(timeout=8)
            assert result["code"] == 0

        with pytest.raises(Exception):
            async with websockets.connect(ws_url):
                pass

    asyncio.run(scenario())


def test_protected_principal_can_use_a_separate_human_approver(live_server: str, tmp_path: Path):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        principal = admin.create_user("serviceuser", "Automation service account", fail_mode="closed")
        approver = admin.create_user("operator", "Operator", fail_mode="open")
        integration = admin.create_integration(
            "delegated-linux",
            client_id="delegated-linux",
            fail_mode="open",
            principal_username="serviceuser",
            approver_username="operator",
            system_name="labbox",
        )

        principal_key, principal_public = device_keypair()
        principal_device = admin.create_device(principal["id"], "Wrong device", "phone", public_key=principal_public)
        principal_device["private_key"] = principal_key

        approver_key, approver_public = device_keypair()
        approver_device = admin.create_device(approver["id"], "Operator phone", "phone", public_key=approver_public)
        approver_device["private_key"] = approver_key

        unbound = admin.create_integration("unbound-linux", client_id="unbound-linux", fail_mode="closed")
        rejected_delegation = signed_auth_start(
            live_server,
            unbound,
            {"username": "serviceuser", "approver_username": "operator", "system": "labbox", "pam_service": "ssh"},
            "unbound-delegation",
        )
        assert rejected_delegation.status_code == 403
        assert rejected_delegation.json()["detail"]["code"] == "delegated_approver_not_bound"

        approver_only = admin.create_integration(
            "approver-only-linux",
            client_id="approver-only-linux",
            fail_mode="open",
            approver_username="operator",
        )
        rejected_unbound_principal = signed_auth_start(
            live_server,
            approver_only,
            {"username": "serviceuser", "approver_username": "operator", "system": "labbox", "pam_service": "ssh"},
            "approver-only-delegation",
        )
        assert rejected_unbound_principal.status_code == 403
        assert rejected_unbound_principal.json()["detail"]["code"] == "delegated_principal_binding_required"

        rejected_system = signed_auth_start(
            live_server,
            integration,
            {"username": "serviceuser", "approver_username": "operator", "system": "spoofed-host", "pam_service": "ssh"},
            "bound-wrong-system",
        )
        assert rejected_system.status_code == 403
        assert rejected_system.json()["detail"]["code"] == "system_binding_mismatch"

        preflight_response = signed_integration_post(
            live_server,
            integration,
            "/api/v1/auth/preflight",
            {"username": "serviceuser", "approver_username": "operator", "system": "labbox"},
            "delegated-preflight",
        )
        preflight_response.raise_for_status()
        preflight_data = preflight_response.json()["data"]
        assert preflight_data["principal_username"] == "serviceuser"
        assert preflight_data["approver_username"] == "operator"
        assert preflight_data["system"] == "labbox"
        assert preflight_data["fail_mode"] == "closed"
        assert preflight_data["active_approver_devices"] == 1

        cfg = AuthConfig(
            live_server,
            integration["client_id"],
            integration["secret"],
            str(tmp_path / "delegated-cache"),
            timeout=6,
            approver_username="operator",
            system_name="labbox",
        )
        assert preflight("serviceuser", cfg=cfg)["active_approver_devices"] == 1

        async def scenario() -> None:
            async with websockets.connect(signed_ws_url(live_server, approver_device, nonce="delegated-ws")) as ws:
                snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
                assert snapshot == {"type": "pending", "data": []}

                thread, result = run_auth_thread(cfg, "ssh", username="serviceuser")
                event = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
                assert event["type"] == "auth_request"
                assert event["data"]["username"] == "serviceuser"
                assert event["data"]["approver_username"] == "operator"

                rejected = decision_response(live_server, event["data"]["id"], principal_device, "approve")
                assert rejected.status_code == 403
                decide(live_server, event["data"]["id"], approver_device, "approve")
                thread.join(timeout=8)
                assert result["code"] == 0

        asyncio.run(scenario())

        cache = read_cache(cfg.cache_dir, "serviceuser")
        assert cache is not None
        assert cache["username"] == "serviceuser"
        assert cache["fail_mode"] == "closed"
        rows = admin.auth_logs(user="serviceuser", system="labbox", limit=5)
        assert rows[0]["approver_user_id"] == approver["id"]
        assert rows[0]["detail"]["approver_username"] == "operator"
    finally:
        admin.close()


def test_proxy_verify_endpoint_waits_for_device_decision(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("proxy-user", "Identity proxy User", fail_mode="closed")
        integration = admin.create_integration("proxy", client_id="proxy-flow", fail_mode="closed", system_type="proxy")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Identity proxy phone", "phone", public_key=phone_public)
        phone["private_key"] = phone_key
        payload = {
            "username": "proxy-user",
            "system": "proxy:paperless",
            "pam_service": "proxy",
            "source_ip": "10.0.0.44",
            "geolocation": "LAN",
            "wait_seconds": 5,
        }
        result: dict[str, httpx.Response] = {}

        def call_verify() -> None:
            result["response"] = signed_integration_post(live_server, integration, "/api/v1/proxy/verify", payload, nonce="proxy-verify-1")

        thread = threading.Thread(target=call_verify)
        thread.start()
        request_id = wait_pending(admin, "proxy", user="proxy-user")
        decide(live_server, request_id, phone, "approve", biometric_verified=False)
        thread.join(timeout=8)
        assert not thread.is_alive()
        assert "response" in result

        response = result["response"]
        response.raise_for_status()
        data = response.json()["data"]
        assert data["id"] == request_id
        assert data["allowed"] is True
        assert data["status"] == "approved"
        assert data["system"] == "proxy:paperless"
        assert data["pam_service"] == "proxy"
        assert data["source_ip"] == "10.0.0.44"
        assert admin.get_integration(integration["id"])["system_type"] == "proxy"

        rows = admin.auth_logs(user="proxy-user", system="proxy:paperless", result="approved")
        assert rows[0]["pam_service"] == "proxy"
    finally:
        admin.close()


def test_proxy_proxy_headers_can_authorize_admin_api(tmp_path: Path):
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'proxy-auth.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            trusted_proxy_auth_enabled=True,
            trusted_proxy_auth_secret="proxy-test-secret",
            trusted_proxy_auth_admin_groups="pushgate-admins",
        )
    )
    server, thread, base_url = start_app_server(app)
    try:
        missing = httpx.get(f"{base_url}/api/admin/settings/global", timeout=5)
        assert missing.status_code == 401

        wrong_group = httpx.get(
            f"{base_url}/api/admin/settings/global",
            headers={"X-proxy-username": "alice", "X-proxy-groups": "operators", "X-PushGate-Proxy-Secret": "proxy-test-secret"},
            timeout=5,
        )
        assert wrong_group.status_code == 403
        assert wrong_group.json()["detail"]["code"] == "proxy_group_required"

        spoofed = httpx.post(
            f"{base_url}/api/admin/users",
            headers={"X-proxy-username": "alice", "X-proxy-groups": "pushgate-admins"},
            json={"username": "spoofed-admin"},
            timeout=5,
        )
        assert spoofed.status_code == 403
        assert spoofed.json()["detail"]["code"] == "untrusted_proxy"

        response = httpx.post(
            f"{base_url}/api/admin/users",
            headers={"X-proxy-username": "alice", "X-proxy-groups": "operators,pushgate-admins", "X-PushGate-Proxy-Secret": "proxy-test-secret", "X-PushGate-CSRF": "1"},
            json={"username": "proxy-admin"},
            timeout=5,
        )
        response.raise_for_status()
        assert response.json()["data"]["username"] == "proxy-admin"

        role = httpx.post(
            f"{base_url}/api/admin/rbac/roles",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
            json={"name": "proxy-no-read", "permissions": {"read": False, "write": False, "admin": False}},
            timeout=5,
        )
        role.raise_for_status()
        app.state.settings.trusted_proxy_auth_role = "proxy-no-read"
        denied_read = httpx.get(
            f"{base_url}/api/admin/users",
            headers={"X-proxy-username": "alice", "X-proxy-groups": "pushgate-admins", "X-PushGate-Proxy-Secret": "proxy-test-secret"},
            timeout=5,
        )
        assert denied_read.status_code == 403
        assert denied_read.json()["detail"]["code"] == "insufficient_scope"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_admin_responses_are_never_cacheable(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("no-store-user", fail_mode="closed")
        totp = httpx.post(
            f"{live_server}/api/admin/users/{user['id']}/totp",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
            timeout=5,
        )
        totp.raise_for_status()
        assert totp.headers["Cache-Control"] == "no-store"
        backup = httpx.post(
            f"{live_server}/api/admin/users/{user['id']}/backup-codes",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
            timeout=5,
        )
        backup.raise_for_status()
        assert backup.headers["Cache-Control"] == "no-store"
        unauthorized = httpx.get(f"{live_server}/api/admin/users", timeout=5)
        assert unauthorized.status_code == 401
        assert unauthorized.headers["Cache-Control"] == "no-store"
    finally:
        admin.close()


def test_single_container_static_admin_web_serving(tmp_path: Path):
    static_dir = tmp_path / "admin-web"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<!doctype html><title>PushGate Admin</title><div id=\"root\"></div>", encoding="utf-8")
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'static.db'}", bootstrap_token="test-admin-token-0123456789abcdef", static_dir=str(static_dir)))
    server, thread, base_url = start_app_server(app)
    try:
        root = httpx.get(f"{base_url}/", timeout=5)
        root.raise_for_status()
        assert "PushGate Admin" in root.text
        api_404 = httpx.get(f"{base_url}/api/not-real", timeout=5)
        assert api_404.status_code == 404
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_push_provider_receives_fcm_device_targets(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'push.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8))
    provider = RecordingPushProvider()
    app.state.push_provider = provider
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("push-user", fail_mode="closed")
        integration = admin.create_integration("push-linux", client_id="push-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "FCM phone", "phone", public_key=phone_public, push_token="fcm-token-1")
        phone["private_key"] = phone_key
        cfg = AuthConfig(base_url, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)

        thread_auth, result = run_auth_thread(cfg, "ssh", username="push-user")
        deadline = time.time() + 5
        while time.time() < deadline and not provider.calls:
            time.sleep(0.05)
        assert provider.calls
        devices, event = provider.calls[0]
        assert devices[0]["id"] == phone["id"]
        assert devices[0]["push_token"] == "fcm-token-1"
        assert event["type"] == "auth_request"
        assert event["data"]["require_biometric"] is False
        decide(base_url, event["data"]["id"], phone, "approve", biometric_verified=False)
        thread_auth.join(timeout=8)
        assert result["code"] == 0

        location = signed_auth_start(
            base_url,
            integration,
            {
                "username": "push-user",
                "system": "geo-box",
                "pam_service": "sudo",
                "source_ip": "10.0.0.8",
                "geolocation": "New York, US",
            },
            nonce="push-geo-nonce-1",
        )
        location.raise_for_status()
        deadline = time.time() + 5
        while time.time() < deadline and len(provider.calls) < 2:
            time.sleep(0.05)
        assert len(provider.calls) >= 2
        _geo_devices, geo_event = provider.calls[-1]
        assert geo_event["data"]["geolocation"] == "New York, US"
        assert geo_event["data"]["requested_at"]
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_device_signed_push_token_refresh(live_server: str, seeded):
    admin, _user, phone, _wear, _cfg = seeded
    response = signed_push_token_update(live_server, phone, "fcm-token-refreshed", nonce="token-refresh-1")
    response.raise_for_status()
    assert "push_token" not in response.json()["data"]
    assert "push_token" not in admin.get_device(phone["id"])

    replay = signed_push_token_update(live_server, phone, "fcm-token-replay", nonce="token-refresh-1")
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == "replay"
    assert "push_token" not in admin.get_device(phone["id"])

    bad_signature = httpx.post(
        f"{live_server}/api/v1/devices/{phone['id']}/push-token",
        json={
            "push_token": "fcm-token-bad",
            "timestamp": str(int(time.time())),
            "nonce": "token-refresh-2",
            "signature": "bad-signature",
        },
        timeout=5,
    )
    assert bad_signature.status_code == 403
    assert bad_signature.json()["detail"]["code"] == "bad_device_signature"


def test_ecdsa_p256_device_enrollment_decision_ws_and_push_token(live_server: str, tmp_path: Path):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("ecdsa-user", fail_mode="closed")
        integration = admin.create_integration("ecdsa-linux", client_id="ecdsa-linux", fail_mode="open")
        pending = admin.create_device(user["id"], "ECDSA phone", "phone", require_biometric=False)
        assert pending["key_type"] == "ed25519"
        payload = json.loads(pending["enrollment_qr_payload"])
        private_key, public_key = device_keypair("ecdsa_p256")

        enrolled = httpx.post(
            f"{live_server}/api/v1/devices/{pending['id']}/enroll",
            json={
                "enrollment_token": payload["enrollment_token"],
                "public_key": public_key,
                "key_type": "ecdsa_p256",
                "push_token": "ecdsa-token-1",
            },
            timeout=5,
        )
        enrolled.raise_for_status()
        phone = enrolled.json()["data"]
        phone["private_key"] = private_key
        assert phone["key_type"] == "ecdsa_p256"
        assert phone["public_key"] == public_key
        assert admin.get_device(phone["id"])["key_type"] == "ecdsa_p256"

        cfg = AuthConfig(live_server, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)
        thread, result = run_auth_thread(cfg, "ssh", username="ecdsa-user")
        request_id = wait_pending(admin, "ssh", user="ecdsa-user")
        forged = httpx.post(
            f"{live_server}/api/v1/auth/requests/{request_id}/decision",
            json={"device_id": phone["id"], "decision": "approve", "biometric_verified": True, "signature": base64.b64encode(b"bad").decode()},
            timeout=5,
        )
        assert forged.status_code == 403
        assert forged.json()["detail"]["code"] == "bad_device_signature"

        decide(live_server, request_id, phone, "approve", biometric_verified=True)
        thread.join(timeout=8)
        assert result["code"] == 0

        async def websocket_succeeds() -> None:
            async with websockets.connect(signed_ws_url(live_server, phone, nonce="ecdsa-ws-1")) as ws:
                snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
                assert snapshot["type"] == "pending"

        asyncio.run(websocket_succeeds())

        token = signed_push_token_update(live_server, phone, "ecdsa-token-2", nonce="ecdsa-push-1")
        token.raise_for_status()
        assert "push_token" not in token.json()["data"]
        assert token.json()["data"]["key_type"] == "ecdsa_p256"
    finally:
        admin.close()


def test_ecdsa_p256_public_key_must_be_spki_for_p256(live_server: str, seeded):
    admin, user, phone, _wear, _cfg = seeded
    _valid_private, valid_public = device_keypair("ecdsa_p256")
    p384_private = ec.generate_private_key(ec.SECP384R1())
    p384_public = base64.b64encode(
        p384_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()

    created = httpx.post(
        f"{live_server}/api/admin/devices",
        headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
        json={"user_id": user["id"], "name": "bad-ecdsa-create", "kind": "phone", "key_type": "ecdsa_p256", "public_key": p384_public},
        timeout=5,
    )
    assert created.status_code == 422
    assert created.json()["detail"]["code"] == "bad_public_key"

    patched = httpx.patch(
        f"{live_server}/api/admin/devices/{phone['id']}",
        headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
        json={"key_type": "ecdsa_p256"},
        timeout=5,
    )
    assert patched.status_code == 422
    assert patched.json()["detail"]["code"] == "bad_public_key"
    assert admin.get_device(phone["id"])["key_type"] == "ed25519"

    valid = httpx.post(
        f"{live_server}/api/admin/devices",
        headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
        json={"user_id": user["id"], "name": "valid-ecdsa-create", "kind": "phone", "key_type": "ecdsa_p256", "public_key": valid_public},
        timeout=5,
    )
    valid.raise_for_status()
    valid_device = valid.json()["data"]
    assert valid_device["key_type"] == "ecdsa_p256"
    assert valid_device["public_key"] == valid_public

    next_private, next_public = device_keypair("ecdsa_p256")
    assert next_private is not None
    updated = admin.update_device(valid_device["id"], public_key=next_public)
    assert updated["key_type"] == "ecdsa_p256"
    assert updated["public_key"] == next_public

    pending = admin.create_device(user["id"], "bad-ecdsa-enroll", "phone")
    payload = json.loads(pending["enrollment_qr_payload"])
    enrolled = httpx.post(
        f"{live_server}/api/v1/devices/{pending['id']}/enroll",
        json={"enrollment_token": payload["enrollment_token"], "key_type": "ecdsa_p256", "public_key": p384_public},
        timeout=5,
    )
    assert enrolled.status_code == 422
    assert enrolled.json()["detail"]["code"] == "bad_public_key"
    assert admin.get_device(pending["id"])["public_key"] is None


def test_stale_replay_nonces_are_pruned_and_fresh_replays_still_fail(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'nonce-prune.db'}", bootstrap_token="test-admin-token-0123456789abcdef", hmac_window_seconds=30, auth_ttl_seconds=8))
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("nonce-user", fail_mode="closed")
        integration = admin.create_integration("nonce-linux", client_id="nonce-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Nonce phone", "phone", public_key=phone_public)
        phone["private_key"] = phone_key
        stale_at = (datetime.now(timezone.utc) - timedelta(seconds=120)).replace(tzinfo=None)
        with app.state.db.SessionLocal() as db:
            db.add(Nonce(integration_id=integration["id"], nonce="stale-integration-nonce", created_at=stale_at))
            db.add(DeviceNonce(device_id=phone["id"], nonce="stale-device-nonce", created_at=stale_at))
            retained_at = (datetime.now(timezone.utc) - timedelta(seconds=45)).replace(tzinfo=None)
            db.add(Nonce(integration_id=integration["id"], nonce="future-integration-nonce", created_at=retained_at))
            db.add(DeviceNonce(device_id=phone["id"], nonce="future-device-nonce", created_at=retained_at))
            db.commit()

        payload = {"username": "nonce-user", "system": "noncebox", "pam_service": "ssh", "source_ip": "10.0.0.11"}
        auth = signed_auth_start(base_url, integration, payload, nonce="stale-integration-nonce")
        auth.raise_for_status()
        token = signed_push_token_update(base_url, phone, "nonce-token-1", nonce="stale-device-nonce")
        token.raise_for_status()

        integration_replay = signed_auth_start(base_url, integration, payload, nonce="stale-integration-nonce")
        assert integration_replay.status_code == 409
        assert integration_replay.json()["detail"]["code"] == "replay"
        device_replay = signed_push_token_update(base_url, phone, "nonce-token-2", nonce="stale-device-nonce")
        assert device_replay.status_code == 409
        assert device_replay.json()["detail"]["code"] == "replay"

        future_timestamp = str(int(time.time()) + 20)
        retained_integration = signed_auth_start(
            base_url,
            integration,
            payload,
            nonce="future-integration-nonce",
            timestamp=future_timestamp,
        )
        assert retained_integration.status_code == 409
        assert retained_integration.json()["detail"]["code"] == "replay"
        retained_device = signed_push_token_update(
            base_url,
            phone,
            "nonce-token-future",
            nonce="future-device-nonce",
            timestamp=future_timestamp,
        )
        assert retained_device.status_code == 409
        assert retained_device.json()["detail"]["code"] == "replay"
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_signed_request_clock_skew_is_enforced_for_integration_and_devices(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'clock-skew.db'}", bootstrap_token="test-admin-token-0123456789abcdef", hmac_window_seconds=30, auth_ttl_seconds=8))
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("skew-user", fail_mode="closed")
        integration = admin.create_integration("skew-linux", client_id="skew-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Skew phone", "phone", public_key=phone_public)
        phone["private_key"] = phone_key
        payload = {"username": "skew-user", "system": "skewbox", "pam_service": "ssh", "source_ip": "10.0.0.12"}
        now_ts = int(time.time())

        fresh_auth = signed_auth_start(base_url, integration, payload, nonce="skew-fresh-auth", timestamp=str(now_ts - 5))
        fresh_auth.raise_for_status()

        stale_auth = signed_auth_start(base_url, integration, payload, nonce="skew-stale-auth", timestamp=str(now_ts - 90))
        assert stale_auth.status_code == 401
        assert stale_auth.json()["detail"]["code"] == "clock_skew"

        future_auth = signed_auth_start(base_url, integration, payload, nonce="skew-future-auth", timestamp=str(now_ts + 90))
        assert future_auth.status_code == 401
        assert future_auth.json()["detail"]["code"] == "clock_skew"

        stale_token = signed_push_token_update(base_url, phone, "skew-token-stale", nonce="skew-stale-token", timestamp=str(now_ts - 90))
        assert stale_token.status_code == 401
        assert stale_token.json()["detail"]["code"] == "clock_skew"

        future_token = signed_push_token_update(base_url, phone, "skew-token-future", nonce="skew-future-token", timestamp=str(now_ts + 90))
        assert future_token.status_code == 401
        assert future_token.json()["detail"]["code"] == "clock_skew"

        async def websocket_skew() -> None:
            with pytest.raises(Exception):
                async with websockets.connect(signed_ws_url(base_url, phone, nonce="skew-stale-ws", timestamp=str(now_ts - 90))):
                    pass
            async with websockets.connect(signed_ws_url(base_url, phone, nonce="skew-fresh-ws", timestamp=str(now_ts))) as ws:
                snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
                assert snapshot["type"] == "pending"

        asyncio.run(websocket_skew())
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_push_provider_failure_does_not_break_auth_start(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'push-fail.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8))
    app.state.push_provider = FailingPushProvider()
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("push-fail-user", fail_mode="closed")
        integration = admin.create_integration("push-fail-linux", client_id="push-fail-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "FCM phone", "phone", public_key=phone_public, push_token="fcm-token-1")
        phone["private_key"] = phone_key
        cfg = AuthConfig(base_url, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)
        thread_auth, result = run_auth_thread(cfg, "ssh", username="push-fail-user")
        request_id = wait_pending(admin, "ssh", user="push-fail-user")
        decide(base_url, request_id, phone, "approve")
        thread_auth.join(timeout=8)
        assert result["code"] == 0
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_push_provider_retries_configured_count_without_device_response(tmp_path: Path):
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'push-retry.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            auth_ttl_seconds=5,
            push_retry_count=2,
        )
    )
    provider = CountingPushProvider()
    app.state.push_provider = provider
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("push-retry-user", fail_mode="closed")
        integration = admin.create_integration("push-retry-linux", client_id="push-retry-linux", fail_mode="open")
        _phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Retry phone", "phone", public_key=phone_public, push_token="retry-token-1")

        response = signed_auth_start(
            base_url,
            integration,
            {
                "username": "push-retry-user",
                "system": "retrybox",
                "pam_service": "ssh",
                "source_ip": "10.0.0.7",
            },
            nonce="push-retry-nonce-1",
        )
        response.raise_for_status()

        deadline = time.time() + 6
        while time.time() < deadline and len(provider.calls) < 3:
            time.sleep(0.05)
        assert len(provider.calls) == 3
        assert all(call[0][0]["id"] == phone["id"] for call in provider.calls)
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_duplicate_auth_start_reuses_existing_pending_request(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'dedupe.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8, push_retry_count=0))
    provider = RecordingPushProvider()
    app.state.push_provider = provider
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("dedupe-user", fail_mode="closed")
        integration = admin.create_integration("dedupe-linux", client_id="dedupe-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Dedupe phone", "phone", public_key=phone_public, push_token="dedupe-token-1")
        phone["private_key"] = phone_key
        payload = {
            "username": "dedupe-user",
            "system": "dedupebox",
            "pam_service": "ssh",
            "source_ip": "10.0.0.6",
            # A retry of one login attempt carries that attempt's own ID.
            "attempt_id": "dedupe-attempt-0001",
        }

        first = signed_auth_start(base_url, integration, payload, nonce="dedupe-nonce-1")
        second = signed_auth_start(base_url, integration, payload, nonce="dedupe-nonce-2")
        first.raise_for_status()
        second.raise_for_status()
        first_data = first.json()["data"]
        second_data = second.json()["data"]
        assert second_data["id"] == first_data["id"]
        assert second_data["duplicate"] is True

        time.sleep(0.2)
        assert len(provider.calls) == 1
        logs = admin.auth_logs(user="dedupe-user", result="pending", limit=10)
        assert [row["id"] for row in logs] == [first_data["id"]]

        # A different login with identical display context never shares it.
        other_attempt = signed_auth_start(base_url, integration, {**payload, "attempt_id": "dedupe-attempt-0002"}, nonce="dedupe-nonce-3")
        no_attempt = signed_auth_start(base_url, integration, {key: value for key, value in payload.items() if key != "attempt_id"}, nonce="dedupe-nonce-4")
        other_attempt.raise_for_status()
        no_attempt.raise_for_status()
        separate_ids = {first_data["id"], other_attempt.json()["data"]["id"], no_attempt.json()["data"]["id"]}
        assert len(separate_ids) == 3
        assert "duplicate" not in other_attempt.json()["data"]
        assert "duplicate" not in no_attempt.json()["data"]
        decide(base_url, first_data["id"], phone, "approve")
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_concurrent_auth_starts_across_workers_create_one_pending_request(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'dedupe-workers.db'}"
    settings = dict(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8, push_retry_count=0)
    app_a = create_app(Settings(**settings))
    app_b = create_app(Settings(**settings))
    provider_a = RecordingPushProvider()
    provider_b = RecordingPushProvider()
    app_a.state.push_provider = provider_a
    app_b.state.push_provider = provider_b
    server_a, thread_a, base_a = start_app_server(app_a)
    server_b, thread_b, base_b = start_app_server(app_b)
    admin = PushGateAdminClient(base_a, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("dedupe-workers", fail_mode="closed")
        integration = admin.create_integration(
            "dedupe-workers",
            client_id="dedupe-workers",
            principal_username="dedupe-workers",
            fail_mode="closed",
        )
        _key, public_key = device_keypair()
        admin.create_device(user["id"], "Worker phone", "phone", public_key=public_key, push_token="worker-token")
        admin.global_settings()
        payload = {"username": "dedupe-workers", "system": "worker-host", "pam_service": "ssh", "source_ip": "10.0.0.20", "attempt_id": "worker-attempt-0001"}
        barrier = threading.Barrier(2)

        def start(base_url: str, nonce: str) -> httpx.Response:
            barrier.wait()
            return signed_auth_start(base_url, integration, payload, nonce)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(start, base_a, "worker-a"), pool.submit(start, base_b, "worker-b")]
            responses = [future.result() for future in futures]
        assert all(response.status_code == 201 for response in responses)
        data = [response.json()["data"] for response in responses]
        assert data[0]["id"] == data[1]["id"]
        assert sum(bool(item.get("duplicate")) for item in data) == 1
        deadline = time.time() + 5
        while time.time() < deadline and len(provider_a.calls) + len(provider_b.calls) < 1:
            time.sleep(0.05)
        assert len(provider_a.calls) + len(provider_b.calls) == 1
    finally:
        admin.close()
        server_a.should_exit = True
        server_b.should_exit = True
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)


def test_first_device_decision_wins(live_server: str, seeded):
    admin, _user, phone, wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")

    first = decision_response(live_server, request_id, phone, "approve")
    first.raise_for_status()
    assert first.json()["data"] == {"id": request_id, "status": "approved", "allowed": True}

    second = decision_response(live_server, request_id, wear, "deny")
    second.raise_for_status()
    assert second.json()["data"] == {"id": request_id, "status": "approved", "first_response_wins": True}

    thread.join(timeout=8)
    assert result["code"] == 0
    rows = admin.auth_logs(user="alice", limit=5)
    assert rows[0]["id"] == request_id
    assert rows[0]["status"] == "approved"
    assert rows[0]["approved_by_device_id"] == phone["id"]


def test_concurrent_device_decisions_have_one_terminal_winner(live_server: str, seeded):
    admin, _user, phone, wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")
    barrier = threading.Barrier(2)

    def respond(device: dict, decision: str) -> httpx.Response:
        barrier.wait()
        return decision_response(live_server, request_id, device, decision)

    with ThreadPoolExecutor(max_workers=2) as pool:
        approve = pool.submit(respond, phone, "approve")
        deny = pool.submit(respond, wear, "deny")
        responses = [approve.result(), deny.result()]

    assert all(response.status_code == 200 for response in responses)
    statuses = {response.json()["data"]["status"] for response in responses}
    assert statuses in ({"approved"}, {"denied"})
    thread.join(timeout=8)
    terminal = [row for row in admin.auth_logs(user="alice", limit=10) if row["id"] == request_id and row["status"] != "pending"]
    assert len(terminal) == 1
    assert result["code"] == (0 if terminal[0]["status"] == "approved" else 1)


def test_expiration_and_device_decision_have_one_timeout_winner(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'expiry-decision-race.db'}"
    app_a = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=60))
    app_b = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=60))
    server_a, thread_a, base_a = start_app_server(app_a)
    server_b, thread_b, base_b = start_app_server(app_b)
    admin = PushGateAdminClient(base_a, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("expiry-race", fail_mode="closed")
        integration = admin.create_integration(
            "expiry-race", client_id="expiry-race", principal_username="expiry-race", fail_mode="closed"
        )
        private_key, public_key = device_keypair()
        phone = admin.create_device(user["id"], "Expiry phone", "phone", public_key=public_key)
        phone["private_key"] = private_key
        admin.global_settings()
        started = signed_auth_start(
            base_a,
            integration,
            {"username": "expiry-race", "system": "expiry-host", "pam_service": "ssh"},
            "expiry-start",
        )
        started.raise_for_status()
        request_id = started.json()["data"]["id"]
        with app_a.state.db.SessionLocal() as db:
            auth_req = db.get(AuthRequest, request_id)
            auth_req.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).replace(tzinfo=None)
            db.commit()
        barrier = threading.Barrier(2)

        def decide_expired() -> httpx.Response:
            barrier.wait()
            return decision_response(base_a, request_id, phone, "approve")

        def poll_expired() -> httpx.Response:
            barrier.wait()
            return signed_integration_get(base_b, integration, f"/api/v1/auth/requests/{request_id}", "expiry-poll")

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = [pool.submit(decide_expired), pool.submit(poll_expired)]
            results = [future.result() for future in responses]
        assert all(response.status_code == 200 for response in results)
        assert all(response.json()["data"]["status"] == "timeout" for response in results)
        terminal = [row for row in admin.auth_logs(user="expiry-race", limit=10) if row["id"] == request_id and row["status"] == "timeout"]
        assert len(terminal) == 1
    finally:
        admin.close()
        server_a.should_exit = True
        server_b.should_exit = True
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)


def test_revoked_device_cannot_decide_pending_request(live_server: str, seeded):
    admin, _user, phone, wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")

    admin.revoke_device(phone["id"])
    rejected = decision_response(live_server, request_id, phone, "approve")
    assert rejected.status_code == 403
    assert rejected.json()["detail"]["code"] == "device_rejected"

    decide(live_server, request_id, wear, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0


def test_revoked_device_websocket_receives_no_future_auth_events(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded

    async def scenario() -> None:
        async with websockets.connect(signed_ws_url(live_server, phone, nonce="revoke-open-ws")) as ws:
            snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert snapshot["type"] == "pending"
            admin.revoke_device(phone["id"])
            integration = {"client_id": cfg.client_id, "secret": cfg.client_secret}
            started = signed_auth_start(
                live_server,
                integration,
                {"username": "alice", "system": "labbox", "pam_service": "ssh", "source_ip": "10.0.0.5"},
                nonce="revoke-event-auth",
            )
            started.raise_for_status()
            with pytest.raises(Exception):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1008

    asyncio.run(scenario())


def test_device_key_rotation_closes_existing_websocket(live_server: str, seeded):
    admin, _user, phone, _wear, _cfg = seeded

    async def scenario() -> None:
        async with websockets.connect(signed_ws_url(live_server, phone, nonce="rotation-open-ws")) as ws:
            snapshot = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert snapshot["type"] == "pending"
            admin.rotate_device_key(phone["id"])
            with pytest.raises(Exception):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1008

    asyncio.run(scenario())


def test_fail_mode_precedence_user_over_integration_over_global(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("precedence-user")
        integration = admin.create_integration("precedence-linux", client_id="precedence-linux")
        admin.update_global_settings(global_fail_mode="open")
        integration_policy = admin.create_policy("precedence-integration", "integration", integration["id"], fail_mode="closed")

        response = signed_auth_start(
            live_server,
            integration,
            {"username": "precedence-user", "system": "labbox", "pam_service": "ssh"},
            nonce="precedence-nonce-1",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "closed"

        admin.set_user_fail_mode(user["id"], "open")
        response = signed_auth_start(
            live_server,
            integration,
            {"username": "precedence-user", "system": "labbox", "pam_service": "sudo"},
            nonce="precedence-nonce-2",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "open"

        user_policy = admin.create_policy("precedence-user", "user", user["id"], fail_mode="closed")
        response = signed_auth_start(
            live_server,
            integration,
            {"username": "precedence-user", "system": "labbox", "pam_service": "login"},
            nonce="precedence-nonce-3",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "closed"

        admin.delete_policy(user_policy["id"])
        admin.delete_policy(integration_policy["id"])
    finally:
        admin.close()


def test_auth_and_audit_log_rows_are_append_only(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'append-only.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8))
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("append-user", fail_mode="closed")
        integration = admin.create_integration("append-linux", client_id="append-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "Append phone", "phone", public_key=phone_public)
        phone["private_key"] = phone_key
        cfg = AuthConfig(base_url, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)

        thread_auth, result = run_auth_thread(cfg, "ssh", username="append-user")
        request_id = wait_pending(admin, "ssh", user="append-user")
        decide(base_url, request_id, phone, "approve", biometric_verified=False)
        thread_auth.join(timeout=8)
        assert result["code"] == 0

        rows = admin.auth_logs(user="append-user", limit=5)
        assert rows[0]["id"] == request_id
        assert rows[0]["log_id"] != request_id
        assert [row["status"] for row in rows[:2]] == ["approved", "pending"]

        with app.state.db.SessionLocal() as db:
            auth_log = db.scalar(select(AuthLogEntry).where(AuthLogEntry.auth_request_id == request_id, AuthLogEntry.status == "approved"))
            assert auth_log is not None
            auth_log.status = "denied"
            with pytest.raises(AppendOnlyLogViolation):
                db.commit()
            db.rollback()

        with app.state.db.SessionLocal() as db:
            audit_log = db.scalar(select(AuditLog).where(AuditLog.action == "auth.decision", AuditLog.resource_id == request_id))
            assert audit_log is not None
            audit_log.action = "tampered"
            with pytest.raises(AppendOnlyLogViolation):
                db.commit()
            db.rollback()

        with app.state.db.SessionLocal() as db:
            auth_log = db.scalar(select(AuthLogEntry).where(AuthLogEntry.auth_request_id == request_id, AuthLogEntry.status == "approved"))
            assert auth_log is not None
            db.delete(auth_log)
            with pytest.raises(AppendOnlyLogViolation):
                db.commit()

        with pytest.raises(DBAPIError):
            with app.state.db.engine.begin() as conn:
                conn.exec_driver_sql("UPDATE auth_log_entries SET status = 'denied' WHERE auth_request_id = ?", (request_id,))

        with pytest.raises(DBAPIError):
            with app.state.db.engine.begin() as conn:
                conn.exec_driver_sql("DELETE FROM auth_log_entries WHERE auth_request_id = ?", (request_id,))

        with pytest.raises(DBAPIError):
            with app.state.db.engine.begin() as conn:
                conn.exec_driver_sql("UPDATE audit_logs SET action = 'tampered' WHERE resource_id = ?", (request_id,))
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_ephemeral_auth_state_tracks_pending_and_final_decisions(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'state.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=8))
    recorder = RecordingAuthState()
    app.state.auth_state = recorder
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("state-user", fail_mode="closed")
        integration = admin.create_integration("state-linux", client_id="state-linux", fail_mode="open")
        phone_key, phone_public = device_keypair()
        phone = admin.create_device(user["id"], "State phone", "phone", public_key=phone_public)
        phone["private_key"] = phone_key
        cfg = AuthConfig(base_url, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=6)

        thread_auth, result = run_auth_thread(cfg, "ssh", username="state-user")
        request_id = wait_pending(admin, "ssh", user="state-user")
        assert recorder.get(request_id)["status"] == "pending"
        assert recorder.pending[request_id]["ttl_seconds"] > 0
        decide(base_url, request_id, phone, "approve")
        thread_auth.join(timeout=8)
        assert result["code"] == 0
        assert request_id in recorder.deleted
        assert recorder.get(request_id) is None
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_no_response_auth_request_expires_without_polling(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'timeout.db'}", bootstrap_token="test-admin-token-0123456789abcdef", auth_ttl_seconds=1))
    recorder = RecordingAuthState()
    app.state.auth_state = recorder
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        admin.create_user("timeout-user", fail_mode="closed")
        integration = admin.create_integration("timeout-linux", client_id="timeout-linux", fail_mode="open")
        response = signed_auth_start(
            base_url,
            integration,
            {
                "username": "timeout-user",
                "system": "timeoutbox",
                "pam_service": "ssh",
                "source_ip": "10.0.0.9",
            },
            nonce="timeout-nonce-1",
        )
        response.raise_for_status()
        request_id = response.json()["data"]["id"]
        assert recorder.get(request_id)["status"] == "pending"

        deadline = time.time() + 5
        while time.time() < deadline and request_id not in recorder.deleted:
            time.sleep(0.1)
        assert request_id in recorder.deleted

        rows = admin.auth_logs(user="timeout-user", limit=5)
        assert rows[0]["id"] == request_id
        assert rows[0]["status"] == "timeout"
        assert rows[0]["decided_at"]
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_redis_auth_state_uses_ttl_keys_and_delete():
    fake = FakeRedisClient()
    state = RedisAuthState("redis://unused", client=fake)
    state.put_pending("request-1", {"status": "pending"}, 12)

    key = "pushgate:auth:request-1"
    assert fake.items[key][0] == 12
    assert state.get("request-1") == {"status": "pending"}
    state.delete("request-1")
    assert fake.deleted == [key]
    assert state.get("request-1") is None


def test_device_decision_rejects_forged_signature(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")
    response = httpx.post(
        f"{live_server}/api/v1/auth/requests/{request_id}/decision",
        json={"device_id": phone["id"], "decision": "approve", "signature": base64.b64encode(b"bad").decode()},
        timeout=5,
    )
    assert response.status_code == 403
    decide(live_server, request_id, phone, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0


def test_biometric_required_approval_rejects_unsigned_assertion(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")

    response = httpx.post(
        f"{live_server}/api/v1/auth/requests/{request_id}/decision",
        json={
            "device_id": phone["id"],
            "decision": "approve",
            "biometric_verified": False,
            "signature": signed_decision(phone, request_id, "approve", biometric_verified=False),
        },
        timeout=5,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "biometric_required"

    decide(live_server, request_id, phone, "approve", biometric_verified=True)
    thread.join(timeout=8)
    assert result["code"] == 0


def test_pending_device_enrollment_flow(live_server: str, seeded):
    admin, user, _phone, _wear, _cfg = seeded
    device = admin.create_device(user["id"], "Spare phone", "phone")
    assert admin.get_device(device["id"])["name"] == "Spare phone"
    assert admin.get_device(device["id"])["key_type"] == "ed25519"
    payload = json.loads(device["enrollment_qr_payload"])
    _private_key, public_key = device_keypair()
    enrolled = httpx.post(
        f"{live_server}/api/v1/devices/{device['id']}/enroll",
        json={"enrollment_token": payload["enrollment_token"], "public_key": public_key, "push_token": "fcm-enrolled-token"},
        timeout=5,
    )
    enrolled.raise_for_status()
    data = enrolled.json()["data"]
    assert data["public_key"] == public_key
    assert data["key_type"] == "ed25519"
    assert "push_token" not in data
    assert "enrollment_token_hash" not in data


def test_device_enrollment_token_expires(tmp_path: Path):
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'enrollment-expiry.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            enrollment_token_ttl_seconds=1,
        )
    )
    server, thread, base_url = start_app_server(app)
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("enrollment-expiry", fail_mode="closed")
        device = admin.create_device(user["id"], "Expiring phone", "phone")
        payload = json.loads(device["enrollment_qr_payload"])
        _private_key, public_key = device_keypair()
        time.sleep(1.1)
        expired = httpx.post(
            f"{base_url}/api/v1/devices/{device['id']}/enroll",
            json={"enrollment_token": payload["enrollment_token"], "public_key": public_key},
            timeout=5,
        )
        assert expired.status_code == 403
        assert expired.json()["detail"]["code"] == "enrollment_token_expired"
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)


def test_concurrent_device_enrollment_has_one_key_winner(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'enrollment-race.db'}"
    app_a = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef"))
    app_b = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef"))
    server_a, thread_a, base_a = start_app_server(app_a)
    server_b, thread_b, base_b = start_app_server(app_b)
    admin = PushGateAdminClient(base_a, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("enrollment-race", fail_mode="closed")
        device = admin.create_device(user["id"], "Racing phone", "phone")
        token = json.loads(device["enrollment_qr_payload"])["enrollment_token"]
        _private_a, public_a = device_keypair()
        _private_b, public_b = device_keypair()
        barrier = threading.Barrier(2)

        def enroll(base_url: str, public_key: str) -> httpx.Response:
            barrier.wait()
            return httpx.post(
                f"{base_url}/api/v1/devices/{device['id']}/enroll",
                json={"enrollment_token": token, "public_key": public_key},
                timeout=5,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = [
                pool.submit(enroll, base_a, public_a),
                pool.submit(enroll, base_b, public_b),
            ]
            results = [future.result() for future in responses]
        assert sorted(response.status_code for response in results) == [200, 409]
        assert admin.get_device(device["id"])["public_key"] in {public_a, public_b}
    finally:
        admin.close()
        server_a.should_exit = True
        server_b.should_exit = True
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)


def test_device_key_rotation_requires_reenrollment(live_server: str, seeded):
    admin, _user, phone, _wear, cfg = seeded
    thread, result = run_auth_thread(cfg, "ssh")
    request_id = wait_pending(admin, "ssh")

    rotated = admin.rotate_device_key(phone["id"])
    assert rotated["public_key"] is None
    response = httpx.post(
        f"{live_server}/api/v1/auth/requests/{request_id}/decision",
        json={"device_id": phone["id"], "decision": "approve", "signature": signed_decision(phone, request_id, "approve")},
        timeout=5,
    )
    assert response.status_code == 403

    payload = json.loads(rotated["enrollment_qr_payload"])
    next_private_key, next_public_key = device_keypair()
    enrolled = httpx.post(
        f"{live_server}/api/v1/devices/{phone['id']}/enroll",
        json={"enrollment_token": payload["enrollment_token"], "public_key": next_public_key},
        timeout=5,
    )
    enrolled.raise_for_status()
    phone["private_key"] = next_private_key
    decide(live_server, request_id, phone, "approve")
    thread.join(timeout=8)
    assert result["code"] == 0


def test_auth_request_poll_is_bound_to_originating_integration(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("poll-alice", "Poll Alice", fail_mode="closed")
        admin.enroll_totp(user["id"])
        codes = admin.create_backup_codes(user["id"], count=1)["codes"]
        integration_a = admin.create_integration(
            "poll-linux-a",
            client_id="poll-linux-a",
            fail_mode="open",
            principal_username="poll-alice",
        )
        integration_b = admin.create_integration("poll-linux-b", client_id="poll-linux-b", fail_mode="closed")

        start = signed_auth_start(
            live_server,
            integration_a,
            {"username": "poll-alice", "system": "labbox", "pam_service": "ssh"},
            nonce="poll-start-a",
        )
        start.raise_for_status()
        request_id = start.json()["data"]["id"]
        assert start.json()["data"]["cache"]["totp_secret"]
        assert codes

        foreign_poll = signed_integration_get(
            live_server,
            integration_b,
            f"/api/v1/auth/requests/{request_id}",
            nonce="poll-foreign-b",
        )

        assert foreign_poll.status_code == 404
        assert "totp_secret" not in foreign_poll.text
        assert "backup_code_hashes" not in foreign_poll.text

        owner_poll = signed_integration_get(
            live_server,
            integration_a,
            f"/api/v1/auth/requests/{request_id}",
            nonce="poll-owner-a",
        )
        owner_poll.raise_for_status()
        owner_data = owner_poll.json()["data"]
        assert owner_data["id"] == request_id
        assert owner_data["cache"]["totp_secret"]
        assert owner_data["cache"]["backup_code_hashes"]

        unbound = signed_auth_start(
            live_server,
            integration_b,
            {"username": "poll-alice", "system": "labbox-b", "pam_service": "ssh"},
            nonce="poll-unbound-b",
        )
        unbound.raise_for_status()
        assert "totp_secret" not in unbound.json()["data"]["cache"]
        assert "backup_code_hashes" not in unbound.json()["data"]["cache"]
    finally:
        admin.close()


def test_device_public_keys_must_be_raw_base64_ed25519(live_server: str, seeded):
    admin, user, phone, _wear, _cfg = seeded
    invalid_keys = [
        "not base64!!!",
        base64.b64encode(b"short").decode(),
        base64.b64encode(b"x" * 33).decode(),
    ]

    for index, public_key in enumerate(invalid_keys):
        created = httpx.post(
            f"{live_server}/api/admin/devices",
            headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
            json={"user_id": user["id"], "name": f"bad-create-{index}", "kind": "phone", "public_key": public_key},
            timeout=5,
        )
        assert created.status_code == 422
        assert created.json()["detail"]["code"] == "bad_public_key"

    before_key = phone["public_key"]
    patched = httpx.patch(
        f"{live_server}/api/admin/devices/{phone['id']}",
        headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"},
        json={"public_key": invalid_keys[1]},
        timeout=5,
    )
    assert patched.status_code == 422
    assert patched.json()["detail"]["code"] == "bad_public_key"
    assert admin.get_device(phone["id"])["public_key"] == before_key

    pending = admin.create_device(user["id"], "bad-enroll", "phone")
    payload = json.loads(pending["enrollment_qr_payload"])
    enrolled = httpx.post(
        f"{live_server}/api/v1/devices/{pending['id']}/enroll",
        json={"enrollment_token": payload["enrollment_token"], "public_key": invalid_keys[2]},
        timeout=5,
    )
    assert enrolled.status_code == 422
    assert enrolled.json()["detail"]["code"] == "bad_public_key"
    assert admin.get_device(pending["id"])["public_key"] is None

    _private_key, valid_public_key = device_keypair()
    retry = httpx.post(
        f"{live_server}/api/v1/devices/{pending['id']}/enroll",
        json={"enrollment_token": payload["enrollment_token"], "public_key": valid_public_key},
        timeout=5,
    )
    retry.raise_for_status()
    assert retry.json()["data"]["public_key"] == valid_public_key


def test_backup_code_admin_lifecycle(live_server: str, seeded):
    admin, user, _phone, _wear, _cfg = seeded
    created = admin.create_backup_codes(user["id"], count=2)
    assert len(created["codes"]) == 2
    listed = admin.backup_codes(user["id"])
    assert len(listed) == 2
    assert "code_hash" not in listed[0]

    admin.delete_backup_code(listed[0]["id"])
    assert len(admin.backup_codes(user["id"])) == 1
    admin.delete_backup_codes(user["id"])
    assert admin.backup_codes(user["id"]) == []


def test_totp_and_backup_codes_are_single_use_server_side(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("factor-replay", fail_mode="closed")
        totp_secret = admin.enroll_totp(user["id"])["secret"]
        backup_code = admin.create_backup_codes(user["id"], count=1)["codes"][0]
        assert len(backup_code) >= 32
        integration = admin.create_integration(
            "factor-replay",
            client_id="factor-replay",
            principal_username="factor-replay",
            fail_mode="closed",
        )
        context = {"username": "factor-replay", "system": "factor-host", "pam_service": "ssh"}
        code = pyotp.TOTP(totp_secret).now()
        first_totp = signed_auth_start(live_server, integration, {**context, "offline_code": code}, "factor-totp-1")
        replayed_totp = signed_auth_start(live_server, integration, {**context, "offline_code": code}, "factor-totp-2")
        first_totp.raise_for_status()
        replayed_totp.raise_for_status()
        first_totp_data = first_totp.json()["data"]
        assert first_totp_data["status"] == "approved"
        cached_counter = first_totp_data["cache"]["last_totp_counter"]
        assert pyotp.TOTP(totp_secret).generate_otp(cached_counter) == code
        assert replayed_totp.json()["data"]["status"] == "denied"

        barrier = threading.Barrier(2)

        def consume_backup(nonce: str) -> httpx.Response:
            barrier.wait()
            return signed_auth_start(live_server, integration, {**context, "offline_code": backup_code}, nonce)

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = [
                pool.submit(consume_backup, "factor-backup-1"),
                pool.submit(consume_backup, "factor-backup-2"),
            ]
            statuses = [future.result().json()["data"]["status"] for future in responses]
        assert sorted(statuses) == ["approved", "denied"]
    finally:
        admin.close()


def test_concurrent_totp_replay_across_workers_has_one_approval(tmp_path: Path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'totp-workers.db'}"
    app_a = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef"))
    app_b = create_app(Settings(database_url=database_url, bootstrap_token="test-admin-token-0123456789abcdef"))
    server_a, thread_a, base_a = start_app_server(app_a)
    server_b, thread_b, base_b = start_app_server(app_b)
    admin = PushGateAdminClient(base_a, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("totp-workers", fail_mode="closed")
        secret = admin.enroll_totp(user["id"])["secret"]
        integration = admin.create_integration(
            "totp-workers",
            client_id="totp-workers",
            principal_username="totp-workers",
            fail_mode="closed",
        )
        admin.global_settings()
        code = pyotp.TOTP(secret).now()
        payload = {"username": "totp-workers", "system": "totp-host", "pam_service": "ssh", "offline_code": code}
        claim_barrier = threading.Barrier(2)
        original_matching_totp_counter = server_main.matching_totp_counter

        def synchronized_matching_totp_counter(secret: str, supplied_code: str, valid_window: int = 1):
            counter = original_matching_totp_counter(secret, supplied_code, valid_window)
            if counter is not None:
                claim_barrier.wait(timeout=5)
            return counter

        monkeypatch.setattr(server_main, "matching_totp_counter", synchronized_matching_totp_counter)
        barrier = threading.Barrier(2)

        def submit(base_url: str, nonce: str) -> httpx.Response:
            barrier.wait()
            return signed_auth_start(base_url, integration, payload, nonce)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(submit, base_a, "totp-worker-a"), pool.submit(submit, base_b, "totp-worker-b")]
            responses = [future.result() for future in futures]
        assert all(response.status_code == 201 for response in responses)
        response_data = [response.json()["data"] for response in responses]
        assert sorted(item["status"] for item in response_data) == ["approved", "denied"]

        approved = next(item for item in response_data if item["status"] == "approved")
        denied = next(item for item in response_data if item["status"] == "denied")
        assert denied["cache"]["last_totp_counter"] == approved["cache"]["last_totp_counter"]

        cache_dir = tmp_path / "loser-cache"
        write_cache(cache_dir, "totp-workers", denied["cache"])
        dead = AuthConfig("http://127.0.0.1:9", "totp-workers", integration["secret"], str(cache_dir), timeout=1)
        assert authenticate("totp-workers", offline_code=code, cfg=dead) == 1
    finally:
        admin.close()
        server_a.should_exit = True
        server_b.should_exit = True
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)


def test_fail_mode_cache_during_backend_outage(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    dead = AuthConfig("http://127.0.0.1:9", "id", "secret", str(cache_dir), timeout=1)
    write_cache(cache_dir, "openuser", {"username": "openuser", "fail_mode": "open"})
    write_cache(cache_dir, "closeduser", {"username": "closeduser", "fail_mode": "closed"})

    assert authenticate("openuser", cfg=dead) == 0
    assert authenticate("closeduser", cfg=dead) == 1


def test_offline_totp_and_backup_codes_with_server_unreachable(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    secret = pyotp.random_base32()
    backup_code = "A1B2C3D4"
    write_cache(
        cache_dir,
        "alice",
        {
            "username": "alice",
            "fail_mode": "closed",
            "totp_secret": secret,
            "backup_code_hashes": [hash_value(backup_code)],
        },
    )
    dead = AuthConfig("http://127.0.0.1:9", "id", "secret", str(cache_dir), timeout=1)
    assert authenticate("alice", offline_code=pyotp.TOTP(secret).now(), cfg=dead) == 0
    assert authenticate("alice", offline_code=backup_code, cfg=dead) == 0
    assert authenticate("alice", offline_code=backup_code, cfg=dead) == 1
    cached = read_cache(cache_dir, "alice")
    assert cached is not None
    assert hash_value(backup_code) not in cached["backup_code_hashes"]
    assert hash_value(backup_code) in cached["used_backup_code_hashes"]
    assert authenticate("alice", offline_code="bad-code", cfg=dead) == 1


def test_admin_api_automation_script(live_server: str):
    result = automation_run(live_server, "test-admin-token-0123456789abcdef")
    assert result["users"] == ["alice", "bob", "carol"]
    assert result["group"] == "operators"
    assert result["group_members"] == ["alice", "bob", "carol"]
    assert result["integration"] == {"name": "lab-linux", "client_id": "lab-linux", "fail_mode": "open"}
    assert result["proxy_integration"] == {"name": "proxy", "client_id": "proxy", "system_type": "proxy", "fail_mode": "closed"}
    assert result["fail_closed_user"] == "alice"
    assert result["revoked_device"]
    assert result["revoked_device_state"] is True
    assert result["rotated_wear_has_payload"] is True
    assert result["bob_device_count"] == 1
    assert result["backup_code_count"] == 3
    assert "denials_last_24h" in result
    assert result["read_only_denials_last_24h"] == result["denials_last_24h"]
    assert "device.revoke" in result["device_audit_actions"]


def test_admin_crud_for_groups_integrations_and_api_keys(live_server: str):
    admin = PushGateAdminClient(live_server, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("crud-user", "CRUD User")

        device = admin.create_device(user["id"], "crud-phone", "phone", push_token="old-token")
        assert device["push_token_configured"] is True
        assert "push_token" not in device
        updated_device = admin.update_device(device["id"], name="crud-phone-renamed", push_token="new-token", require_biometric=True)
        assert updated_device["name"] == "crud-phone-renamed"
        assert "push_token" not in updated_device
        assert updated_device["push_token_configured"] is True
        assert updated_device["require_biometric"] is True
        cleared_device = admin.update_device(device["id"], push_token=None)
        assert "push_token" not in cleared_device
        assert cleared_device["push_token_configured"] is False
        admin.revoke_device(device["id"])
        assert admin.get_device(device["id"])["revoked"] is True
        assert admin.update_device(device["id"], revoked=False)["revoked"] is False

        group = admin.create_group("operators", "Initial")
        updated_group = admin.update_group(group["id"], name="operators-renamed", description="Updated")
        assert updated_group["name"] == "operators-renamed"
        membership = admin.add_group_user(group["id"], user["id"])
        assert membership["group_id"] == group["id"]
        assert admin.add_group_user(group["id"], user["id"])["user_id"] == user["id"]
        assert [row["username"] for row in admin.group_users(group["id"])] == ["crud-user"]
        admin.remove_group_user(group["id"], user["id"])
        assert admin.group_users(group["id"]) == []

        integration = admin.create_integration("crud-linux", client_id="crud-linux", fail_mode="open")
        assert admin.get_integration(integration["id"])["client_id"] == "crud-linux"
        patched = admin.update_integration(integration["id"], name="crud-linux-renamed", fail_mode="closed")
        assert patched["name"] == "crud-linux-renamed"
        assert patched["fail_mode"] == "closed"
        admin.delete_integration(integration["id"])
        assert admin.get_integration(integration["id"])["enabled"] is False

        policy_integration = admin.create_integration("policy-linux", client_id="policy-linux")
        global_policy = admin.create_policy("global-policy", "global", fail_mode="closed", auth_ttl_seconds=5, push_retry_count=0)
        user_policy = admin.create_policy("crud-user-policy", "user", user["id"], fail_mode="open")
        assert [row["name"] for row in admin.policies("user", user["id"])] == ["crud-user-policy"]

        response = signed_auth_start(
            live_server,
            policy_integration,
            {"username": "crud-user", "system": "policybox", "pam_service": "ssh", "source_ip": "10.0.0.10"},
            nonce="policy-nonce-1",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "open"

        assert admin.update_policy(user_policy["id"], fail_mode="closed")["fail_mode"] == "closed"
        response = signed_auth_start(
            live_server,
            policy_integration,
            {"username": "crud-user", "system": "policybox", "pam_service": "sudo", "source_ip": "10.0.0.10"},
            nonce="policy-nonce-2",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "closed"

        assert admin.update_policy(global_policy["id"], fail_mode="open")["fail_mode"] == "open"
        admin.delete_policy(user_policy["id"])
        response = signed_auth_start(
            live_server,
            policy_integration,
            {"username": "crud-user", "system": "policybox", "pam_service": "login", "source_ip": "10.0.0.10"},
            nonce="policy-nonce-3",
        )
        response.raise_for_status()
        assert response.json()["data"]["fail_mode"] == "open"
        admin.delete_policy(global_policy["id"])

        roles = admin.roles()
        assert {"read-only", "read-write", "admin"}.issubset({row["name"] for row in roles})
        role = admin.create_role("crud-auditor", {"read": True, "write": False, "admin": False}, description="Custom read-only auditor")
        assert admin.get_role(role["id"])["permissions"]["write"] is False
        custom_key = admin.create_api_key("crud-custom", "crud-auditor")
        custom = PushGateAdminClient(live_server, custom_key["token"])
        try:
            assert custom.get_group(group["id"])["name"] == "operators-renamed"
            with pytest.raises(httpx.HTTPStatusError) as exc:
                custom.create_group("custom-should-fail")
            assert exc.value.response.status_code == 403
            assert admin.update_role(role["id"], permissions={"read": True, "write": True, "admin": False})["permissions"]["write"] is True
            writable_group = custom.create_group("custom-writer")
            assert writable_group["name"] == "custom-writer"
            admin.delete_group(writable_group["id"])
        finally:
            custom.close()
        admin.delete_api_key(custom_key["id"])
        admin.delete_role(role["id"])

        api_key = admin.create_api_key("crud-robot", "read-write")
        fetched_key = admin.get_api_key(api_key["id"])
        assert fetched_key["name"] == "crud-robot"
        assert "token" not in fetched_key
        assert "token_hash" not in fetched_key
        updated_key = admin.update_api_key(api_key["id"], name="crud-reader", role="read-only")
        assert updated_key["role"] == "read-only"
        reader = PushGateAdminClient(live_server, api_key["token"])
        try:
            assert reader.get_group(group["id"])["name"] == "operators-renamed"
            with pytest.raises(httpx.HTTPStatusError) as exc:
                reader.create_group("should-fail")
            assert exc.value.response.status_code == 403
        finally:
            reader.close()
        admin.delete_api_key(api_key["id"])

        no_read_role = admin.create_role("no-read", {"read": False, "write": False, "admin": False})
        no_read_key = admin.create_api_key("no-read-key", "no-read")
        denied_read = httpx.get(
            f"{live_server}/api/admin/users",
            headers={"Authorization": f"Bearer {no_read_key['token']}"},
            timeout=5,
        )
        assert denied_read.status_code == 403
        assert denied_read.json()["detail"]["code"] == "insufficient_scope"
        admin.delete_api_key(no_read_key["id"])
        admin.delete_role(no_read_role["id"])

        audit = admin.audit_logs(resource_type="group", resource_id=group["id"], limit=10)
        assert any(row["action"] == "group.user.add" for row in audit)
        admin.delete_group(group["id"])
    finally:
        admin.close()


def test_admin_lockout_log_filters_pagination_and_headers(live_server: str, seeded):
    admin, user, _phone, _wear, cfg = seeded
    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    locked = admin.lock_user(user["id"])
    assert locked["locked"] is True

    assert authenticate("alice", pam_service="ssh", source_ip="10.0.0.8", system_name="labbox", cfg=cfg) == 1

    headers = {"Authorization": "Bearer test-admin-token-0123456789abcdef"}
    response = httpx.get(
        f"{live_server}/api/admin/auth-logs",
        params={"user": "alice", "result": "denied", "from": since.isoformat(), "limit": 1, "offset": 0},
        headers=headers,
        timeout=5,
    )
    response.raise_for_status()
    assert response.headers["X-RateLimit-Limit"] == "600"
    payload = response.json()
    assert payload["meta"] == {"limit": 1, "offset": 0, "count": 1}
    assert payload["data"][0]["status"] == "denied"
    assert payload["data"][0]["factor"] == "lockout"

    audit = admin.audit_logs(action="user.lock", resource_type="user", resource_id=user["id"], limit=5)
    assert audit and audit[0]["action"] == "user.lock"
    unlocked = admin.unlock_user(user["id"])
    assert unlocked["locked"] is False


def test_rate_limit_enforces_429_with_retry_headers(tmp_path: Path):
    server, thread, base_url = start_live_server(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'ratelimit.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            rate_limit_per_minute=2,
            rate_limit_window_seconds=60,
        )
    )
    headers = {"Authorization": "Bearer test-admin-token-0123456789abcdef"}
    try:
        first = httpx.get(f"{base_url}/api/admin/settings/global", headers=headers, timeout=5)
        second = httpx.get(f"{base_url}/api/admin/settings/global", headers=headers, timeout=5)
        limited = httpx.get(
            f"{base_url}/api/admin/settings/global",
            headers={"Authorization": "Bearer rotated-invalid", "X-PushGate-Client-Id": "rotated-client"},
            timeout=5,
        )

        assert first.status_code == 200
        assert second.status_code == 200
        assert limited.status_code == 429
        assert limited.json()["detail"]["code"] == "rate_limited"
        assert limited.headers["X-RateLimit-Limit"] == "2"
        assert limited.headers["X-RateLimit-Remaining"] == "0"
        assert int(limited.headers["Retry-After"]) > 0
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_rate_limit_uses_authenticated_proxy_client_ip_and_rejects_spoofing(tmp_path: Path):
    secret = "test-trusted-proxy-secret"
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'ratelimit-proxy.db'}",
        bootstrap_token="test-admin-token-0123456789abcdef",
        rate_limit_per_minute=1,
        rate_limit_window_seconds=60,
        trusted_proxy_auth_enabled=True,
        trusted_proxy_auth_secret=secret,
    )
    auth = {"Authorization": "Bearer test-admin-token-0123456789abcdef"}

    direct_app = create_app(settings)
    with TestClient(direct_app) as client:
        first = client.get(
            "/api/admin/settings/global",
            headers={**auth, "X-Forwarded-For": "198.51.100.10"},
        )
        spoofed = client.get(
            "/api/admin/settings/global",
            headers={
                **auth,
                "X-PushGate-Proxy-Secret": "attacker-controlled-value",
                "X-Forwarded-For": "198.51.100.11",
            },
        )
    assert first.status_code == 200
    assert spoofed.status_code == 429
    assert set(direct_app.state.rate_limits) == {"ip:testclient"}

    proxied_app = create_app(
        settings.model_copy(update={"database_url": f"sqlite:///{tmp_path / 'ratelimit-proxy-auth.db'}"})
    )
    proxy_headers = {**auth, "X-PushGate-Proxy-Secret": secret}
    with TestClient(proxied_app) as client:
        first_client = client.get(
            "/api/admin/settings/global",
            headers={**proxy_headers, "X-Forwarded-For": "198.51.100.20"},
        )
        second_client = client.get(
            "/api/admin/settings/global",
            headers={**proxy_headers, "X-Forwarded-For": "198.51.100.21"},
        )
        leftmost_spoof = client.get(
            "/api/admin/settings/global",
            headers={**proxy_headers, "X-Forwarded-For": "203.0.113.99, 198.51.100.20"},
        )
    assert first_client.status_code == 200
    assert second_client.status_code == 200
    assert leftmost_spoof.status_code == 429
    assert set(proxied_app.state.rate_limits) == {"ip:198.51.100.20", "ip:198.51.100.21"}


def test_rate_limit_bucket_storage_is_hard_bounded(tmp_path: Path):
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'ratelimit-bound.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            rate_limit_per_minute=10,
            rate_limit_window_seconds=60,
        )
    )
    future_reset = time.time() + 60
    app.state.rate_limits = {f"ip:198.51.100.{index}": (future_reset + index, 1) for index in range(1024)}
    with TestClient(app) as client:
        response = client.get("/api/admin/settings/global", headers={"Authorization": "Bearer test-admin-token-0123456789abcdef"})
        response.raise_for_status()
    assert len(app.state.rate_limits) == 1024
    assert "ip:testclient" in app.state.rate_limits


@pytest.mark.parametrize("bootstrap_token", [None, ""])
def test_security_sensitive_defaults_fail_closed(
    tmp_path: Path, bootstrap_token: str | None
):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'safe-defaults.db'}",
        bootstrap_token=bootstrap_token,
    )
    assert settings.global_fail_mode == "closed"
    app = create_app(settings)
    with TestClient(app) as client:
        rejected = client.get(
            "/api/admin/settings/global",
            headers={"Authorization": "Bearer dev-admin"},
        )
        assert rejected.status_code == 403


@pytest.mark.parametrize(
    "bootstrap_token",
    ["x", "a" * 31, "dev-admin", "change-me", "replace-me", " " + "a" * 32],
)
def test_weak_bootstrap_tokens_are_rejected_at_configuration_load(
    bootstrap_token: str,
):
    with pytest.raises(ValidationError, match="bootstrap token"):
        Settings(bootstrap_token=bootstrap_token)


def test_bootstrap_token_environment_uses_same_strength_validation(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("PUSHGATE_BOOTSTRAP_TOKEN", "too-short")
    with pytest.raises(ValidationError, match="bootstrap token"):
        Settings()

    strong_token = "pushgate-test-token-0123456789abcdef"
    monkeypatch.setenv("PUSHGATE_BOOTSTRAP_TOKEN", strong_token)
    assert Settings().bootstrap_token == strong_token


def test_invalid_security_settings_are_rejected():
    for values in (
        {"auth_ttl_seconds": 0},
        {"hmac_window_seconds": 0},
        {"global_fail_mode": "maybe"},
        {"enrollment_token_ttl_seconds": 0},
        {"rate_limit_per_minute": 0},
        {"trusted_proxy_auth_secret": "too-short"},
    ):
        with pytest.raises(ValidationError):
            Settings(**values)


def test_trusted_proxy_auth_requires_shared_secret(tmp_path: Path):
    with pytest.raises(RuntimeError, match="TRUSTED_PROXY_AUTH_SECRET"):
        create_app(
            Settings(
                database_url=f"sqlite:///{tmp_path / 'proxy-no-secret.db'}",
                bootstrap_token="test-admin-token-0123456789abcdef",
                trusted_proxy_auth_enabled=True,
                trusted_proxy_auth_secret=None,
            )
        )


def test_sqlite_database_is_owner_only_under_permissive_umask(tmp_path: Path):
    database_path = tmp_path / "secure-mode.db"
    previous_umask = os.umask(0o022)
    try:
        create_app(Settings(database_url=f"sqlite:///{database_path}", bootstrap_token="test-admin-token-0123456789abcdef"))
    finally:
        os.umask(previous_umask)
    assert database_path.stat().st_mode & 0o077 == 0


def test_sqlite_database_rejects_preexisting_symlink(tmp_path: Path):
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    link = tmp_path / "linked.db"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="symlink"):
        create_app(Settings(database_url=f"sqlite:///{link}", bootstrap_token="test-admin-token-0123456789abcdef"))


def test_sqlite_database_rejects_wrong_owner_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from server.app import db as db_module

    database_path = tmp_path / "wrong-owner.db"
    real_fstat = db_module.os.fstat

    def wrong_file_owner(fd: int):
        result = real_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            values = list(result)
            values[4] = result.st_uid + 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(db_module.os, "fstat", wrong_file_owner)
    with pytest.raises(RuntimeError, match="owned by the service user"):
        Database(f"sqlite:///{database_path}")


def test_sqlite_database_rejects_shared_writable_parent(tmp_path: Path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o707)
    try:
        with pytest.raises(RuntimeError, match="writable by non-owners"):
            Database(f"sqlite:///{shared / 'unsafe.db'}")
    finally:
        shared.chmod(0o700)


def test_sqlite_database_rejects_parent_writable_by_service_primary_group(tmp_path: Path):
    shared = tmp_path / "service-group-writable"
    shared.mkdir()
    assert shared.stat().st_gid == os.getegid()
    shared.chmod(0o770)
    try:
        with pytest.raises(RuntimeError, match="writable by non-owners"):
            Database(f"sqlite:///{shared / 'unsafe.db'}")
    finally:
        shared.chmod(0o700)


def test_sqlite_database_rejects_disk_backed_file_uri(tmp_path: Path):
    database_path = tmp_path / "uri-bypass.db"
    with pytest.raises(RuntimeError, match="Disk-backed SQLite file URIs"):
        Database(f"sqlite:///file:{database_path}?uri=true")
    assert not database_path.exists()


@pytest.mark.parametrize(
    "database_name",
    (
        "file::memory:",
        "file:pushgate-test",
    ),
)
def test_sqlite_database_allows_explicit_in_memory_file_uris(
    database_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    mode = "" if database_name == "file::memory:" else "mode=memory&"
    database_url = f"sqlite:///{database_name}?{mode}cache=shared&uri=true"
    database = Database(database_url)
    try:
        database.init()
        assert database.sqlite_path is None
    finally:
        database.engine.dispose()
    assert not any(tmp_path.iterdir())


def test_schema_compatibility_adds_security_hardening_columns(tmp_path: Path):
    database_path = tmp_path / "legacy-schema.db"
    with sqlite3.connect(database_path) as conn:
        conn.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(128))")
        conn.execute("CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36), name VARCHAR(128))")
    Database(f"sqlite:///{database_path}").init()
    with sqlite3.connect(database_path) as conn:
        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        device_columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    assert "totp_last_used_step" in user_columns
    assert {"key_type", "enrollment_expires_at"}.issubset(device_columns)


def test_cors_rejects_unconfigured_browser_origins(tmp_path: Path):
    server, thread, base_url = start_live_server(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'cors.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            cors_allow_origins="http://admin.local:5173",
            cors_allow_origin_regex=None,
        )
    )
    try:
        allowed = httpx.options(
            f"{base_url}/api/admin/settings/global",
            headers={"Origin": "http://admin.local:5173", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        assert allowed.headers["access-control-allow-origin"] == "http://admin.local:5173"

        rejected = httpx.options(
            f"{base_url}/api/admin/settings/global",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        assert "access-control-allow-origin" not in rejected.headers
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_default_cors_rejects_all_cross_origin_requests(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'cors-default.db'}", bootstrap_token="test-admin-token-0123456789abcdef"))
    with TestClient(app) as client:
        loopback = client.options(
            "/api/admin/settings/global",
            headers={"Origin": "http://localhost:9999", "Access-Control-Request-Method": "GET"},
        )
        hostile_lan = client.options(
            "/api/admin/settings/global",
            headers={"Origin": "http://192.0.2.66:8080", "Access-Control-Request-Method": "GET"},
        )
    assert "access-control-allow-origin" not in loopback.headers
    assert "access-control-allow-origin" not in hostile_lan.headers


def test_syslog_export_for_audit_and_auth(tmp_path: Path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    syslog_port = sock.getsockname()[1]
    server, thread, base_url = start_live_server(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'syslog.db'}",
            bootstrap_token="test-admin-token-0123456789abcdef",
            auth_ttl_seconds=5,
            syslog_enabled=True,
            syslog_host="127.0.0.1",
            syslog_port=syslog_port,
        )
    )
    admin = PushGateAdminClient(base_url, "test-admin-token-0123456789abcdef")
    try:
        user = admin.create_user("syslog-user", fail_mode="closed")
        integration = admin.create_integration("syslog-linux", client_id="syslog-linux", fail_mode="open")
        cfg = AuthConfig(base_url, integration["client_id"], integration["secret"], str(tmp_path / "cache"), timeout=1)
        admin.lock_user(user["id"])
        assert authenticate("syslog-user", pam_service="ssh", system_name="syslogbox", cfg=cfg) == 1

        messages: list[str] = []
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                messages.append(sock.recvfrom(4096)[0].decode("utf-8"))
            except TimeoutError:
                pass
            if any("user.lock" in item for item in messages) and any('"factor":"lockout"' in item for item in messages):
                break
        assert any("user.lock" in item for item in messages)
        assert any('"factor":"lockout"' in item for item in messages)
    finally:
        admin.close()
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
