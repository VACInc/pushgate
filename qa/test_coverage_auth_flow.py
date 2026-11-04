"""Integration HMAC (signature, nonce, expiry), auth context binding, device decisions,
single-use consumption and the device WebSocket, branch by branch."""
from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import event, insert, update
from sqlalchemy.exc import OperationalError
from starlette.websockets import WebSocketDisconnect

from server.app.config import Settings
from server.app.main import create_app
from server.app.models import AuthRequest, Device, DeviceNonce, Nonce, User
from server.app.push import FanoutDisconnected
from server.app.security import integration_signature, utcnow

ADMIN_TOKEN = "test-admin-token-0123456789abcdef"
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


class RecordingSyslog:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, event_type: str, payload: dict) -> None:
        self.events.append((event_type, payload))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.events]


class World:
    """One app, an alice/bob pair, an enrolled phone for alice and a host integration."""

    _nonce = 0

    def __init__(self, client: TestClient, app) -> None:
        self.c = client
        self.app = app
        self.alice = self.admin("POST", "/api/admin/users", json={"username": "alice"})
        self.bob = self.admin("POST", "/api/admin/users", json={"username": "bob"})
        self.key = Ed25519PrivateKey.generate()
        self.phone = self.add_device(self.alice["id"], self.key)
        self.integration = self.admin("POST", "/api/admin/integrations", json={"name": "host", "client_id": "host"})

    def admin(self, method: str, path: str, **kwargs):
        response = self.c.request(method, path, headers=ADMIN, **kwargs)
        assert response.status_code in (200, 201, 204), response.text
        return response.json()["data"] if response.content else None

    def add_device(self, user_id: str, key: Ed25519PrivateKey, **extra) -> dict:
        public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        return self.admin("POST", "/api/admin/devices", json={"user_id": user_id, "name": "phone", "public_key": public, **extra})

    def nonce(self) -> str:
        World._nonce += 1
        return f"nonce-{World._nonce:08d}"

    def signed(self, method: str, path: str, payload=None, *, integration=None, nonce=None, timestamp=None, raw: bytes | None = None,
               headers: dict | None = None):
        integration = integration or self.integration
        body = raw if raw is not None else (b"" if payload is None else json.dumps(payload).encode())
        timestamp = timestamp if timestamp is not None else str(int(time.time()))
        nonce = nonce or self.nonce()
        signature = integration_signature(integration["secret"], method, path, body, timestamp, nonce)
        sent = {
            "X-PushGate-Client-Id": integration["client_id"],
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": signature,
            "Content-Type": "application/json",
        }
        sent.update(headers or {})
        return self.c.request(method, path, content=body, headers=sent)

    def start(self, expected: int = 201, **payload):
        body = {"username": "alice", "system": "host1", "pam_service": "ssh", **payload}
        response = self.signed("POST", "/api/v1/auth/requests", body)
        assert response.status_code == expected, response.text
        return response.json()

    def decide(self, request_id: str, decision: str = "approve", *, key=None, device=None, biometric: bool = False):
        key = key or self.key
        device = device or self.phone
        signature = base64.b64encode(key.sign(f"{request_id}.{decision}.{str(biometric).lower()}".encode())).decode()
        return self.c.post(f"/api/v1/auth/requests/{request_id}/decision",
                           json={"device_id": device["id"], "decision": decision, "signature": signature, "biometric_verified": biometric})

    def consume(self, request_id: str, integration=None):
        return self.signed("POST", f"/api/v1/auth/requests/{request_id}/consume", integration=integration)

    def sql(self, statement) -> None:
        with self.app.state.db.engine.begin() as conn:
            conn.execute(statement)

    def ws_path(self, device=None, key=None, *, nonce=None, timestamp=None, signature=None, drop: str | None = None) -> str:
        device = device or self.phone
        key = key or self.key
        timestamp = timestamp if timestamp is not None else str(int(time.time()))
        nonce = nonce or self.nonce()
        signature = signature or base64.b64encode(key.sign(f"ws.{device['id']}.{timestamp}.{nonce}".encode())).decode()
        params = {"timestamp": timestamp, "nonce": nonce, "signature": signature}
        if drop:
            params.pop(drop)
        return f"/api/v1/devices/{device['id']}/ws?{urlencode(params)}"


@pytest.fixture()
def world(tmp_path: Path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'flow.db'}", bootstrap_token=ADMIN_TOKEN, ws_reconcile_seconds=0.1,
                              push_retry_count=0))
    app.state.syslog = RecordingSyslog()
    with TestClient(app, raise_server_exceptions=False) as client:
        yield World(client, app)


def code_of(response) -> str:
    return response.json()["detail"]["code"]


# --- HMAC: headers, timestamp, signature, nonce --------------------------------------------------


def test_signed_request_header_timestamp_and_signature_failures(world: World) -> None:
    path = "/api/v1/auth/requests"
    body = {"username": "alice"}
    missing = world.c.post(path, json=body, headers={"X-PushGate-Client-Id": "host"})
    assert missing.status_code == 401 and code_of(missing) == "missing_signature"
    for timestamp in ("soon", "9" * 40, "1.5"):
        response = world.signed("POST", path, body, timestamp=timestamp)
        assert response.status_code == 401 and code_of(response) == "bad_timestamp", timestamp
    for offset in (-301, 301):
        response = world.signed("POST", path, body, timestamp=str(int(time.time()) + offset))
        assert response.status_code == 401 and code_of(response) == "clock_skew"
    unknown = world.signed("POST", path, body, integration={"client_id": "nope", "secret": "x"})
    assert unknown.status_code == 403 and code_of(unknown) == "unknown_integration"
    forged = world.signed("POST", path, body, integration={"client_id": "host", "secret": "not-the-secret"})
    assert forged.status_code == 403 and code_of(forged) == "bad_signature"
    # Non-ASCII signature header text is a plain mismatch, never a 500.
    odd = world.signed("POST", path, body, headers={"X-PushGate-Signature": "café".encode()})
    assert odd.status_code == 403
    # Body, path and method are all covered by the signature.
    timestamp, nonce = str(int(time.time())), world.nonce()
    raw = json.dumps(body).encode()
    sig = integration_signature(world.integration["secret"], "POST", path, raw, timestamp, nonce)
    tampered = world.c.post(path, content=raw.replace(b"alice", b"bobby"),
                            headers={"X-PushGate-Client-Id": "host", "X-PushGate-Timestamp": timestamp, "X-PushGate-Nonce": nonce,
                                     "X-PushGate-Signature": sig})
    assert tampered.status_code == 403 and code_of(tampered) == "bad_signature"
    other_path = world.c.post("/api/v1/auth/preflight", content=raw,
                              headers={"X-PushGate-Client-Id": "host", "X-PushGate-Timestamp": timestamp, "X-PushGate-Nonce": nonce,
                                       "X-PushGate-Signature": sig})
    assert other_path.status_code == 403
    # A disabled integration is unknown.
    world.admin("DELETE", f"/api/admin/integrations/{world.integration['id']}")
    disabled = world.signed("POST", path, body)
    assert disabled.status_code == 403 and code_of(disabled) == "unknown_integration"


def test_integration_nonce_replay_is_rejected_per_integration(world: World) -> None:
    other = world.admin("POST", "/api/admin/integrations", json={"name": "other", "client_id": "other"})
    nonce = world.nonce()
    assert world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}, nonce=nonce).status_code == 200
    replay = world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}, nonce=nonce)
    assert replay.status_code == 409 and code_of(replay) == "replay"
    # Nonces are scoped to the integration that signed them.
    assert world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}, nonce=nonce, integration=other).status_code == 200


def test_body_must_be_a_json_object(world: World) -> None:
    for raw in (b"{not json", b"[1, 2]", b'"alice"'):
        response = world.signed("POST", "/api/v1/auth/requests", raw=raw)
        assert response.status_code == 422 and code_of(response) == "invalid_json", raw
    # An empty body is an empty object, which then lacks a username.
    empty = world.signed("POST", "/api/v1/auth/requests", raw=b"")
    assert empty.status_code == 422 and code_of(empty) == "username_required"


# --- auth context binding ----------------------------------------------------------------------


def test_auth_context_binding_errors(world: World) -> None:
    bound = world.admin("POST", "/api/admin/integrations", json={"name": "bound", "client_id": "bound", "principal_username": "alice",
                                                                 "approver_username": "bob", "system_name": "web01"})
    approver_only = world.admin("POST", "/api/admin/integrations", json={"name": "ao", "client_id": "ao", "approver_username": "bob"})
    ghost = world.admin("POST", "/api/admin/integrations", json={"name": "g", "client_id": "g", "principal_username": "alice",
                                                                "approver_username": "nobody"})
    cases = [
        (world.integration, {"username": ""}, 422, "username_required"),
        (world.integration, {"username": 7}, 422, "username_required"),
        (world.integration, {"username": "carol"}, 404, "unknown_user"),
        (world.integration, {"username": "alice", "approver_username": 5}, 422, "invalid_approver"),
        (world.integration, {"username": "alice", "approver_username": ""}, 422, "invalid_approver"),
        (world.integration, {"username": "alice", "approver_username": "bob"}, 403, "delegated_approver_not_bound"),
        (world.integration, {"username": "alice", "system": ""}, 422, "invalid_system"),
        (world.integration, {"username": "alice", "system": "x" * 129}, 422, "invalid_system"),
        (world.integration, {"username": "alice", "system": "a\x00b"}, 422, "invalid_system"),
        (world.integration, {"username": "alice", "system": ["x"]}, 422, "invalid_system"),
        (world.integration, {"username": "alice", "pam_service": "s" * 65}, 422, "invalid_pam_service"),
        (world.integration, {"username": "alice", "source_ip": 10}, 422, "invalid_source_ip"),
        (world.integration, {"username": "alice", "attempt_id": "short"}, 422, "invalid_attempt_id"),
        (world.integration, {"username": "alice", "attempt_id": "x" * 16 + "!"}, 422, "invalid_attempt_id"),
        (world.integration, {"username": "alice", "client_expires_at": "2030-01-01"}, 422, "invalid_client_timeout"),
        (world.integration, {"username": "alice", "client_timeout_seconds": True}, 422, "invalid_client_timeout"),
        (world.integration, {"username": "alice", "client_timeout_seconds": "5"}, 422, "invalid_client_timeout"),
        (world.integration, {"username": "alice", "client_timeout_seconds": 0}, 422, "invalid_client_timeout"),
        (world.integration, {"username": "alice", "client_timeout_seconds": 601}, 422, "invalid_client_timeout"),
        (bound, {"username": "bob"}, 403, "principal_binding_mismatch"),
        (bound, {"username": "alice", "approver_username": "alice"}, 403, "approver_binding_mismatch"),
        (bound, {"username": "alice", "system": "web02"}, 403, "system_binding_mismatch"),
        (approver_only, {"username": "alice"}, 403, "delegated_principal_binding_required"),
        (ghost, {"username": "alice"}, 404, "unknown_approver"),
    ]
    for integration, payload, status, expected in cases:
        response = world.signed("POST", "/api/v1/auth/requests", payload, integration=integration)
        assert (response.status_code, code_of(response)) == (status, expected), payload
    # Non-finite numbers are not valid JSON numbers for the server either.
    inf = world.signed("POST", "/api/v1/auth/requests", raw=b'{"username":"alice","client_timeout_seconds":Infinity}')
    assert inf.status_code == 422 and code_of(inf) == "invalid_client_timeout"

    ok = world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}, integration=bound).json()["data"]
    assert ok["approver_username"] == "bob" and ok["system"] == "web01" and ok["active_approver_devices"] == 0
    # Without a requested system, an unbound integration falls back to its own name.
    started = world.signed("POST", "/api/v1/auth/requests", {"username": "alice"}).json()["data"]
    row = world.c.get("/api/admin/auth-logs", headers=ADMIN, params={"user": "alice"}).json()["data"][0]
    assert row["id"] == started["id"] and row["system"] == "host"


def test_effective_fail_mode_precedence_branches(world: World) -> None:
    def fail_mode() -> str:
        return world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}).json()["data"]["fail_mode"]

    assert fail_mode() == "closed"  # global default
    world.admin("PATCH", "/api/admin/settings/global", json={"global_fail_mode": "open"})
    assert fail_mode() == "open"
    world.admin("PATCH", f"/api/admin/integrations/{world.integration['id']}", json={"fail_mode": "closed"})
    assert fail_mode() == "closed"
    world.admin("POST", "/api/admin/policies", json={"name": "ip", "subject_type": "integration",
                                                     "subject_id": world.integration["id"], "fail_mode": "open"})
    assert fail_mode() == "open"
    world.admin("PATCH", f"/api/admin/users/{world.alice['id']}", json={"fail_mode": "closed"})
    assert fail_mode() == "closed"
    world.admin("POST", "/api/admin/policies", json={"name": "up", "subject_type": "user", "subject_id": world.alice["id"],
                                                     "fail_mode": "open"})
    assert fail_mode() == "open"
    # Policies without a fail mode never override.
    world.admin("POST", "/api/admin/policies", json={"name": "gp", "subject_type": "global", "auth_ttl_seconds": 30})
    assert fail_mode() == "open"


def test_locked_principal_or_approver_is_denied_at_start_and_preflight(world: World) -> None:
    delegated = world.admin("POST", "/api/admin/integrations", json={"name": "d", "client_id": "d", "principal_username": "alice",
                                                                     "approver_username": "bob"})
    world.add_device(world.bob["id"], Ed25519PrivateKey.generate())
    world.admin("POST", f"/api/admin/users/{world.bob['id']}/lockout")
    pre = world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}, integration=delegated).json()["data"]
    assert pre["approver_locked"] is True and pre["active_approver_devices"] == 0
    started = world.signed("POST", "/api/v1/auth/requests", {"username": "alice"}, integration=delegated).json()["data"]
    assert (started["status"], started["allowed"]) == ("denied", False)
    world.admin("POST", f"/api/admin/users/{world.alice['id']}/lockout")
    assert world.start()["data"]["status"] == "denied"
    logs = world.c.get("/api/admin/auth-logs", headers=ADMIN, params={"result": "denied"}).json()["data"]
    assert {row["factor"] for row in logs} == {"lockout", "approver_lockout"}


def test_source_name_lookup_failure_never_blocks_a_login(world: World) -> None:
    async def broken(_source):
        raise RuntimeError("resolver exploded")

    world.app.state.source_names.display_name = broken
    data = world.start(source_ip="192.0.2.1")["data"]
    assert data["status"] == "pending"


# --- poll / consume / proxy verify -------------------------------------------------------------


def test_poll_and_consume_are_bound_to_the_originating_integration(world: World) -> None:
    other = world.admin("POST", "/api/admin/integrations", json={"name": "o", "client_id": "o"})
    request_id = world.start()["data"]["id"]
    assert world.signed("GET", f"/api/v1/auth/requests/{request_id}", integration=other).status_code == 404
    assert world.signed("GET", "/api/v1/auth/requests/missing").status_code == 404
    assert world.consume("missing").status_code == 404
    assert world.consume(request_id, integration=other).status_code == 404
    pending = world.consume(request_id)
    assert pending.status_code == 409 and pending.json()["detail"] == {"code": "auth_not_consumable", "status": "pending"}
    assert world.decide(request_id).json()["data"]["status"] == "approved"
    consumed = world.consume(request_id)
    assert consumed.status_code == 200 and consumed.json()["data"]["consumed"] is True
    again = world.consume(request_id)
    assert again.status_code == 409 and again.json()["detail"]["status"] == "approved"


@pytest.mark.parametrize(
    ("revoke", "factor"),
    [
        (lambda w: update(User).where(User.username == "alice").values(locked=True), "lockout"),
        (lambda w: update(Device).where(Device.id == w.phone["id"]).values(revoked=True), "device_revoked"),
        (lambda w: update(Device).where(Device.id == w.phone["id"]).values(public_key=None), "device_revoked"),
        (lambda w: update(Device).where(Device.id == w.phone["id"]).values(user_id=w.bob["id"]), "device_revoked"),
    ],
)
def test_consume_rechecks_principal_and_approving_device(world: World, revoke, factor: str) -> None:
    request_id = world.start()["data"]["id"]
    assert world.decide(request_id).json()["data"]["status"] == "approved"
    # Changed directly in SQL, bypassing the admin routes that would also cancel the grant.
    world.sql(revoke(world))
    response = world.consume(request_id)
    assert response.status_code == 409 and response.json()["detail"]["status"] == "denied"
    row = world.c.get("/api/admin/auth-logs", headers=ADMIN, params={"user": "alice"}).json()["data"][0]
    assert (row["status"], row["factor"]) == ("denied", factor)
    assert "auth" in world.app.state.syslog.kinds()


def test_consume_rechecks_a_locked_delegated_approver(world: World) -> None:
    delegated = world.admin("POST", "/api/admin/integrations", json={"name": "d", "client_id": "d", "principal_username": "alice",
                                                                     "approver_username": "bob"})
    bob_key = Ed25519PrivateKey.generate()
    bob_phone = world.add_device(world.bob["id"], bob_key)
    request_id = world.signed("POST", "/api/v1/auth/requests", {"username": "alice"}, integration=delegated).json()["data"]["id"]
    assert world.decide(request_id, key=bob_key, device=bob_phone).json()["data"]["status"] == "approved"
    world.sql(update(User).where(User.username == "bob").values(locked=True))
    response = world.consume(request_id, integration=delegated)
    assert response.status_code == 409
    row = world.c.get("/api/admin/auth-logs", headers=ADMIN, params={"user": "alice"}).json()["data"][0]
    assert row["factor"] == "approver_lockout"


def test_consume_after_expiry_times_out_pending_and_approved_grants(world: World) -> None:
    pending_id = world.start()["data"]["id"]
    approved_id = world.start(pam_service="sudo")["data"]["id"]
    denied_id = world.start(pam_service="login")["data"]["id"]
    assert world.decide(approved_id).json()["data"]["status"] == "approved"
    assert world.decide(denied_id, "deny").json()["data"]["status"] == "denied"
    past = utcnow().replace(tzinfo=None) - __import__("datetime").timedelta(seconds=5)
    world.sql(update(AuthRequest).values(expires_at=past))
    watch_before = world.app.state.unanswered_watch.streak
    for request_id in (pending_id, approved_id):
        response = world.consume(request_id)
        assert response.status_code == 409 and response.json()["detail"]["status"] == "timeout"
    # Only the never-answered request counts towards the unanswered-push streak.
    assert world.app.state.unanswered_watch.streak == watch_before + 1
    # A request that already settled stays as it was.
    late = world.consume(denied_id)
    assert late.status_code == 409 and late.json()["detail"]["status"] == "denied"


def test_proxy_verify_validates_wait_seconds_and_reports_terminal_states(world: World) -> None:
    path = "/api/v1/proxy/verify"
    for wait in ("soon", -1, [1]):
        response = world.signed("POST", path, {"username": "alice", "wait_seconds": wait})
        assert response.status_code == 422 and code_of(response) == "bad_wait_seconds", wait
    overflow = world.signed("POST", path, raw=b'{"username":"alice","wait_seconds":1e400}')
    assert overflow.status_code == 422 and code_of(overflow) == "bad_wait_seconds"
    pending = world.signed("POST", path, {"username": "alice", "wait_seconds": 0}).json()["data"]
    assert (pending["status"], pending["allowed"]) == ("pending", False)
    world.admin("POST", f"/api/admin/users/{world.alice['id']}/lockout")
    denied = world.signed("POST", path, {"username": "alice", "wait_seconds": "0", "pam_service": "http"}).json()["data"]
    assert (denied["status"], denied["allowed"]) == ("denied", False)


def test_proxy_verify_consumes_an_offline_backup_code_once(world: World) -> None:
    codes = world.admin("POST", f"/api/admin/users/{world.alice['id']}/backup-codes", params={"count": 1})["codes"]
    first = world.signed("POST", "/api/v1/proxy/verify", {"username": "alice", "offline_code": codes[0]}).json()["data"]
    assert (first["status"], first["allowed"], first["factor"]) == ("approved", True, "backup_code")
    second = world.signed("POST", "/api/v1/proxy/verify", {"username": "alice", "offline_code": codes[0]}).json()["data"]
    assert (second["status"], second["factor"]) == ("denied", "offline_code")


def test_offline_code_without_enrolled_totp_falls_through_to_backup_codes(world: World) -> None:
    denied = world.start(offline_code="123456")["data"]
    assert denied["status"] == "denied"


# --- device decisions --------------------------------------------------------------------------


def test_decision_rejections(world: World) -> None:
    request_id = world.start()["data"]["id"]
    assert world.decide("missing").status_code == 404
    bob_key = Ed25519PrivateKey.generate()
    bob_phone = world.add_device(world.bob["id"], bob_key)
    rejected = world.decide(request_id, key=bob_key, device=bob_phone)
    assert rejected.status_code == 403 and code_of(rejected) == "device_rejected"
    ghost = world.decide(request_id, device={"id": "ghost"})
    assert code_of(ghost) == "device_rejected"
    forged = world.decide(request_id, key=Ed25519PrivateKey.generate())
    assert forged.status_code == 403 and code_of(forged) == "bad_device_signature"
    bad_b64 = world.c.post(f"/api/v1/auth/requests/{request_id}/decision",
                           json={"device_id": world.phone["id"], "decision": "approve", "signature": "!!!"})
    assert code_of(bad_b64) == "bad_device_signature"
    # A signature over a different decision does not authorize this one.
    deny_sig = base64.b64encode(world.key.sign(f"{request_id}.deny.false".encode())).decode()
    swapped = world.c.post(f"/api/v1/auth/requests/{request_id}/decision",
                           json={"device_id": world.phone["id"], "decision": "approve", "signature": deny_sig})
    assert code_of(swapped) == "bad_device_signature"
    pending_device = world.admin("POST", "/api/admin/devices", json={"user_id": world.alice["id"], "name": "unenrolled"})
    assert code_of(world.decide(request_id, device=pending_device)) == "device_not_enrolled"
    world.admin("DELETE", f"/api/admin/devices/{bob_phone['id']}")
    world.sql(update(Device).where(Device.id == bob_phone["id"]).values(user_id=world.alice["id"]))
    assert code_of(world.decide(request_id, key=bob_key, device=bob_phone)) == "device_rejected"


def test_decision_refuses_locked_users_even_with_a_valid_signature(world: World) -> None:
    request_id = world.start()["data"]["id"]
    world.sql(update(User).where(User.username == "alice").values(locked=True))
    response = world.decide(request_id)
    assert response.status_code == 403 and code_of(response) == "principal_locked"

    delegated = world.admin("POST", "/api/admin/integrations", json={"name": "d", "client_id": "d", "principal_username": "bob",
                                                                     "approver_username": "alice"})
    world.sql(update(User).where(User.username == "alice").values(locked=False))
    other_id = world.signed("POST", "/api/v1/auth/requests", {"username": "bob"}, integration=delegated).json()["data"]["id"]
    world.sql(update(User).where(User.username == "alice").values(locked=True))
    response = world.decide(other_id)
    assert response.status_code == 403 and code_of(response) == "approver_locked"


def test_decision_biometric_first_response_and_expiry(world: World) -> None:
    world.admin("PATCH", f"/api/admin/devices/{world.phone['id']}", json={"require_biometric": True})
    request_id = world.start()["data"]["id"]
    needs = world.decide(request_id)
    assert needs.status_code == 403 and code_of(needs) == "biometric_required"
    # A denial never needs a biometric.
    assert world.decide(request_id, "deny").json()["data"] == {"id": request_id, "status": "denied", "allowed": False}
    again = world.decide(request_id, biometric=True).json()["data"]
    assert again == {"id": request_id, "status": "denied", "first_response_wins": True}

    late_id = world.start(pam_service="sudo")["data"]["id"]
    past = utcnow().replace(tzinfo=None) - __import__("datetime").timedelta(seconds=1)
    world.sql(update(AuthRequest).where(AuthRequest.id == late_id).values(expires_at=past))
    late = world.decide(late_id, biometric=True).json()["data"]
    assert late == {"id": late_id, "status": "timeout", "allowed": False}


# --- enrollment and push token -----------------------------------------------------------------


def test_enrollment_rejections(world: World) -> None:
    enroll = world.c.post
    public = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    assert enroll("/api/v1/devices/missing/enroll", json={"enrollment_token": "x", "public_key": public}).status_code == 404
    consumed = enroll(f"/api/v1/devices/{world.phone['id']}/enroll", json={"enrollment_token": "x", "public_key": public})
    assert consumed.status_code == 409 and code_of(consumed) == "enrollment_consumed"
    pending = world.admin("POST", "/api/admin/devices", json={"user_id": world.alice["id"], "name": "new"})
    token = json.loads(pending["enrollment_qr_payload"])["enrollment_token"]
    bad = enroll(f"/api/v1/devices/{pending['id']}/enroll", json={"enrollment_token": "wrong", "public_key": public})
    assert bad.status_code == 403 and code_of(bad) == "bad_enrollment_token"
    bad_key = enroll(f"/api/v1/devices/{pending['id']}/enroll", json={"enrollment_token": token, "public_key": "AAAA"})
    assert bad_key.status_code == 422 and code_of(bad_key) == "bad_public_key"
    world.sql(update(Device).where(Device.id == pending["id"]).values(enrollment_expires_at=utcnow().replace(tzinfo=None)))
    expired = enroll(f"/api/v1/devices/{pending['id']}/enroll", json={"enrollment_token": token, "public_key": public})
    assert expired.status_code == 403 and code_of(expired) == "enrollment_token_expired"
    world.admin("DELETE", f"/api/admin/devices/{pending['id']}")
    revoked = enroll(f"/api/v1/devices/{pending['id']}/enroll", json={"enrollment_token": token, "public_key": public})
    assert revoked.status_code == 404


def push_token_body(world: World, token: str, *, key=None, device=None, timestamp=None, nonce=None) -> dict:
    key = key or world.key
    device = device or world.phone
    timestamp = timestamp if timestamp is not None else str(int(time.time()))
    nonce = nonce or world.nonce()
    signature = base64.b64encode(key.sign(f"push_token.{device['id']}.{timestamp}.{nonce}.{token}".encode())).decode()
    return {"push_token": token, "timestamp": timestamp, "nonce": nonce, "signature": signature}


def test_push_token_update_rejections_and_replay(world: World) -> None:
    path = f"/api/v1/devices/{world.phone['id']}/push-token"
    assert world.c.post("/api/v1/devices/missing/push-token", json=push_token_body(world, "t")).status_code == 404
    pending = world.admin("POST", "/api/admin/devices", json={"user_id": world.alice["id"], "name": "new"})
    unenrolled = world.c.post(f"/api/v1/devices/{pending['id']}/push-token", json=push_token_body(world, "t", device=pending))
    assert unenrolled.status_code == 403 and code_of(unenrolled) == "device_not_enrolled"
    for timestamp, expected in (("later", "bad_timestamp"), ("9" * 40, "bad_timestamp"), (str(int(time.time()) - 1000), "clock_skew")):
        response = world.c.post(path, json=push_token_body(world, "t", timestamp=timestamp))
        assert response.status_code == 401 and code_of(response) == expected
    forged = world.c.post(path, json=push_token_body(world, "t", key=Ed25519PrivateKey.generate()))
    assert forged.status_code == 403 and code_of(forged) == "bad_device_signature"
    endpoint = world.c.post(path, json=push_token_body(world, "https://push.example/up/abc"))
    assert endpoint.status_code == 422 and code_of(endpoint) == "push_endpoint_not_allowed"
    body = push_token_body(world, "fcm-token")
    assert world.c.post(path, json=body).json()["data"]["push_token_configured"] is True
    replay = world.c.post(path, json=body)
    assert replay.status_code == 409 and code_of(replay) == "replay"


# --- WebSocket ---------------------------------------------------------------------------------


def ws_rejected(world: World, path: str) -> int:
    with pytest.raises(WebSocketDisconnect) as closed:
        with world.c.websocket_connect(path) as ws:
            ws.receive_json()
    return closed.value.code


def test_websocket_handshake_rejections(world: World) -> None:
    assert ws_rejected(world, "/api/v1/devices/missing/ws?timestamp=1&nonce=n&signature=s") == 1008
    for drop in ("timestamp", "nonce", "signature"):
        assert ws_rejected(world, world.ws_path(drop=drop)) == 1008
    assert ws_rejected(world, world.ws_path(timestamp="abc", signature="AAAA")) == 1008
    assert ws_rejected(world, world.ws_path(timestamp="9" * 40, signature="AAAA")) == 1008
    assert ws_rejected(world, world.ws_path(timestamp=str(int(time.time()) - 1000))) == 1008
    assert ws_rejected(world, world.ws_path(key=Ed25519PrivateKey.generate())) == 1008
    nonce = world.nonce()
    with world.c.websocket_connect(world.ws_path(nonce=nonce)) as ws:
        assert ws.receive_json() == {"type": "pending", "data": []}
    assert ws_rejected(world, world.ws_path(nonce=nonce)) == 1008
    pending = world.admin("POST", "/api/admin/devices", json={"user_id": world.alice["id"], "name": "new"})
    assert ws_rejected(world, world.ws_path(device=pending)) == 1008
    world.admin("DELETE", f"/api/admin/devices/{world.phone['id']}")
    assert ws_rejected(world, world.ws_path()) == 1008


def test_websocket_closes_1013_when_fanout_is_unavailable(world: World) -> None:
    async def unavailable(_device_id):
        raise ConnectionError("redis down")

    world.app.state.push_fanout.subscribe = unavailable
    assert ws_rejected(world, world.ws_path()) == 1013


def test_websocket_client_messages_close_the_stream(world: World) -> None:
    with pytest.raises(WebSocketDisconnect) as closed:
        with world.c.websocket_connect(world.ws_path()) as ws:
            assert ws.receive_json()["type"] == "pending"
            ws.send_text("hello")
            ws.receive_json()
    assert closed.value.code == 1008


def test_websocket_fanout_loss_closes_1013(world: World) -> None:
    with pytest.raises(WebSocketDisconnect) as closed:
        with world.c.websocket_connect(world.ws_path()) as ws:
            assert ws.receive_json()["type"] == "pending"
            fanout = world.app.state.push_fanout
            queue = next(iter(fanout._subscribers[world.phone["id"]]))
            world.c.portal.call(queue.put, FanoutDisconnected())
            ws.receive_json()
    assert closed.value.code == 1013


def test_websocket_reconcile_announces_new_and_settled_requests(world: World) -> None:
    # Publishing is suppressed, so only the SQL reconciliation can deliver these events.
    async def silent(_ids, _event):
        return None

    with world.c.websocket_connect(world.ws_path()) as ws:
        assert ws.receive_json() == {"type": "pending", "data": []}
        world.app.state.push_fanout.publish = silent
        request_id = world.start()["data"]["id"]
        announced = ws.receive_json()
        assert announced["type"] == "auth_request" and announced["data"]["id"] == request_id
        assert world.decide(request_id, "deny").status_code == 200
        settled = ws.receive_json()
        assert settled == {"type": "auth_decided", "data": {"id": request_id, "status": "denied", "decided_at": settled["data"]["decided_at"]}}


def test_websocket_reconcile_survives_a_database_error(world: World) -> None:
    armed = {"on": False, "hits": 0}

    def fail_auth_requests(_conn, _cursor, statement, _params, _context, _many):
        if armed["on"] and "FROM auth_requests" in statement:
            armed["hits"] += 1
            armed["on"] = False
            raise OperationalError(statement, {}, Exception("failover"))

    event.listen(world.app.state.db.engine, "before_cursor_execute", fail_auth_requests)
    try:
        with world.c.websocket_connect(world.ws_path()) as ws:
            assert ws.receive_json()["type"] == "pending"
            armed["on"] = True
            deadline = time.monotonic() + 5
            while not armed["hits"] and time.monotonic() < deadline:
                time.sleep(0.02)
            assert armed["hits"] == 1
            world.app.state.push_fanout.publish = lambda *_a: asyncio.sleep(0)
            request_id = world.start()["data"]["id"]
            assert ws.receive_json()["data"]["id"] == request_id
    finally:
        event.remove(world.app.state.db.engine, "before_cursor_execute", fail_auth_requests)
    assert ("ws_reconcile_error", {"device_id": world.phone["id"], "error": "OperationalError"}) in world.app.state.syslog.events


def test_websocket_reconcile_closes_when_the_device_is_revoked_elsewhere(world: World) -> None:
    with pytest.raises(WebSocketDisconnect) as closed:
        with world.c.websocket_connect(world.ws_path()) as ws:
            assert ws.receive_json()["type"] == "pending"
            # Revoked through another edge: no local fan-out event is published.
            world.sql(update(Device).where(Device.id == world.phone["id"]).values(revoked=True))
            ws.receive_json()
    assert closed.value.code == 1008


def test_websocket_reports_expired_requests_only_once_settled(world: World) -> None:
    world.app.state.push_fanout.publish = lambda *_a: asyncio.sleep(0)
    request_id = world.start()["data"]["id"]
    with world.c.websocket_connect(world.ws_path()) as ws:
        first = ws.receive_json()
        assert [row["id"] for row in first["data"]] == [request_id]
        # Expire it without letting the sweeper settle it yet.
        world.app.state.unanswered_watch.unanswered = lambda *_a: 0
        past = utcnow().replace(tzinfo=None) - __import__("datetime").timedelta(seconds=1)
        world.sql(update(AuthRequest).where(AuthRequest.id == request_id).values(expires_at=past))
        settled = ws.receive_json()
        assert settled["type"] == "auth_decided" and settled["data"]["status"] == "timeout"


def test_websocket_pending_snapshot_pages_past_100_requests(world: World) -> None:
    world.app.state.push_fanout.publish = lambda *_a: asyncio.sleep(0)
    now = utcnow().replace(tzinfo=None)
    rows = [
        {"id": f"req-{index:04d}", "user_id": world.alice["id"], "approver_user_id": world.alice["id"],
         "integration_id": world.integration["id"], "username": "alice", "system": "h", "pam_service": "ssh",
         "status": "pending", "factor": "push", "fail_mode_effective": "closed",
         "detail": {"timestamp": "not-a-timestamp"} if index == 0 else {},
         "expires_at": now + __import__("datetime").timedelta(minutes=5), "created_at": now}
        for index in range(130)
    ]
    world.sql(insert(AuthRequest).values(rows))
    with world.c.websocket_connect(world.ws_path()) as ws:
        first = ws.receive_json()
        second = ws.receive_json()
    assert [len(first["data"]), len(second["data"])] == [100, 30]
    # A malformed stored timestamp falls back to the creation time.
    assert first["data"][0]["requested_at"] == first["data"][0]["created_at"]


# --- background loops and resolution scheduling ------------------------------------------------


def test_expiry_loop_prunes_old_nonces_and_logs_sweep_errors(world: World) -> None:
    old = utcnow().replace(tzinfo=None) - __import__("datetime").timedelta(hours=2)
    world.sql(insert(Nonce).values(id=990001, integration_id=world.integration["id"], nonce="old", created_at=old))
    world.sql(insert(DeviceNonce).values(id=990002, device_id=world.phone["id"], nonce="old", created_at=old))
    deadline = time.monotonic() + 5
    with world.app.state.db.SessionLocal() as db:
        while time.monotonic() < deadline and (db.get(Nonce, 990001) or db.get(DeviceNonce, 990002)):
            time.sleep(0.1)
            db.expire_all()
        assert db.get(Nonce, 990001) is None and db.get(DeviceNonce, 990002) is None

    def fail_sweep(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().upper().startswith("DELETE FROM NONCES"):
            raise OperationalError(statement, {}, Exception("sweep failed"))

    event.listen(world.app.state.db.engine, "before_cursor_execute", fail_sweep)
    try:
        deadline = time.monotonic() + 5
        while "auth_expiry_error" not in world.app.state.syslog.kinds() and time.monotonic() < deadline:
            time.sleep(0.1)
    finally:
        event.remove(world.app.state.db.engine, "before_cursor_execute", fail_sweep)
    assert ("auth_expiry_error", {"error": "OperationalError"}) in world.app.state.syslog.events


def test_resolution_notify_errors_are_logged_not_raised(world: World) -> None:
    class Exploding:
        async def notify_auth_request(self, devices, payload):
            return {"sent": 0}

        async def notify_event(self, devices, event):
            raise RuntimeError("provider down")

    world.app.state.push_provider = Exploding()
    request_id = world.start()["data"]["id"]
    assert world.decide(request_id, "deny").status_code == 200
    deadline = time.monotonic() + 3
    while "resolution_notify_error" not in world.app.state.syslog.kinds() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert ("resolution_notify_error", {"auth_request_id": request_id, "error": "RuntimeError"}) in world.app.state.syslog.events


def test_push_retry_errors_are_logged_per_device(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'retry.db'}", bootstrap_token=ADMIN_TOKEN, push_retry_count=1,
                              auth_ttl_seconds=5))
    app.state.syslog = RecordingSyslog()

    class Failing:
        async def notify_auth_request(self, devices, payload):
            raise RuntimeError("fcm down")

        async def notify_event(self, devices, event):
            return {"sent": 0}

    app.state.push_provider = Failing()
    with TestClient(app) as client:
        w = World(client, app)
        w.start()
        deadline = time.monotonic() + 6
        while sum(kind == "push_error" for kind in app.state.syslog.kinds()) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
    attempts = [payload["attempt"] for kind, payload in app.state.syslog.events if kind == "push_error"]
    assert attempts[:2] == [1, 2]


def test_resolution_without_a_running_loop_is_dropped_quietly(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'noloop.db'}", bootstrap_token=ADMIN_TOKEN))
    # No lifespan: app.state.loop is never set, so the scheduled notification is closed.
    client = TestClient(app)
    w = World(client, app)
    request_id = w.start()["data"]["id"]
    assert w.decide(request_id, "deny").json()["data"]["status"] == "denied"


def test_source_name_prewarm_failure_is_logged(tmp_path: Path, caplog) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'warm.db'}", bootstrap_token=ADMIN_TOKEN,
                              source_name_suffix="example.test", source_name_resolvers="127.0.0.1:9"))

    async def broken(_sources):
        raise RuntimeError("no dns")

    app.state.source_names.prewarm = broken
    caplog.set_level("WARNING", logger="pushgate.source")
    import logging

    logging.getLogger("pushgate.source").propagate = True
    try:
        with TestClient(app):
            deadline = time.monotonic() + 3
            while not any("source_name_prewarm_failed" in r.getMessage() for r in caplog.records) and time.monotonic() < deadline:
                time.sleep(0.05)
    finally:
        logging.getLogger("pushgate.source").propagate = False
    assert any("source_name_prewarm_failed error=RuntimeError" in r.getMessage() for r in caplog.records)


def test_policies_without_a_fail_mode_fall_through(world: World) -> None:
    world.admin("POST", "/api/admin/policies", json={"name": "u", "subject_type": "user", "subject_id": world.alice["id"], "auth_ttl_seconds": 30})
    world.admin("POST", "/api/admin/policies", json={"name": "i", "subject_type": "integration", "subject_id": world.integration["id"],
                                                     "push_retry_count": 0})
    world.admin("PATCH", f"/api/admin/integrations/{world.integration['id']}", json={"fail_mode": "open"})
    assert world.signed("POST", "/api/v1/auth/preflight", {"username": "alice"}).json()["data"]["fail_mode"] == "open"


def test_provisioner_bindings_must_name_existing_users(world: World) -> None:
    response = world.c.post("/api/admin/rbac/provisioners", headers=ADMIN,
                            json={"name": "p", "principal_username": "alice", "approver_username": "ghost", "systems": ["web01"]})
    assert response.status_code == 422 and code_of(response) == "unknown_binding_user"
    for systems in (["Web01"], ["web01", "web01"], ["*", "web01"]):
        response = world.c.post("/api/admin/rbac/provisioners", headers=ADMIN,
                                json={"name": "p", "principal_username": "alice", "approver_username": "alice", "systems": systems})
        assert response.status_code == 422 and code_of(response) == "invalid_system_allowlist", systems


def test_websocket_forwards_security_events_while_the_key_is_unchanged(world: World) -> None:
    with world.c.websocket_connect(world.ws_path()) as ws:
        assert ws.receive_json()["type"] == "pending"
        # Re-asserting the same key type publishes a security event but leaves the key valid.
        world.admin("PATCH", f"/api/admin/devices/{world.phone['id']}", json={"key_type": "ed25519"})
        assert ws.receive_json() == {"type": "device_security_changed", "data": {"id": world.phone["id"]}}
