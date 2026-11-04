"""Seeded property tests: many generated cases per invariant, reproducible from the seed.

No extra dependency: each test draws its cases from random.Random(seed), and a failure
message names the case so it can be replayed.
"""
from __future__ import annotations

import base64
import json
import random
import string
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from pam import config_validation, pushgate_pam
from server.app import main as server_main
from server.app.config import Settings
from server.app.main import create_app
from server.app.push import UNIFIEDPUSH_MAX_BYTES, PushFanout, FanoutDisconnected, unifiedpush_body
from server.app.security import constant_eq, integration_signature, verify_device_signature
from server.app.source_names import DnsError, DnsNoName, parse_resolvers, parse_response

SEED = 20261104
ADMIN = {"Authorization": "Bearer test-admin-token-0123456789abcdef"}


def text(rng: random.Random, low: int = 0, high: int = 24, alphabet: str = string.printable) -> str:
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(low, high)))


# --- HMAC request signing ----------------------------------------------------------------------


def test_pam_and_server_sign_identically_and_every_field_is_covered() -> None:
    rng = random.Random(SEED)
    for case in range(300):
        fields = {
            "secret": text(rng, 1, 40),
            "method": rng.choice(["GET", "POST", "post", "PATCH"]),
            "path": "/" + text(rng, 0, 30, string.ascii_letters + "/-_"),
            "body": rng.randbytes(rng.randint(0, 64)),
            "timestamp": str(rng.randint(0, 2**34)),
            "nonce": text(rng, 1, 32, string.hexdigits),
        }
        server_sig = integration_signature(**fields)
        assert server_sig == pushgate_pam.integration_signature(**fields), case
        assert server_sig == integration_signature(**{**fields, "method": fields["method"].lower()}), case
        for name in ("secret", "path", "body", "timestamp", "nonce"):
            changed = dict(fields)
            changed[name] = fields[name] + (b"x" if name == "body" else "x")
            assert integration_signature(**changed) != server_sig, (case, name)


def test_constant_eq_matches_equality_for_any_text() -> None:
    rng = random.Random(SEED + 1)
    alphabet = string.printable + "éß漢 \U0001f512"
    for case in range(500):
        left = text(rng, 0, 12, alphabet)
        right = left if rng.random() < 0.4 else text(rng, 0, 12, alphabet)
        assert constant_eq(left, right) is (left == right), case
    assert constant_eq(None, "x") is False and constant_eq("x", b"x") is False


def test_device_decision_signatures_bind_request_decision_and_biometric() -> None:
    rng = random.Random(SEED + 2)
    ed = Ed25519PrivateKey.generate()
    p256 = ec.generate_private_key(ec.SECP256R1())
    keys = {
        "ed25519": (base64.b64encode(ed.public_key().public_bytes_raw()).decode(), lambda m: ed.sign(m)),
        "ecdsa_p256": (
            base64.b64encode(p256.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            lambda m: p256.sign(m, ec.ECDSA(hashes.SHA256())),
        ),
    }
    for case in range(120):
        key_type = rng.choice(list(keys))
        public, sign = keys[key_type]
        request_id = text(rng, 1, 36, string.ascii_lowercase + string.digits + "-")
        decision = rng.choice(["approve", "deny"])
        biometric = rng.random() < 0.5
        signature = base64.b64encode(sign(f"{request_id}.{decision}.{str(biometric).lower()}".encode())).decode()
        assert verify_device_signature(public, signature, request_id, decision, biometric, key_type), case
        other_decision = "deny" if decision == "approve" else "approve"
        assert not verify_device_signature(public, signature, request_id, other_decision, biometric, key_type), case
        assert not verify_device_signature(public, signature, request_id, decision, not biometric, key_type), case
        assert not verify_device_signature(public, signature, request_id + "x", decision, biometric, key_type), case
        other_type = "ecdsa_p256" if key_type == "ed25519" else "ed25519"
        assert not verify_device_signature(public, signature, request_id, decision, biometric, other_type), case


def test_signed_requests_can_never_be_replayed_inside_or_after_the_window(tmp_path: Path, monkeypatch) -> None:
    """Any replay is refused: as a replay while the nonce is stored, as clock skew once it is pruned."""
    rng = random.Random(SEED + 3)
    window = 30
    clock = [datetime(2030, 1, 1, tzinfo=timezone.utc)]
    monkeypatch.setattr(server_main, "utcnow", lambda: clock[0])

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0] if tz else clock[0].replace(tzinfo=None)

    # Row defaults (Nonce.created_at) read the same frozen server clock as the prune.
    monkeypatch.setattr("server.app.models.datetime", FrozenDatetime)
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'replay.db'}", bootstrap_token=ADMIN["Authorization"][7:],
                              hmac_window_seconds=window, rate_limit_per_minute=100000))
    with TestClient(app) as client:
        client.post("/api/admin/users", headers=ADMIN, json={"username": "alice"}).raise_for_status()
        integration = client.post("/api/admin/integrations", headers=ADMIN, json={"name": "h", "client_id": "h"}).json()["data"]
        path = "/api/v1/auth/preflight"
        body = json.dumps({"username": "alice"}).encode()
        for case in range(60):
            signed_at = clock[0] + timedelta(seconds=rng.randint(-window, window))
            timestamp = str(int(signed_at.timestamp()))
            nonce = f"case-{case}"
            headers = {"X-PushGate-Client-Id": "h", "X-PushGate-Timestamp": timestamp, "X-PushGate-Nonce": nonce,
                       "X-PushGate-Signature": integration_signature(integration["secret"], "POST", path, body, timestamp, nonce)}
            first = client.post(path, content=body, headers=headers)
            assert first.status_code == 200, (case, first.text)
            clock[0] += timedelta(seconds=rng.choice([0, 1, window - 1, window, window + 1, 2 * window, 2 * window + 1, 5 * window]))
            # Force the prune that the background sweeper would run.
            with app.state.db.SessionLocal() as db:
                cutoff = (clock[0] - timedelta(seconds=2 * window)).replace(tzinfo=None)
                from sqlalchemy import delete

                from server.app.models import Nonce

                db.execute(delete(Nonce).where(Nonce.created_at < cutoff))
                db.commit()
            replay = client.post(path, content=body, headers=headers)
            assert replay.status_code in (401, 409), (case, replay.status_code)
            assert replay.json()["detail"]["code"] in ("replay", "clock_skew"), case


# --- fan-out and push bodies -------------------------------------------------------------------


def test_fanout_delivers_each_event_at_most_once_and_overflow_always_signals_replay() -> None:
    import asyncio

    rng = random.Random(SEED + 4)

    async def scenario():
        for case in range(60):
            fanout = PushFanout()
            queue = await fanout.subscribe("phone")
            sent = []
            for _ in range(rng.randint(1, 40)):
                event = {"type": rng.choice(["auth_request", "auth_decided"]), "data": {"id": str(rng.randint(0, 8)),
                                                                                         "status": rng.choice(["pending", "denied"])}}
                sent.append(event)
                await fanout.publish(["phone"] * rng.randint(1, 3), event)
            received = []
            while not queue.empty():
                received.append(queue.get_nowait())
            if any(isinstance(item, FanoutDisconnected) for item in received):
                assert received == [received[-1]] and isinstance(received[-1], FanoutDisconnected), case
                continue
            keys = [json.dumps(item, sort_keys=True) for item in received]
            assert len(keys) == len(set(keys)), case
            assert set(keys) == {json.dumps(item, sort_keys=True) for item in sent}, case
            assert len(received) <= queue.maxsize, case

    asyncio.run(scenario())


def test_unifiedpush_body_is_bounded_and_keeps_the_challenge() -> None:
    rng = random.Random(SEED + 5)
    for case in range(200):
        data = {
            "id": text(rng, 36, 36, string.hexdigits),
            "username": text(rng, 1, 128),
            "approver_username": text(rng, 1, 128),
            "system": text(rng, 1, 128),
            "pam_service": text(rng, 1, 64),
            "source_ip": text(rng, 0, 64),
            "push_text": text(rng, 0, 400),
            "status": "pending",
            "geolocation": {"blob": text(rng, 0, 6000)},
        }
        wire = unifiedpush_body("device-1", {"type": "auth_request", "data": data})
        assert len(wire) <= UNIFIEDPUSH_MAX_BYTES, (case, len(wire))
        payload = json.loads(json.loads(wire)["payload"])["data"]
        assert {k: payload[k] for k in ("id", "username", "system", "pam_service", "status")} == \
               {k: data[k] for k in ("id", "username", "system", "pam_service", "status")}, case


# --- PAM offline codes -------------------------------------------------------------------------


def test_locally_spent_backup_code_never_comes_back(tmp_path: Path) -> None:
    """Server snapshots arrive late and out of order; a code spent offline stays spent."""
    rng = random.Random(SEED + 6)
    base = datetime.now(timezone.utc) - timedelta(minutes=30)
    for case in range(40):
        cache_dir = tmp_path / f"case-{case}"
        codes = [f"CODE{case}-{index}" for index in range(4)]
        server_unused = set(codes)
        snapshots = []
        spent_locally = None
        for step in range(12):
            at = (base + timedelta(seconds=step)).isoformat()
            snapshots.append({"updated_at": at, "backup_code_hashes": sorted(pushgate_pam.hash_value(c) for c in server_unused)})
            if rng.random() < 0.25 and server_unused:
                server_unused.discard(rng.choice(sorted(server_unused)))  # spent online
        rng.shuffle(snapshots)
        for index, snapshot in enumerate(snapshots):
            pushgate_pam.write_cache(cache_dir, "alice", snapshot, authoritative_snapshot=True)
            if spent_locally is None and index >= rng.randint(0, 6):
                cache = pushgate_pam.read_cache(cache_dir, "alice")
                usable = [c for c in codes if pushgate_pam.offline_code_kind(cache, c)]
                if usable:
                    spent_locally = rng.choice(usable)
                    assert pushgate_pam.consume_offline_code(cache_dir, "alice", spent_locally), case
            if spent_locally is not None:
                cache = pushgate_pam.read_cache(cache_dir, "alice")
                assert pushgate_pam.offline_code_kind(cache, spent_locally) is None, (case, index)
                assert not pushgate_pam.consume_offline_code(cache_dir, "alice", spent_locally), (case, index)


def test_installer_env_encoding_round_trips_any_text(tmp_path: Path) -> None:
    rng = random.Random(SEED + 7)
    alphabet = string.printable.replace("\r", "").replace("\x0b", "").replace("\x0c", "") + "é漢'\"\\"
    for case in range(300):
        value = text(rng, 0, 40, alphabet)
        assert config_validation.decode_env_value(json.dumps(value)) == value, (case, value)
        env = tmp_path / "pushgate.env"
        env.write_text(f"PUSHGATE_CLIENT_SECRET={json.dumps(value)}\n", encoding="utf-8")
        assert pushgate_pam.read_env_file(str(env))["PUSHGATE_CLIENT_SECRET"] == value, (case, value)


def test_offline_totp_window_accepts_only_adjacent_unspent_steps() -> None:
    import pyotp

    rng = random.Random(SEED + 8)
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // 30
    for case in range(200):
        offset = rng.randint(-4, 4)
        last = rng.choice([None, current - 3, current - 1, current, current + 1])
        cache = {"username": "a", "updated_at": datetime.now(timezone.utc).isoformat(), "totp_secret": secret}
        if last is not None:
            cache["last_totp_counter"] = last
        code = totp.generate_otp(current + offset)
        expected = abs(offset) <= 1 and (last is None or current + offset > last)
        # A code from another step may collide with an accepted one; only assert when it cannot.
        collides = any(totp.generate_otp(current + o) == code for o in (-1, 0, 1) if o != offset)
        if not collides:
            assert (pushgate_pam.offline_code_kind(cache, code) == "totp") is expected, (case, offset, last)


# --- parsers -----------------------------------------------------------------------------------


def test_resolver_lists_round_trip() -> None:
    rng = random.Random(SEED + 9)
    for case in range(200):
        servers = []
        for _ in range(rng.randint(1, 4)):
            kind = rng.choice(["name", "v4", "v6"])
            port = rng.choice([53, rng.randint(1, 65535)])
            if kind == "name":
                host = text(rng, 1, 12, string.ascii_lowercase) + ".example"
                item = host if port == 53 and rng.random() < 0.5 else f"{host}:{port}"
            elif kind == "v4":
                host = ".".join(str(rng.randint(0, 255)) for _ in range(4))
                item = host if port == 53 and rng.random() < 0.5 else f"{host}:{port}"
            else:
                host = f"2001:db8::{rng.randint(1, 0xffff):x}"
                item = rng.choice([f"[{host}]:{port}", f"[{host}]" if port == 53 else f"[{host}]:{port}", host if port == 53 else f"[{host}]:{port}"])
            servers.append((host, port, item))
        joined = " , ".join(item for _, _, item in servers)
        assert parse_resolvers(joined) == [(host, port) for host, port, _ in servers], (case, joined)
    for bad in ("[::1", "[::1]x", "host:0", "host:70000", "host:", ":53"):
        with pytest.raises(ValueError):
            parse_resolvers(bad)


def test_dns_response_parser_only_raises_dns_errors_on_garbage() -> None:
    rng = random.Random(SEED + 10)
    for case in range(4000):
        qid = rng.getrandbits(16)
        body = rng.randbytes(rng.randint(0, 96))
        flags = rng.choice([0x8180, 0x8183, 0x8182, 0x8380, rng.getrandbits(16)])
        msg = struct.pack("!HHHH", qid, flags, rng.randint(0, 2), rng.randint(0, 3)) + body
        try:
            parse_response(msg, qid, rng.choice([1, 12, 28]))
        except (DnsError, DnsNoName):
            pass
