"""Unit branches of the server helpers: fan-out, push providers, ephemeral state,
device-key checks, syslog export, SQLite file hardening, legacy schema upgrades and
the DNS name resolver. No network: HTTP uses mock transports, Redis uses fakes."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import sqlite3
import struct
from pathlib import Path

import httpx
import pyotp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redis.exceptions import RedisError

from server.app import push, source_names
from server.app.db import Database
from server.app.ephemeral import MemoryAuthState, RedisAuthState, build_auth_state
from server.app.push import (
    FanoutDisconnected,
    FcmPushProvider,
    NoopPushProvider,
    PushFanout,
    RedisPushFanout,
    UnifiedPushProvider,
    build_push_fanout,
    unifiedpush_endpoint_allowed,
)
from server.app.security import (
    decision_signature,
    is_valid_device_public_key,
    normalize_device_key_type,
    verify_device_message_signature,
    verify_totp,
)
from server.app.source_names import DnsError, DnsNoName, SourceNameResolver, machine_name, parse_response
from server.app.syslog_export import SyslogExporter


def run(coro):
    return asyncio.run(coro)


# --- in-process fan-out ------------------------------------------------------------------------


def test_fanout_unsubscribe_keeps_other_subscribers_and_ignores_disconnected_queues() -> None:
    async def scenario():
        fanout = PushFanout()
        first = await fanout.subscribe("phone")
        second = await fanout.subscribe("phone")
        fanout.unsubscribe("phone", first)
        assert fanout._subscribers["phone"] == {second}
        fanout._disconnect(second)
        assert isinstance(second.get_nowait(), FanoutDisconnected)
        await fanout.publish(["phone"], {"type": "auth_request", "data": {"id": "after"}})
        assert second.empty()
        # Payloads without a request id deduplicate on their full JSON.
        third = await fanout.subscribe("watch")
        await fanout.publish(["watch", "watch"], {"type": "ping"})
        await fanout.publish(["watch"], {"type": "ping"})
        await fanout.publish(["watch"], {"type": "pong"})
        assert [third.get_nowait(), third.get_nowait()] == [{"type": "ping"}, {"type": "pong"}]
        assert third.empty()

    run(scenario())


# --- Redis fan-out (fake client) ---------------------------------------------------------------


class FakePubSub:
    def __init__(self, fail_subscribe: Exception | None = None, end: bool = False) -> None:
        self.messages: asyncio.Queue = asyncio.Queue()
        self.fail_subscribe = fail_subscribe
        self.end = end
        self.closed = False

    async def subscribe(self, channel):
        if self.fail_subscribe:
            raise self.fail_subscribe

    async def listen(self):
        if self.end:
            return
        while True:
            yield await self.messages.get()

    async def aclose(self):
        self.closed = True


class FakeRedis:
    def __init__(self, pubsub: FakePubSub | None = None, publish_error: Exception | None = None) -> None:
        self._pubsub = pubsub
        self.published: list[tuple[str, str]] = []
        self.publish_error = publish_error

    def pubsub(self):
        return self._pubsub

    async def publish(self, channel, message):
        if self.publish_error:
            raise self.publish_error
        self.published.append((channel, message))

    async def aclose(self):
        pass


def install_fake_redis(monkeypatch, pubsub: FakePubSub | None, publisher: FakeRedis | None = None) -> FakeRedis:
    publisher = publisher or FakeRedis()
    calls = {"n": 0}

    def from_url(url, **kwargs):
        calls["n"] += 1
        return publisher if calls["n"] == 1 else FakeRedis(pubsub)

    monkeypatch.setattr(push.aioredis.Redis, "from_url", staticmethod(from_url))
    return publisher


@pytest.mark.parametrize("pubsub", [FakePubSub(fail_subscribe=RedisError("refused")), FakePubSub(end=True)])
def test_redis_subscription_failure_raises_connection_error_and_cleans_up(monkeypatch, pubsub) -> None:
    install_fake_redis(monkeypatch, pubsub)

    async def scenario():
        fanout = RedisPushFanout("redis://unused")
        with pytest.raises(ConnectionError):
            await fanout.subscribe("phone")
        assert not fanout._subscribers and not fanout._tasks
        await asyncio.sleep(0)

    run(scenario())


def test_redis_subscription_cancelled_while_waiting_cleans_up(monkeypatch) -> None:
    install_fake_redis(monkeypatch, FakePubSub())

    async def scenario():
        fanout = RedisPushFanout("redis://unused")
        task = asyncio.create_task(fanout.subscribe("phone"))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not fanout._subscribers and not fanout._tasks

    run(scenario())


def test_redis_relay_ignores_control_messages_and_disconnects_on_bad_payload(monkeypatch) -> None:
    pubsub = FakePubSub()
    publisher = install_fake_redis(monkeypatch, pubsub)

    async def scenario():
        fanout = RedisPushFanout("redis://unused")
        subscribing = asyncio.create_task(fanout.subscribe("phone"))
        await pubsub.messages.put({"type": "subscribe"})
        queue = await asyncio.wait_for(subscribing, 1)
        await pubsub.messages.put({"type": "pong"})
        await pubsub.messages.put({"type": "message", "data": json.dumps({"type": "auth_request", "data": {"id": "r1"}})})
        assert (await asyncio.wait_for(queue.get(), 1))["data"]["id"] == "r1"
        await pubsub.messages.put({"type": "message", "data": "{not json"})
        assert isinstance(await asyncio.wait_for(queue.get(), 1), FanoutDisconnected)
        await fanout.publish(["phone", "watch"], {"type": "auth_decided", "data": {"id": "r1"}})
        assert sorted(channel for channel, _ in publisher.published) == ["pushgate:device:phone", "pushgate:device:watch"]
        fanout.unsubscribe("phone", queue)
        fanout.unsubscribe("phone", queue)  # second call: no task left
        assert pubsub.closed

    run(scenario())


def test_redis_publish_errors_still_deliver_locally(monkeypatch) -> None:
    pubsub = FakePubSub()
    install_fake_redis(monkeypatch, pubsub, FakeRedis(publish_error=RedisError("down")))

    async def scenario():
        fanout = RedisPushFanout("redis://unused")
        subscribing = asyncio.create_task(fanout.subscribe("phone"))
        await pubsub.messages.put({"type": "subscribe"})
        queue = await asyncio.wait_for(subscribing, 1)
        await fanout.publish(["phone"], {"type": "auth_request", "data": {"id": "local"}})
        assert queue.get_nowait()["data"]["id"] == "local"
        fanout.unsubscribe("phone", queue)

    run(scenario())


def test_build_push_fanout_and_auth_state_choose_redis_only_when_configured() -> None:
    assert type(build_push_fanout(None)) is PushFanout
    assert isinstance(build_push_fanout("redis://127.0.0.1:1/0"), RedisPushFanout)
    assert isinstance(build_auth_state(None), MemoryAuthState)
    assert isinstance(build_auth_state("redis://127.0.0.1:1/0"), RedisAuthState)


# --- push providers ----------------------------------------------------------------------------


def mock_http(monkeypatch, handler):
    real = httpx.AsyncClient
    seen: list[httpx.Request] = []

    def handle(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", lambda *a, **k: real(*a, transport=httpx.MockTransport(handle), **k))
    return seen


def test_fcm_skips_without_credentials_or_tokens(monkeypatch) -> None:
    seen = mock_http(monkeypatch, lambda r: httpx.Response(200))
    devices = [{"id": "d", "push_token": "t"}]
    event = {"type": "auth_decided", "data": {"id": "r"}}
    assert run(FcmPushProvider(None, "p", "https://fcm.example/{project_id}").notify_auth_request(devices, {})) == {"sent": 0}
    assert run(FcmPushProvider("tok", None, "https://fcm.example/{project_id}").notify_event(devices, event)) == {"sent": 0}
    assert run(FcmPushProvider("tok", "p", "https://fcm.example/{project_id}").notify_event([{"id": "d"}], event)) == {"sent": 0}
    assert seen == []
    sent = run(FcmPushProvider("tok", "proj", "https://fcm.example/{project_id}/send").notify_event(devices, event))
    assert sent == {"sent": 1}
    body = json.loads(seen[0].content)["message"]
    assert seen[0].url.path == "/proj/send" and body["data"]["type"] == "auth_decided" and json.loads(body["data"]["payload"]) == event


def test_noop_provider_sends_nothing() -> None:
    assert run(NoopPushProvider().notify_auth_request([{"id": "d"}], {})) == {"sent": 0}
    assert run(NoopPushProvider().notify_event([{"id": "d"}], {})) == {"sent": 0}


def test_unifiedpush_credential_is_sent_only_to_the_configured_host(monkeypatch) -> None:
    seen = mock_http(monkeypatch, lambda r: httpx.Response(200))
    provider = UnifiedPushProvider(NoopPushProvider(), auth="Bearer tk_secret", auth_host="Push.Example",
                                   allowed_hosts="push.example, other.example")
    devices = [
        {"id": "a", "push_token": "https://push.example/up/a"},
        {"id": "b", "push_token": "https://other.example/up/b"},
        {"id": "c", "push_token": "https://evil.example/up/c"},
        {"id": "d", "push_token": "fcm-token"},
    ]
    result = run(provider.notify_auth_request(devices, {"type": "auth_request", "data": {"id": "r"}}))
    assert result == {"sent": 2, "unifiedpush": 2}
    by_host = {request.url.host: request.headers.get("authorization") for request in seen}
    assert by_host == {"push.example": "Bearer tk_secret", "other.example": None}
    seen.clear()
    big = {"type": "auth_decided", "data": {"id": "r", "status": "denied", "blob": "x" * 5000}}
    assert run(provider.notify_event(devices[:1], big)) == {"sent": 1, "unifiedpush": 1}
    assert json.loads(seen[0].content) == {"type": "auth_decided", "device_id": "a", "data": {"id": "r", "status": "denied"}}


def test_unifiedpush_endpoint_allowlist_edge_cases() -> None:
    assert unifiedpush_endpoint_allowed(None, "") is True  # no token: nothing to deliver
    assert unifiedpush_endpoint_allowed("fcm-registration-token", "") is True
    assert unifiedpush_endpoint_allowed("https://push.example/x", "") is False
    assert unifiedpush_endpoint_allowed("https://push.example/x", " PUSH.example ,") is True
    assert unifiedpush_endpoint_allowed("https://push.example.evil/x", "push.example") is False
    assert unifiedpush_endpoint_allowed("https://push.example@evil.example/x", "push.example") is False
    assert unifiedpush_endpoint_allowed("https://[::1", "push.example") is False


# --- ephemeral auth state ----------------------------------------------------------------------


class ExplodingRedis:
    def setex(self, *a):
        raise RedisError("down")

    def get(self, *a):
        raise RedisError("down")

    def delete(self, *a):
        raise RedisError("down")


class EmptyRedis:
    def get(self, *a):
        return None


def test_memory_auth_state_expires_entries(monkeypatch) -> None:
    state = MemoryAuthState()
    clock = [100.0]
    monkeypatch.setattr("server.app.ephemeral.time.monotonic", lambda: clock[0])
    state.put_pending("r", {"status": "pending"}, 0)  # clamped to one second
    assert state.get("r") == {"status": "pending"}
    clock[0] += 1.5
    assert state.get("r") is None and "r" not in state._items
    assert state.get("never") is None
    state.delete("never")


def test_redis_auth_state_falls_back_to_memory_when_redis_fails() -> None:
    state = RedisAuthState("redis://unused", client=ExplodingRedis())
    state.put_pending("r", {"status": "pending"}, 30)
    assert state.get("r") == {"status": "pending"}
    state.delete("r")
    assert state.get("r") is None
    # A Redis miss still consults the local fallback.
    fallback = RedisAuthState("redis://unused", client=EmptyRedis())
    fallback.fallback.put_pending("x", {"status": "pending"}, 30)
    assert fallback.get("x") == {"status": "pending"}


# --- device keys and signatures ----------------------------------------------------------------


def test_device_key_type_normalization_and_wrong_curve_keys() -> None:
    assert normalize_device_key_type(None) == "ed25519"
    assert normalize_device_key_type("") == "ed25519"
    with pytest.raises(ValueError):
        normalize_device_key_type("rsa")
    ed_spki = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert is_valid_device_public_key(base64.b64encode(ed_spki).decode(), "ecdsa_p256") is False
    assert is_valid_device_public_key(base64.b64encode(p384).decode(), "ecdsa_p256") is False
    assert is_valid_device_public_key(base64.b64encode(b"\x00" * 31).decode(), "ed25519") is False
    # An unsupported key type is a failed verification, never an exception.
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    signature = base64.b64encode(key.sign(b"m")).decode()
    assert verify_device_message_signature(public, signature, "m") is True
    assert verify_device_message_signature(public, signature, "m", "rsa") is False


def test_hmac_decision_signature_and_totp_helpers() -> None:
    assert decision_signature("s", "r", "approve") != decision_signature("s", "r", "deny")
    secret = pyotp.random_base32()
    assert verify_totp(secret, pyotp.TOTP(secret).now()) is True
    assert verify_totp(secret, "000000") is (pyotp.TOTP(secret).now() == "000000")


# --- syslog ------------------------------------------------------------------------------------


def test_syslog_export_sends_udp_and_swallows_errors() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        SyslogExporter(True, "127.0.0.1", receiver.getsockname()[1], "pg").emit("auth", {"b": 2, "a": 1})
        assert receiver.recv(4096) == b'<134>pg: auth {"a":1,"b":2}'
    SyslogExporter(True, "host.invalid.", 514).emit("auth", {})
    SyslogExporter(False, "127.0.0.1", 9).emit("auth", {})


# --- SQLite file hardening ---------------------------------------------------------------------


def test_engine_options_for_other_backends_are_empty() -> None:
    assert Database.engine_options("mysql://u@h/db") == {}
    timeouts = Database.engine_options("postgresql+psycopg://u@h/db", 0, 0)["connect_args"]
    assert "options" not in timeouts


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///file:x?uri=false",
        "sqlite:///file:x?uri=true&extra=1",
        "sqlite:///file:x?uri=true&cache=weird",
        "sqlite:///file::memory:?uri=true&mode=rw",
        "sqlite:///file:../x?uri=true&mode=memory",
    ],
)
def test_sqlite_file_uri_restrictions(url: str) -> None:
    with pytest.raises(RuntimeError):
        Database(url)


def test_sqlite_parent_directory_checks(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(RuntimeError, match="real, accessible directory"):
        Database(f"sqlite:///{tmp_path / 'missing' / 'x.db'}")
    private = tmp_path / "ro"
    private.mkdir(mode=0o500)
    try:
        with pytest.raises(RuntimeError, match="owner-writable"):
            Database(f"sqlite:///{private / 'x.db'}")
    finally:
        private.chmod(0o700)
    real_fstat = os.fstat

    class Foreign:
        def __init__(self, st):
            self.st_uid = st.st_uid + 1
            self.st_mode = st.st_mode

    monkeypatch.setattr("server.app.db.os.fstat", lambda fd: Foreign(real_fstat(fd)))
    with pytest.raises(RuntimeError, match="owned by the service user"):
        Database(f"sqlite:///{tmp_path / 'y.db'}")


def test_sqlite_database_path_must_be_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / "dir.db").mkdir()
    with pytest.raises(RuntimeError):
        Database(f"sqlite:///{tmp_path / 'dir.db'}")
    (tmp_path / "side.db-wal").mkdir()
    (tmp_path / "side.db").touch(mode=0o600)
    with pytest.raises(RuntimeError, match="regular files"):
        Database(f"sqlite:///{tmp_path / 'side.db'}")


def test_legacy_sqlite_schema_is_upgraded_in_place(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(128), display_name VARCHAR(255),
                                fail_mode VARCHAR(16), totp_secret VARCHAR(64), locked BOOLEAN, created_at DATETIME, updated_at DATETIME);
            CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36), name VARCHAR(128), kind VARCHAR(32),
                                  public_key TEXT, push_token TEXT, enrollment_token_hash VARCHAR(128), revoked BOOLEAN,
                                  require_biometric BOOLEAN, enrolled_at DATETIME, created_at DATETIME);
            CREATE TABLE integrations (id VARCHAR(36) PRIMARY KEY, name VARCHAR(128), client_id VARCHAR(64), secret VARCHAR(128),
                                       system_type VARCHAR(64), fail_mode VARCHAR(16), enabled BOOLEAN, created_at DATETIME);
            CREATE TABLE auth_requests (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36), integration_id VARCHAR(36), username VARCHAR(128),
                                        system VARCHAR(128), pam_service VARCHAR(64), source_ip VARCHAR(64), status VARCHAR(32),
                                        factor VARCHAR(32), fail_mode_effective VARCHAR(16), detail JSON, created_at DATETIME,
                                        expires_at DATETIME, decided_at DATETIME, approved_by_device_id VARCHAR(36));
            INSERT INTO devices (id, user_id, name, kind, enrollment_token_hash, revoked, require_biometric)
                VALUES ('d1', 'u1', 'old', 'phone', 'legacy-token-hash', 0, 0);
            INSERT INTO auth_requests (id, user_id, integration_id, username, system, status, created_at, decided_at, expires_at)
                VALUES ('r1', 'u1', 'i1', 'alice', 'h', 'approved', '2020-01-01 00:00:00', '2020-01-01 00:00:05', '2020-01-01 00:01:00');
            """
        )
    path.chmod(0o600)
    Database(f"sqlite:///{path}").init()
    with sqlite3.connect(path) as conn:
        def columns(table):
            return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

        assert {"key_type", "enrollment_expires_at"} <= columns("devices")
        assert "totp_last_used_step" in columns("users")
        assert {"principal_username", "approver_username", "system_name"} <= columns("integrations")
        assert {"approver_user_id", "consumed_at"} <= columns("auth_requests")
        # A legacy enrollment token had no expiry: it is invalidated, never revived.
        assert conn.execute("SELECT enrollment_token_hash, key_type FROM devices").fetchone() == (None, "ed25519")
        # A historical approval is already effective; it cannot seed a new trust window.
        assert conn.execute("SELECT consumed_at FROM auth_requests").fetchone()[0] == "2020-01-01 00:00:05"
    # Upgrading twice is a no-op.
    Database(f"sqlite:///{path}").init()


# --- DNS resolver ------------------------------------------------------------------------------


def header(qid: int, flags: int = 0x8180, qd: int = 0, an: int = 0) -> bytes:
    return struct.pack("!HHHHHH", qid, flags, qd, an, 0, 0)


def test_dns_parser_rejects_each_truncation() -> None:
    with pytest.raises(DnsError, match="short"):
        parse_response(b"\x00" * 5, 0, 12)
    with pytest.raises(DnsError, match="truncated pointer"):
        parse_response(header(1, an=1) + b"\xc0", 1, 12)
    with pytest.raises(DnsError, match="bad label"):
        parse_response(header(1, an=1) + b"\x80", 1, 12)
    with pytest.raises(DnsError, match="truncated label"):
        parse_response(header(1, an=1) + b"\x05ab", 1, 12)
    with pytest.raises(DnsError, match="truncated record"):
        parse_response(header(1, an=1) + b"\x00\x00\x0c", 1, 12)
    with pytest.raises(DnsError, match="truncated rdata"):
        parse_response(header(1, an=1) + b"\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01", 1, 1)
    aaaa = ipaddress.IPv6Address("2001:db8::7")
    answer = header(1, an=2) + b"\x00" + struct.pack("!HHIH", 28, 1, 60, 16) + aaaa.packed + b"\x00" + struct.pack("!HHIH", 28, 1, 60, 4) + b"\x01\x02\x03\x04"
    assert parse_response(answer, 1, 28) == [aaaa]


def test_machine_name_and_query_name_limits() -> None:
    assert machine_name("a" * 64 + ".example.test", "example.test") is None
    assert machine_name("example.test", "example.test") is None
    with pytest.raises(DnsError):
        source_names.build_query(1, "a..b", 12)


class UdpResponder:
    """A local UDP socket that answers with scripted datagrams (stale first, then real)."""

    def __init__(self, replies) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.replies = replies
        import threading

        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            query, peer = self.sock.recvfrom(4096)
        except OSError:
            return
        qid = struct.unpack("!H", query[:2])[0]
        for reply in self.replies(qid):
            self.sock.sendto(reply, peer)

    @property
    def addr(self):
        return self.sock.getsockname()

    def close(self) -> None:
        self.sock.close()


def test_udp_query_skips_foreign_answers_and_times_out() -> None:
    responder = UdpResponder(lambda qid: [header(qid ^ 1), header(qid, an=1) + b"\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x0a\x00\x00\x01"])
    try:
        assert source_names.udp_query(socket.AF_INET, responder.addr, "h.example.test", 1, 2.0) == [ipaddress.IPv4Address("10.0.0.1")]
    finally:
        responder.close()
    silent = UdpResponder(lambda qid: [])
    try:
        with pytest.raises(DnsError):
            source_names.udp_query(socket.AF_INET, silent.addr, "h.example.test", 1, 0.2)
    finally:
        silent.close()


def test_resolver_query_outcomes(monkeypatch) -> None:
    resolver = SourceNameResolver(suffix="example.test", resolvers="dns1.invalid,dns2.invalid")
    outcomes = {}
    monkeypatch.setattr(resolver, "_addresses_of", lambda server: [] if server[0] == "dns1.invalid" else [(socket.AF_INET, ("127.0.0.1", 53))])
    monkeypatch.setattr(source_names, "udp_query", lambda *a: outcomes["dns2"]())
    outcomes["dns2"] = lambda: []
    with pytest.raises(DnsError, match="lookup incomplete"):
        resolver._query("x", 1)  # dns1 had no address, dns2 answered empty
    monkeypatch.setattr(resolver, "_addresses_of", lambda server: [(socket.AF_INET, ("127.0.0.1", 53))])
    assert resolver._query("x", 1) == []
    empty = SourceNameResolver(suffix="example.test")
    with pytest.raises(DnsError, match="no resolver configured"):
        empty._query("x", 1)

    def nxdomain():
        raise DnsNoName()

    outcomes["dns2"] = nxdomain
    assert resolver._query("x", 1) == []


def test_resolver_address_cache_survives_getaddrinfo_failure(monkeypatch) -> None:
    clock = [0.0]
    resolver = SourceNameResolver(suffix="example.test", resolvers="dns.example", clock=lambda: clock[0], positive_ttl=10)
    infos = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("192.0.2.53", 53))] * 2
    monkeypatch.setattr(source_names.socket, "getaddrinfo", lambda *a, **k: infos)
    assert resolver._addresses_of(("dns.example", 53)) == [(socket.AF_INET, ("192.0.2.53", 53))]

    def fail(*a, **k):
        raise socket.gaierror(-2, "unknown")

    monkeypatch.setattr(source_names.socket, "getaddrinfo", fail)
    clock[0] = 20
    assert resolver._addresses_of(("dns.example", 53)) == [(socket.AF_INET, ("192.0.2.53", 53))]
    assert resolver._addresses_of(("other.example", 53)) == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (socket.herror(1, "not found"), []),
        (socket.herror(2, "try again"), DnsError),
        (socket.gaierror(socket.EAI_NONAME, "no name"), []),
        (socket.gaierror(socket.EAI_AGAIN, "again"), DnsError),
        (OSError("boom"), DnsError),
    ],
)
def test_system_reverse_lookup_error_mapping(monkeypatch, error, expected) -> None:
    resolver = SourceNameResolver(suffix="example.test")

    def raise_error(_address):
        raise error

    monkeypatch.setattr(source_names.socket, "gethostbyaddr", raise_error)
    if expected is DnsError:
        with pytest.raises(DnsError):
            resolver._ptr_names(ipaddress.ip_address("192.0.2.1"))
    else:
        assert resolver._ptr_names(ipaddress.ip_address("192.0.2.1")) == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (socket.gaierror(socket.EAI_NONAME, "no name"), set()),
        (socket.gaierror(socket.EAI_AGAIN, "again"), DnsError),
        (UnicodeError("bad idna"), DnsError),
    ],
)
def test_system_forward_lookup_error_mapping(monkeypatch, error, expected) -> None:
    resolver = SourceNameResolver(suffix="example.test")

    def raise_error(*_a, **_k):
        raise error

    monkeypatch.setattr(source_names.socket, "getaddrinfo", raise_error)
    if expected is DnsError:
        with pytest.raises(DnsError):
            resolver._forward_addresses("h.example.test", 4)
    else:
        assert resolver._forward_addresses("h.example.test", 4) == expected
    monkeypatch.setattr(source_names.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET6, 0, 0, "", ("fe80::1%eth0", 0, 0, 0)), (socket.AF_INET6, 0, 0, "", ("bogus", 0, 0, 0))])
    assert resolver._forward_addresses("h.example.test", 6) == {ipaddress.ip_address("fe80::1")}


def test_resolver_cache_is_bounded_and_failed_lookups_show_the_source(monkeypatch) -> None:
    resolver = SourceNameResolver(suffix="example.test", max_entries=16)
    for index in range(16):
        resolver._store(f"192.0.2.{index}", None)
    resolver._store("192.0.2.200", "named")
    assert len(resolver._cache) == 16 and "192.0.2.200" in resolver._cache

    async def scenario():
        broken = SourceNameResolver(suffix="example.test", timeout=1.0)

        def boom(_key, _address):
            future = asyncio.get_running_loop().create_future()
            future.set_exception(RuntimeError("lookup task failed"))
            return future

        broken._start = boom
        assert await broken.display_name("192.0.2.9") == "192.0.2.9"
        assert await broken.prewarm(["192.0.2.9", "not-an-ip", "192.0.2.9"]) == 1
        broken.close()

    run(scenario())
