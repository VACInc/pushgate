"""Server-side requester names (2026-10-30: hosts with older helpers showed the raw client address).

A login helper sends the connecting address as source_ip. The server now shows the shortest machine
name under the configured suffix (PTR, confirmed forward), capped in time, cached, and falls back to the
address. Dedupe and trusted sessions keep the raw value the helper sent.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app
from server.app.source_names import (
    DnsError,
    DnsNoName,
    SourceNameResolver,
    build_query,
    machine_name,
    parse_address,
    parse_resolvers,
    parse_response,
)

from test_server_hardening import (
    ADMIN_TOKEN,
    RecordingPushProvider,
    admin_request,
    create_device,
    create_integration,
    create_user,
    start_auth,
    wait_for_push_count,
)

SUFFIX = "example.test"
CLIENT_IP = "192.0.2.178"  # the automation host logins come from
CLIENT_NAME = "server01"
CLIENT_ALIAS = "workstation01"  # a second, longer machine name for the same address
UNKNOWN_IP = "192.0.2.250"  # no reverse record
SPOOF_IP = "192.0.2.251"  # reverse record that does not resolve back


def fqdn(short: str) -> str:
    return f"{short}.{SUFFIX}"


# --- an independent fake DNS server (UDP, stdlib) ------------------------------------------------------


def _name_wire(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _qname(msg: bytes, offset: int = 12) -> tuple[str, int]:
    labels = []
    while msg[offset]:
        n = msg[offset]
        labels.append(msg[offset + 1 : offset + 1 + n].decode())
        offset += 1 + n
    return ".".join(labels), offset + 1


class FakeDns:
    """Answers PTR/A/AAAA from dictionaries; NXDOMAIN for unknown names; optional delay."""

    def __init__(self, ptr: dict[str, list[str]], a: dict[str, list[str]], delay: float = 0.0) -> None:
        self.ptr = {ipaddress.ip_address(k).reverse_pointer: v for k, v in ptr.items()}
        self.a = a
        self.delay = delay
        self.drop: set[int] = set()  # query types left unanswered (a resolver timing out)
        self.queries: list[tuple[str, int]] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _answer(self, query: bytes) -> bytes:
        qid = struct.unpack("!H", query[:2])[0]
        name, end = _qname(query)
        qtype, _ = struct.unpack("!HH", query[end : end + 4])
        self.queries.append((name.lower(), qtype))
        question = query[12 : end + 4]
        records = b""
        count = 0
        rcode = 0
        if qtype == 12 and name.lower() in self.ptr:
            for target in self.ptr[name.lower()]:
                rdata = _name_wire(target)
                # compressed owner name pointing at the question (offset 12)
                records += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata
                count += 1
        elif qtype in (1, 28) and name.lower() in self.a:
            for addr in self.a[name.lower()]:
                ip = ipaddress.ip_address(addr)
                if (ip.version == 4) != (qtype == 1):
                    continue
                records += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(ip.packed)) + ip.packed
                count += 1
        elif not (qtype in (1, 28) and name.lower() in self.a):
            rcode = 3
        header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, count, 0, 0)
        return header + question + records

    def _serve(self) -> None:
        self.sock.settimeout(0.1)
        while not self._stop:
            try:
                query, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self._answer(query)
            if self.queries and self.queries[-1][1] in self.drop:
                continue
            if self.delay:
                threading.Timer(self.delay, self._send, args=(reply, peer)).start()
            else:
                self._send(reply, peer)

    def _send(self, reply: bytes, peer) -> None:
        try:
            self.sock.sendto(reply, peer)
        except OSError:
            pass

    def close(self) -> None:
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def dns():
    server = FakeDns(
        ptr={
            CLIENT_IP: [fqdn(CLIENT_ALIAS), fqdn(CLIENT_NAME), "server01.other.test"],
            SPOOF_IP: [fqdn("admin")],
        },
        a={fqdn(CLIENT_NAME): [CLIENT_IP], fqdn(CLIENT_ALIAS): [CLIENT_IP], fqdn("admin"): ["192.0.2.6"]},
    )
    yield server
    server.close()


def dead_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- pure helpers ----------------------------------------------------------------------------------------


def test_address_and_name_parsing() -> None:
    assert str(parse_address(CLIENT_IP)) == CLIENT_IP
    assert str(parse_address(f" {CLIENT_IP} ")) == CLIENT_IP
    assert str(parse_address(f"::ffff:{CLIENT_IP}")) == CLIENT_IP
    assert parse_address("2001:db8::5").version == 6
    for not_address in (CLIENT_NAME, "", None, 42, "fe80::1%eth0", "1.2.3"):
        assert parse_address(not_address) is None
    assert machine_name(fqdn(CLIENT_NAME) + ".", SUFFIX) == CLIENT_NAME
    assert machine_name(fqdn(CLIENT_NAME).upper(), SUFFIX) == CLIENT_NAME
    assert machine_name("server01.other.test", SUFFIX) is None
    assert machine_name(SUFFIX, SUFFIX) is None
    assert machine_name("x" + SUFFIX, SUFFIX) is None  # suffix must be a whole label boundary
    assert machine_name(fqdn("bad_name"), SUFFIX) is None
    assert machine_name(fqdn(CLIENT_NAME), "") is None


def test_resolver_list_parsing() -> None:
    assert parse_resolvers("") == []
    assert parse_resolvers(" dns1.example.test , dns2.example.test:5353,[2001:db8::53]:54,[2001:db8::1]") == [
        ("dns1.example.test", 53),
        ("dns2.example.test", 5353),
        ("2001:db8::53", 54),
        ("2001:db8::1", 53),
    ]
    for bad in ("dns:0", "dns:x", "[2001:db8::1", "[2001:db8::1]x", ":53"):
        with pytest.raises(ValueError):
            parse_resolvers(bad)
    with pytest.raises(ValueError):
        Settings(source_name_resolvers="dns:notaport")


def test_response_parser_handles_compression_and_rejects_garbage() -> None:
    query = build_query(0x1234, "178.2.0.192.in-addr.arpa", 12)
    assert query[:2] == b"\x12\x34" and query.endswith(b"\x00\x0c\x00\x01")
    server = FakeDns(ptr={CLIENT_IP: [fqdn(CLIENT_NAME)]}, a={})
    try:
        reply = server._answer(query)
    finally:
        server.close()
    assert parse_response(reply, 0x1234, 12) == [fqdn(CLIENT_NAME)]
    with pytest.raises(DnsError):
        parse_response(reply, 0x9999, 12)  # someone else's answer
    with pytest.raises(DnsError):
        parse_response(reply[:20], 0x1234, 12)  # truncated
    truncated_flag = reply[:2] + bytes([reply[2] | 0x02]) + reply[3:]
    with pytest.raises(DnsError):
        parse_response(truncated_flag, 0x1234, 12)
    nx = reply[:3] + bytes([(reply[3] & 0xF0) | 3]) + reply[4:]
    with pytest.raises(DnsNoName):
        parse_response(nx, 0x1234, 12)
    servfail = reply[:3] + bytes([(reply[3] & 0xF0) | 2]) + reply[4:]
    with pytest.raises(DnsError):
        parse_response(servfail, 0x1234, 12)
    loop = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 1, 2) + b"\xc0\x0c"
    with pytest.raises(DnsError):
        parse_response(loop, 1, 12)


# --- resolver ------------------------------------------------------------------------------------------


def resolver(dns_server: FakeDns | None = None, **kwargs) -> SourceNameResolver:
    kwargs.setdefault("suffix", SUFFIX)
    if dns_server is not None:
        kwargs.setdefault("resolvers", dns_server.address)
    return SourceNameResolver(**kwargs)


def test_shortest_forward_confirmed_machine_name_wins(dns: FakeDns) -> None:
    r = resolver(dns)
    assert r.lookup(parse_address(CLIENT_IP)) == CLIENT_NAME
    assert r.lookup(parse_address(UNKNOWN_IP)) is None  # NXDOMAIN
    assert r.lookup(parse_address(SPOOF_IP)) is None  # PTR does not resolve back


def test_display_name_rewrites_addresses_only(dns: FakeDns) -> None:
    r = resolver(dns)

    async def run():
        return [
            await r.display_name(CLIENT_IP),
            await r.display_name(f"::ffff:{CLIENT_IP}"),
            await r.display_name(UNKNOWN_IP),
            await r.display_name("already-named"),
            await r.display_name(None),
            await r.display_name(""),
        ]

    assert asyncio.run(run()) == [CLIENT_NAME, CLIENT_NAME, UNKNOWN_IP, "already-named", None, ""]


def test_disabled_or_unconfigured_lookup_never_queries(dns: FakeDns) -> None:
    for r in (resolver(dns, enabled=False), resolver(dns, suffix="")):
        assert not r.enabled
        assert asyncio.run(r.display_name(CLIENT_IP)) == CLIENT_IP
    assert dns.queries == []


def test_answers_are_cached_and_failures_cached_briefly(dns: FakeDns) -> None:
    now = [1000.0]
    r = resolver(dns, positive_ttl=3600, negative_ttl=60, clock=lambda: now[0])

    async def run(source):
        return await r.display_name(source)

    assert asyncio.run(run(CLIENT_IP)) == CLIENT_NAME
    asked = len(dns.queries)
    assert asyncio.run(run(CLIENT_IP)) == CLIENT_NAME
    assert len(dns.queries) == asked  # cached
    assert asyncio.run(run(UNKNOWN_IP)) == UNKNOWN_IP
    asked = len(dns.queries)
    now[0] += 59
    assert asyncio.run(run(UNKNOWN_IP)) == UNKNOWN_IP
    assert len(dns.queries) == asked  # negative answer still cached
    now[0] += 2
    assert asyncio.run(run(UNKNOWN_IP)) == UNKNOWN_IP
    assert len(dns.queries) > asked  # negative entry expired, asked again


def test_expired_name_is_served_while_refreshing(dns: FakeDns) -> None:
    now = [0.0]
    r = resolver(dns, positive_ttl=10, clock=lambda: now[0])

    async def run():
        first = await r.display_name(CLIENT_IP)
        now[0] += 11
        dns.ptr.clear()  # the record went away; the next refresh sees NXDOMAIN
        stale = await r.display_name(CLIENT_IP)
        for _ in range(100):
            if r.cached(CLIENT_IP) == (None, True):
                break
            await asyncio.sleep(0.01)
        after = await r.display_name(CLIENT_IP)
        return first, stale, after

    assert asyncio.run(run()) == (CLIENT_NAME, CLIENT_NAME, CLIENT_IP)


def test_slow_dns_never_holds_a_login_past_the_cap() -> None:
    slow = FakeDns(ptr={CLIENT_IP: [fqdn(CLIENT_NAME)]}, a={fqdn(CLIENT_NAME): [CLIENT_IP]}, delay=0.6)
    try:
        r = resolver(slow, timeout=0.1, query_timeout=2.0)

        async def run():
            started = time.monotonic()
            first = await r.display_name(CLIENT_IP)
            waited = time.monotonic() - started
            for _ in range(300):
                if r.cached(CLIENT_IP) is not None:
                    break
                await asyncio.sleep(0.01)
            return first, waited, await r.display_name(CLIENT_IP)

        first, waited, later = asyncio.run(run())
    finally:
        slow.close()
    assert first == CLIENT_IP and waited < 0.4
    assert later == CLIENT_NAME  # the background lookup finished and filled the cache


def test_dead_resolver_falls_through_to_the_next(dns: FakeDns) -> None:
    r = resolver(dns, resolvers=f"127.0.0.1:{dead_port()},{dns.address}", query_timeout=0.2)
    assert r.lookup(parse_address(CLIENT_IP)) == CLIENT_NAME
    all_dead = resolver(resolvers=f"127.0.0.1:{dead_port()}", query_timeout=0.1)
    with pytest.raises(DnsError):
        all_dead.lookup(parse_address(CLIENT_IP))
    assert asyncio.run(all_dead.display_name(CLIENT_IP)) == CLIENT_IP


def test_system_resolver_mode(monkeypatch) -> None:
    calls = []

    def fake_gethostbyaddr(address):
        calls.append(address)
        if address == CLIENT_IP:
            return fqdn(CLIENT_ALIAS), [fqdn(CLIENT_NAME)], [CLIENT_IP]
        raise socket.herror(1, "unknown host")

    def fake_getaddrinfo(name, port, family=0, *args, **kwargs):
        if name in (fqdn(CLIENT_NAME), fqdn(CLIENT_ALIAS)):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (CLIENT_IP, 0))]
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "gethostbyaddr", fake_gethostbyaddr)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    r = resolver()
    assert r.resolvers == []
    assert r.lookup(parse_address(CLIENT_IP)) == CLIENT_NAME
    assert r.lookup(parse_address(UNKNOWN_IP)) is None
    assert calls == [CLIENT_IP, UNKNOWN_IP]

    def flaky_gethostbyaddr(address):
        raise socket.herror(2, "Host name lookup failure")  # TRY_AGAIN: unknown, not "no name"

    monkeypatch.setattr(socket, "gethostbyaddr", flaky_gethostbyaddr)
    with pytest.raises(DnsError):
        r.lookup(parse_address(CLIENT_IP))

    def v6_gethostbyaddr(address):
        return fqdn(CLIENT_NAME), [], [address]

    def v6_getaddrinfo(name, port, family=0, *args, **kwargs):
        # glibc spells the same address differently from Python and may add a scope
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:0db8:0000:0000:0000:0000:0000:0005", 0, 0, 0))]

    monkeypatch.setattr(socket, "gethostbyaddr", v6_gethostbyaddr)
    monkeypatch.setattr(socket, "getaddrinfo", v6_getaddrinfo)
    assert r.lookup(parse_address("2001:db8::5")) == CLIENT_NAME


def test_transient_failure_keeps_the_last_good_name(dns: FakeDns) -> None:
    now = [0.0]
    r = resolver(dns, positive_ttl=10, negative_ttl=5, query_timeout=0.1, clock=lambda: now[0])

    async def run():
        first = await r.display_name(CLIENT_IP)
        now[0] += 11
        dns.drop = {1, 28}  # forward lookups now time out
        stale = await r.display_name(CLIENT_IP)
        for _ in range(200):
            entry = r.cached(CLIENT_IP)
            if entry is not None and entry[1]:
                break
            await asyncio.sleep(0.01)
        return first, stale, r.cached(CLIENT_IP)

    assert asyncio.run(run()) == (CLIENT_NAME, CLIENT_NAME, (CLIENT_NAME, True))


def test_nxdomain_from_one_resolver_does_not_hide_another() -> None:
    empty = FakeDns(ptr={}, a={})
    full = FakeDns(ptr={CLIENT_IP: [fqdn(CLIENT_NAME)]}, a={fqdn(CLIENT_NAME): [CLIENT_IP]})
    try:
        r = resolver(resolvers=f"{empty.address},{full.address}")
        assert r.lookup(parse_address(CLIENT_IP)) == CLIENT_NAME
        assert r.lookup(parse_address(UNKNOWN_IP)) is None  # both say no record
        dead = resolver(resolvers=f"{empty.address},127.0.0.1:{dead_port()}", query_timeout=0.1)
        with pytest.raises(DnsError):
            dead.lookup(parse_address(UNKNOWN_IP))  # one said no, one did not answer: unknown
    finally:
        empty.close()
        full.close()


# --- end to end through the API ------------------------------------------------------------------------


def make_app(tmp_path: Path, dns: FakeDns, **settings):
    return create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'source-names.db'}",
            bootstrap_token=ADMIN_TOKEN,
            source_name_suffix=SUFFIX,
            source_name_resolvers=dns.address,
            **settings,
        )
    )


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_login_from_an_address_reaches_the_phone_as_the_machine_name(tmp_path: Path, dns: FakeDns) -> None:
    app = make_app(tmp_path, dns)
    push = RecordingPushProvider()
    source_log = logging.getLogger("pushgate.source")
    captured = ListHandler()
    source_log.addHandler(captured)
    try:
        run_named_logins(app, push)
    finally:
        source_log.removeHandler(captured)
    texts = captured.lines
    assert source_log.propagate is False  # one line per event even when the root logger has a handler
    assert any(t.startswith("push_text ") and t.endswith(f"text=serviceuser requests SSH access on server02 from {CLIENT_NAME}") for t in texts)
    assert any(t.endswith(f"from {UNKNOWN_IP}") for t in texts)


def run_named_logins(app, push) -> None:
    with TestClient(app) as client:
        app.state.push_provider = push
        user = create_user(client, "serviceuser")
        device, _ = create_device(client, user["id"])
        assert admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"push_token": "tok"}).status_code == 200
        integration = create_integration(client, "server02", principal_username="serviceuser")

        named = start_auth(client, integration, "serviceuser", "sn-1", system="server02", pam_service="SSH access", source_ip=CLIENT_IP)
        assert named.status_code == 201
        unknown = start_auth(client, integration, "serviceuser", "sn-2", system="server02", pam_service="SSH access", source_ip=UNKNOWN_IP)
        sent_name = start_auth(client, integration, "serviceuser", "sn-3", system="server02", pam_service="SSH access", source_ip="server03")
        payloads = wait_for_push_count(push, device["id"], 3)

        shown = {p["data"]["id"]: p["data"]["source_ip"] for p in payloads}
        assert shown[named.json()["data"]["id"]] == CLIENT_NAME
        assert shown[unknown.json()["data"]["id"]] == UNKNOWN_IP  # unresolvable: the address, as before
        assert shown[sent_name.json()["data"]["id"]] == "server03"  # helper already named it: unchanged

        # Storage, dedupe and trust keep the raw value the helper sent.
        logs = admin_request(client, "GET", "/api/admin/auth-logs").json()["data"]
        stored = {row["id"]: row["source_ip"] for row in logs}
        assert stored[named.json()["data"]["id"]] == CLIENT_IP
        # Only a real rename is recorded; a source shown as sent carries no extra name.
        names = {row["id"]: (row.get("detail") or {}).get("source_name") for row in logs}
        assert names[named.json()["data"]["id"]] == CLIENT_NAME
        assert names[unknown.json()["data"]["id"]] is None
        assert names[sent_name.json()["data"]["id"]] is None


def test_retry_of_the_same_attempt_still_dedupes_when_the_name_arrives_late(tmp_path: Path) -> None:
    slow = FakeDns(ptr={CLIENT_IP: [fqdn(CLIENT_NAME)]}, a={fqdn(CLIENT_NAME): [CLIENT_IP]}, delay=0.5)
    try:
        app = make_app(tmp_path, slow, source_name_timeout_ms=50)
        with TestClient(app) as client:
            user = create_user(client, "serviceuser")
            create_device(client, user["id"])
            integration = create_integration(client, "server02", principal_username="serviceuser")
            first = start_auth(client, integration, "serviceuser", "dd-1", system="server02", source_ip=CLIENT_IP, attempt_id="dedupe-attempt-0001")
            deadline = time.time() + 5
            while app.state.source_names.cached(CLIENT_IP) is None and time.time() < deadline:
                time.sleep(0.05)
            assert app.state.source_names.cached(CLIENT_IP) == (CLIENT_NAME, True)
            retry = start_auth(client, integration, "serviceuser", "dd-2", system="server02", source_ip=CLIENT_IP, attempt_id="dedupe-attempt-0001")
            assert retry.json()["data"].get("duplicate") is True
            assert retry.json()["data"]["id"] == first.json()["data"]["id"]
    finally:
        slow.close()


def test_restart_prewarms_recent_addresses(tmp_path: Path, dns: FakeDns) -> None:
    app = make_app(tmp_path, dns)
    with TestClient(app) as client:
        user = create_user(client, "serviceuser")
        integration = create_integration(client, "server02", principal_username="serviceuser")
        start_auth(client, integration, "serviceuser", "pw-1", system="server02", source_ip=CLIENT_IP)
    dns.queries.clear()
    again = make_app(tmp_path, dns)
    with TestClient(again):
        deadline = time.time() + 5
        while again.state.source_names.cached(CLIENT_IP) is None and time.time() < deadline:
            time.sleep(0.05)
        assert again.state.source_names.cached(CLIENT_IP) == (CLIENT_NAME, True)
    assert any(q[1] == 12 for q in dns.queries)


def test_prewarm_counts_only_new_addresses(dns: FakeDns) -> None:
    assert asyncio.run(resolver(dns, enabled=False).prewarm([CLIENT_IP])) == 0
    r = resolver(dns)
    assert asyncio.run(r.prewarm([CLIENT_IP, CLIENT_IP, "named-host", None])) == 1
    assert r.cached(CLIENT_IP) == (CLIENT_NAME, True)
    assert asyncio.run(r.prewarm([CLIENT_IP])) == 0


def test_resends_after_a_late_lookup_show_the_name(tmp_path: Path) -> None:
    slow = FakeDns(ptr={CLIENT_IP: [fqdn(CLIENT_NAME)]}, a={fqdn(CLIENT_NAME): [CLIENT_IP]}, delay=0.3)
    try:
        app = make_app(tmp_path, slow, source_name_timeout_ms=50)
        push = RecordingPushProvider()
        with TestClient(app) as client:
            app.state.push_provider = push
            assert admin_request(client, "PATCH", "/api/admin/settings/global", json={"push_retry_count": 2}).status_code == 200
            user = create_user(client, "serviceuser")
            device, _ = create_device(client, user["id"])
            assert admin_request(client, "PATCH", f"/api/admin/devices/{device['id']}", json={"push_token": "tok"}).status_code == 200
            integration = create_integration(client, "server02", principal_username="serviceuser")
            started = start_auth(client, integration, "serviceuser", "late-1", system="server02", source_ip=CLIENT_IP)
            assert started.status_code == 201
            payloads = wait_for_push_count(push, device["id"], 2, timeout_seconds=8)
    finally:
        slow.close()
    shown = [p["data"]["source_ip"] for p in payloads]
    assert shown[0] == CLIENT_IP  # the lookup missed the creation deadline
    assert shown[-1] == CLIENT_NAME  # the retry already shows the name
