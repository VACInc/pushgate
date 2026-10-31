"""Name the requesting machine on the server, so every login shows the same short source name.

Login helpers send the connecting client address as ``source_ip``. Older or simpler helpers send the raw
address, newer ones may already send a name. When a configured DNS suffix is set, the server turns an
address into the shortest machine name under that suffix (``192.0.2.10`` -> PTR ``host.example.test`` ->
``host``) and shows it on the phone instead of the address. Helpers that already sent a name are left alone.

Display only: the stored ``source_ip`` (used for request dedupe and trusted sessions) keeps whatever the
helper sent. A PTR name is used only when it resolves forward to the same address, so a stray reverse
record cannot put an arbitrary name on the phone.

Lookups never delay a login by more than ``timeout`` seconds: a slow lookup keeps running in the
background and fills the cache, and that request shows the address. Answers are cached (names for
``positive_ttl``, failures for ``negative_ttl``); an expired name is still shown while it is refreshed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import secrets
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable, Iterable
from typing import Any

LOG = logging.getLogger("pushgate.source")

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_NAME = 63

TYPE_A = 1
TYPE_PTR = 12
TYPE_AAAA = 28
RCODE_NXDOMAIN = 3


class DnsError(Exception):
    """This resolver gave no usable answer; another resolver may."""


class DnsNoName(Exception):
    """The name does not exist (authoritative NXDOMAIN); no other resolver is asked."""


def ensure_log_handler(logger: logging.Logger = LOG) -> None:
    """Uvicorn configures only its own loggers; give ours a stderr handler so INFO lines reach the log."""
    if logger.level == logging.NOTSET or logger.level > logging.INFO:
        logger.setLevel(logging.INFO)
    if not any(getattr(h, "_pushgate_source", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s %(message)s"))
        handler._pushgate_source = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
        logger.propagate = False


def parse_address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address in a helper's source value, or None when the value is a name (or empty)."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id:
            return None  # link-local with a zone: no global reverse record to ask for
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
    return address


def normalize_suffix(suffix: str | None) -> str:
    return (suffix or "").strip().strip(".").lower()


def machine_name(fqdn: str, suffix: str) -> str | None:
    """``host.example.test`` -> ``host`` for suffix ``example.test``; None for anything else."""
    name = fqdn.strip().rstrip(".").lower()
    tail = "." + suffix
    if not suffix or not name.endswith(tail):
        return None
    short = name[: -len(tail)]
    if not short or len(short) > _MAX_NAME:
        return None
    if not all(_LABEL.match(label) for label in short.split(".")):
        return None
    return short


def parse_resolvers(value: str | None) -> list[tuple[str, int]]:
    """``"dns1.example.test,dns2.example.test:5353,[2001:db8::53]:53"`` -> [(host, port), ...]."""
    out: list[tuple[str, int]] = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        host, port = item, 53
        if item.startswith("["):
            end = item.find("]")
            if end < 0:
                raise ValueError(f"bad resolver {item!r}")
            host = item[1:end]
            rest = item[end + 1 :]
            if rest:
                if not rest.startswith(":"):
                    raise ValueError(f"bad resolver {item!r}")
                port = int(rest[1:])
        elif item.count(":") == 1:
            host, raw_port = item.split(":", 1)
            port = int(raw_port)
        if not host or not 0 < port < 65536:
            raise ValueError(f"bad resolver {item!r}")
        out.append((host, port))
    return out


# --- minimal DNS over UDP (stdlib only) -------------------------------------------------------------


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise DnsError("bad query name")
        out += bytes([len(raw)]) + raw
    return bytes(out + b"\x00")


def build_query(qid: int, name: str, qtype: int) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", qtype, 1)


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name; return it and the offset after it in the original position."""
    labels: list[str] = []
    end = None
    jumps = 0
    while True:
        if offset >= len(msg):
            raise DnsError("truncated name")
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise DnsError("truncated pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            jumps += 1
            if jumps > 32:
                raise DnsError("name pointer loop")
            continue
        if length & 0xC0:
            raise DnsError("bad label")
        offset += 1
        if length == 0:
            break
        if offset + length > len(msg):
            raise DnsError("truncated label")
        labels.append(msg[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def parse_response(msg: bytes, qid: int, qtype: int) -> list[Any]:
    """Answers of ``qtype`` in a response: names for PTR, address objects for A/AAAA."""
    if len(msg) < 12:
        raise DnsError("short response")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise DnsError("not our answer")
    if flags & 0x0200:
        raise DnsError("truncated response")
    rcode = flags & 0x000F
    if rcode == RCODE_NXDOMAIN:
        raise DnsNoName()
    if rcode:
        raise DnsError(f"rcode {rcode}")
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(msg, offset)
        offset += 4
    answers: list[Any] = []
    for _ in range(ancount):
        _, offset = _read_name(msg, offset)
        if offset + 10 > len(msg):
            raise DnsError("truncated record")
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", msg[offset : offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(msg):
            raise DnsError("truncated rdata")
        if rtype == qtype == TYPE_PTR:
            answers.append(_read_name(msg, offset)[0])
        elif rtype == qtype == TYPE_A and rdlength == 4:
            answers.append(ipaddress.IPv4Address(msg[offset:rdata_end]))
        elif rtype == qtype == TYPE_AAAA and rdlength == 16:
            answers.append(ipaddress.IPv6Address(msg[offset:rdata_end]))
        offset = rdata_end
    return answers


def udp_query(family: int, sockaddr: Any, name: str, qtype: int, timeout: float) -> list[Any]:
    """One question to one resolver address. Raises DnsError (no usable answer) or DnsNoName (NXDOMAIN)."""
    qid = secrets.randbelow(0x10000)
    deadline = time.monotonic() + timeout
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(sockaddr)
            sock.send(build_query(qid, name, qtype))
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise DnsError("timeout")
                sock.settimeout(left)
                msg = sock.recv(4096)
                try:
                    return parse_response(msg, qid, qtype)
                except DnsError as exc:
                    if str(exc) == "not our answer":
                        continue
                    raise
        except (OSError, socket.timeout) as exc:
            raise DnsError(exc.__class__.__name__) from exc


def _as_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


# System resolver errors that mean "no such name" rather than "try again later".
_NO_NAME_HERRNO = {1, 4}  # HOST_NOT_FOUND, NO_DATA
_NO_NAME_EAI = {getattr(socket, n) for n in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, n)}


class SourceNameResolver:
    """Address -> shortest machine name, cached, with a hard per-request time cap."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        suffix: str | None = None,
        resolvers: str | None = None,
        timeout: float = 0.3,
        query_timeout: float = 1.0,
        positive_ttl: float = 3600.0,
        negative_ttl: float = 60.0,
        max_entries: int = 4096,
        clock: Callable[[], float] = time.monotonic,
        logger: logging.Logger | None = None,
    ) -> None:
        self.suffix = normalize_suffix(suffix)
        self.enabled = bool(enabled) and bool(self.suffix)
        self.resolvers = parse_resolvers(resolvers)
        self.timeout = max(0.0, float(timeout))
        self.query_timeout = max(0.05, float(query_timeout))
        self.positive_ttl = max(1.0, float(positive_ttl))
        self.negative_ttl = max(1.0, float(negative_ttl))
        self.max_entries = max(16, int(max_entries))
        self.clock = clock
        self.log = logger or LOG
        # address text -> (short name or None, expires at)
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._inflight: dict[str, asyncio.Task[str | None]] = {}
        # Own small pool: a slow or dead resolver must never take the threads the loop's default
        # executor lends to push delivery and other getaddrinfo calls.
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pushgate-source-name")
        self._resolver_addrs: dict[tuple[str, int], tuple[list[tuple[int, Any]], float]] = {}

    # -- blocking lookup (worker thread) ------------------------------------------------------------

    def _addresses_of(self, server: tuple[str, int]) -> list[tuple[int, Any]]:
        """All socket addresses of one resolver, resolved once per positive TTL."""
        hit = self._resolver_addrs.get(server)
        if hit and self.clock() < hit[1]:
            return hit[0]
        try:
            infos = socket.getaddrinfo(server[0], server[1], type=socket.SOCK_DGRAM)
        except (OSError, UnicodeError):
            return hit[0] if hit else []
        seen: list[tuple[int, Any]] = []
        for family, _, _, _, sockaddr in infos:
            if (family, sockaddr) not in seen:
                seen.append((family, sockaddr))
        self._resolver_addrs[server] = (seen, self.clock() + self.positive_ttl)
        return seen

    def _query(self, name: str, qtype: int) -> list[Any]:
        """Ask each resolver in turn; the first non-empty answer wins.

        Every resolver saying NXDOMAIN or answering empty means no record ([]). A resolver that
        fails is skipped; if none answered at all, or the only answers were "no record" while
        another resolver failed, the outcome is unknown and DnsError is raised.
        """
        answered = False
        failed: Exception | None = None
        for server in self.resolvers:
            addrs = self._addresses_of(server)
            if not addrs:
                failed = DnsError(f"resolver address: {server[0]}")
            for family, sockaddr in addrs:
                try:
                    answers = udp_query(family, sockaddr, name, qtype, self.query_timeout)
                except DnsNoName:
                    answered = True
                    break
                except DnsError as exc:
                    failed = exc
                    continue
                if answers:
                    return answers
                answered = True
                break
        if failed is not None:
            raise DnsError(f"lookup incomplete: {failed}")
        if not answered:
            raise DnsError("no resolver configured")
        return []

    def _ptr_names(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
        if self.resolvers:
            return [str(n) for n in self._query(address.reverse_pointer, TYPE_PTR)]
        try:
            host, aliases, _ = socket.gethostbyaddr(str(address))
        except socket.herror as exc:
            if exc.errno in _NO_NAME_HERRNO:
                return []
            raise DnsError(f"reverse lookup: herror {exc.errno}") from exc
        except socket.gaierror as exc:
            if exc.errno in _NO_NAME_EAI:
                return []
            raise DnsError(f"reverse lookup: gaierror {exc.errno}") from exc
        except (OSError, UnicodeError) as exc:
            raise DnsError(f"reverse lookup: {exc.__class__.__name__}") from exc
        return [host, *aliases]

    def _forward_addresses(self, name: str, version: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        if self.resolvers:
            return set(self._query(name, TYPE_A if version == 4 else TYPE_AAAA))
        family = socket.AF_INET if version == 4 else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family)
        except socket.gaierror as exc:
            if exc.errno in _NO_NAME_EAI:
                return set()
            raise DnsError(f"forward lookup: gaierror {exc.errno}") from exc
        except (OSError, UnicodeError) as exc:
            raise DnsError(f"forward lookup: {exc.__class__.__name__}") from exc
        return {a for info in infos if (a := _as_address(str(info[4][0]))) is not None}

    def lookup(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        """Blocking: the shortest forward-confirmed machine name for ``address``, or None.

        Raises DnsError when a resolver failure leaves the answer unknown, so a cached name survives.
        """
        shorts = sorted(
            {s for n in self._ptr_names(address) if (s := machine_name(n, self.suffix))},
            key=lambda s: (len(s), s),
        )
        for short in shorts:
            if address in self._forward_addresses(f"{short}.{self.suffix}", address.version):
                return short
        return None

    # -- cache + time cap (event loop) --------------------------------------------------------------

    def known_name(self, source: Any) -> str | None:
        """A cached name (fresh or expired) for a source address, without any lookup."""
        if not self.enabled:
            return None
        address = parse_address(source)
        if address is None:
            return None
        entry = self._cache.get(str(address))
        return entry[0] if entry else None

    def cached(self, address: str) -> tuple[str | None, bool] | None:
        """(name, fresh) for a cached address, None when never looked up."""
        entry = self._cache.get(address)
        if entry is None:
            return None
        name, expires = entry
        return name, self.clock() < expires

    def _store(self, address: str, name: str | None) -> None:
        if len(self._cache) >= self.max_entries and address not in self._cache:
            oldest = min(self._cache, key=lambda k: self._cache[k][1])
            self._cache.pop(oldest, None)
        ttl = self.positive_ttl if name else self.negative_ttl
        self._cache[address] = (name, self.clock() + ttl)

    async def _resolve(self, key: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        previous = self._cache.get(key)
        try:
            name = await asyncio.get_running_loop().run_in_executor(self._executor, self.lookup, address)
        except Exception as exc:  # never let a lookup failure reach a login
            self.log.warning("source_name_lookup_failed address=%s error=%s", key, exc.__class__.__name__)
            name = None
            if previous and previous[0]:
                # Keep showing the last good name; retry after the short negative window.
                self._cache[key] = (previous[0], self.clock() + self.negative_ttl)
                return previous[0]
        self._store(key, name)
        return name

    def _start(self, key: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> asyncio.Task[str | None]:
        task = self._inflight.get(key)
        if task is None or task.done():
            task = asyncio.get_running_loop().create_task(self._resolve(key, address))
            self._inflight[key] = task
            task.add_done_callback(lambda t, k=key: self._inflight.pop(k, None) if self._inflight.get(k) is t else None)
        return task

    async def display_name(self, source: Any) -> Any:
        """What the phone shows for a helper's ``source_ip``: a machine name when one is known in time."""
        if not self.enabled:
            return source
        address = parse_address(source)
        if address is None:
            return source
        key = str(address)
        hit = self.cached(key)
        if hit is not None:
            name, fresh = hit
            if fresh:
                return name or source
            self._start(key, address)  # refresh in the background
            if name:
                return name  # the expired name stays good until the refresh replaces it
        task = self._start(key, address)
        try:
            name = await asyncio.wait_for(asyncio.shield(task), timeout=self.timeout)
        except asyncio.TimeoutError:
            self.log.info("source_name_slow address=%s timeout_ms=%d", key, int(self.timeout * 1000))
            return source
        except Exception:
            return source
        return name or source

    async def prewarm(self, sources: Iterable[Any], concurrency: int = 2) -> int:
        """Look up recently seen addresses so the first login after a restart is already named.

        At most ``concurrency`` lookups at a time, so live logins still find a free lookup thread.
        """
        if not self.enabled:
            return 0
        todo: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
        for source in sources:
            address = parse_address(source)
            if address is not None and str(address) not in todo and self.cached(str(address)) is None:
                todo[str(address)] = address
        gate = asyncio.Semaphore(max(1, concurrency))

        async def one(key: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
            async with gate:
                if self.cached(key) is None:
                    await self._start(key, address)

        if todo:
            await asyncio.gather(*(one(k, a) for k, a in todo.items()), return_exceptions=True)
        return len(todo)

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def resolver_from_settings(settings: Any) -> SourceNameResolver:
    return SourceNameResolver(
        enabled=settings.source_name_lookup,
        suffix=settings.source_name_suffix,
        resolvers=settings.source_name_resolvers,
        timeout=settings.source_name_timeout_ms / 1000.0,
        query_timeout=settings.source_name_query_timeout_ms / 1000.0,
        positive_ttl=settings.source_name_ttl_seconds,
        negative_ttl=settings.source_name_negative_ttl_seconds,
    )


__all__ = [
    "DnsError",
    "DnsNoName",
    "SourceNameResolver",
    "ensure_log_handler",
    "machine_name",
    "parse_address",
    "parse_resolvers",
    "resolver_from_settings",
]

