#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import stat
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import httpx
import pyotp


_VALIDATION_SPEC = importlib.util.spec_from_file_location(
    "pushgate_config_validation",
    Path(__file__).with_name("config_validation.py"),
)
if _VALIDATION_SPEC is None or _VALIDATION_SPEC.loader is None:
    raise ImportError("cannot load PushGate configuration validation")
_VALIDATION = importlib.util.module_from_spec(_VALIDATION_SPEC)
_VALIDATION_SPEC.loader.exec_module(_VALIDATION)
validate_cache_max_age = _VALIDATION.validate_cache_max_age
validate_server_url = _VALIDATION.validate_server_url
validate_timeout = _VALIDATION.validate_timeout


DEFAULT_CACHE_DIR = "/etc/pushgate/failmode.d"
DEFAULT_CONFIG_FILE = "/etc/pushgate/pushgate.env"
DEFAULT_CACHE_MAX_AGE = 86400
_CLOCK_SKEW_SECONDS = 300
_BACKUP_CODE_TOMBSTONES = "backup_code_tombstones"
_SERVER_SNAPSHOT_AT = "server_snapshot_at"


class AuthConfig:
    def __init__(
        self,
        server: str,
        client_id: str,
        client_secret: str,
        cache_dir: str = DEFAULT_CACHE_DIR,
        timeout: int = 70,
        approver_username: str | None = None,
        system_name: str | None = None,
        cache_max_age: int = DEFAULT_CACHE_MAX_AGE,
        require_cache_binding: bool = False,
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("PushGate client ID and secret are required")
        validate_timeout(timeout)
        validate_cache_max_age(cache_max_age)
        self.server = validate_server_url(server.rstrip("/"))
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self.approver_username = approver_username
        self.system_name = system_name
        self.cache_max_age = cache_max_age
        self.require_cache_binding = require_cache_binding


def config_from_env() -> AuthConfig:
    launched_by_wrapper = os.environ.get("PUSHGATE_PAM_LAUNCHER") == "1"
    pam_context = bool(os.environ.get("PAM_TYPE")) or launched_by_wrapper
    if launched_by_wrapper:
        config_path = os.environ.get("PUSHGATE_PAM_CONFIG") or DEFAULT_CONFIG_FILE
    else:
        config_path = DEFAULT_CONFIG_FILE if pam_context else os.environ.get("PUSHGATE_CONFIG") or DEFAULT_CONFIG_FILE
    if pam_context:
        validate_secure_config_file(config_path)
    file_env = read_env_file(config_path)

    def value(name: str, default: str | None = None) -> str | None:
        if pam_context:
            return file_env.get(name) or default
        return os.environ.get(name) or file_env.get(name) or default

    cfg = AuthConfig(
        server=value("PUSHGATE_SERVER", "http://127.0.0.1:8000") or "http://127.0.0.1:8000",
        client_id=value("PUSHGATE_CLIENT_ID") or file_env["PUSHGATE_CLIENT_ID"],
        client_secret=value("PUSHGATE_CLIENT_SECRET") or file_env["PUSHGATE_CLIENT_SECRET"],
        cache_dir=value("PUSHGATE_CACHE_DIR", DEFAULT_CACHE_DIR) or DEFAULT_CACHE_DIR,
        timeout=int(value("PUSHGATE_TIMEOUT", "70") or "70"),
        approver_username=value("PUSHGATE_APPROVER_USERNAME"),
        system_name=value("PUSHGATE_SYSTEM_NAME"),
        cache_max_age=int(value("PUSHGATE_CACHE_MAX_AGE", str(DEFAULT_CACHE_MAX_AGE)) or str(DEFAULT_CACHE_MAX_AGE)),
        require_cache_binding=pam_context,
    )
    if pam_context:
        validate_secure_cache_location(cfg.cache_dir)
    return cfg


def validate_secure_config_file(path: str) -> None:
    file_path = Path(path)
    if not file_path.is_absolute():
        raise PermissionError("PAM config path must be absolute")
    current = file_path
    while True:
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise PermissionError("PAM config path must not contain symlinks")
        if metadata.st_uid != 0:
            raise PermissionError("PAM config path must be root-owned")
        if current == file_path:
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PermissionError("PAM config must be a private regular file")
        elif not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PermissionError("PAM config parent directories must not be writable by non-root users")
        if current.parent == current:
            break
        current = current.parent


def validate_secure_cache_location(path: Path) -> None:
    if not path.is_absolute():
        raise PermissionError("PAM cache path must be absolute")
    current = path
    while not current.exists():
        if current.parent == current:
            raise FileNotFoundError(path)
        current = current.parent
    while True:
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise PermissionError("PAM cache path must contain only root-owned directories")
        if current == path:
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PermissionError("PAM cache directory must use mode 0700")
        elif stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PermissionError("PAM cache parent directories must not be writable by non-root users")
        if current.parent == current:
            break
        current = current.parent


def read_env_file(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return env
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = _VALIDATION.decode_env_value(value)
    return env


def _headers(cfg: AuthConfig, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()
    return {
        "X-PushGate-Client-Id": cfg.client_id,
        "X-PushGate-Timestamp": timestamp,
        "X-PushGate-Nonce": nonce,
        "X-PushGate-Signature": integration_signature(cfg.client_secret, method, path, body, timestamp, nonce),
        "Content-Type": "application/json",
    }


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def integration_signature(secret: str, method: str, path: str, body: bytes, timestamp: str, nonce: str) -> str:
    canonical = b"\n".join(
        [
            method.upper().encode(),
            path.encode(),
            timestamp.encode(),
            nonce.encode(),
            body,
        ]
    )
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def cache_path(cache_dir: Path, username: str) -> Path:
    return cache_dir / f"{hash_value(username)}.json"


def _cache_root(cache_dir: str | Path, create: bool = False) -> Path:
    root = Path(cache_dir)
    if not root.is_absolute():
        raise PermissionError("PushGate cache path must be absolute")
    if create:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not root.exists():
        return root
    if root.resolve(strict=True) != root.absolute():
        raise PermissionError("PushGate cache path must not contain symlinks")
    metadata = os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise PermissionError("PushGate cache must be a directory owned by the effective user")
    if create:
        os.chmod(root, stat.S_IRWXU)
        metadata = os.lstat(root)
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError("PushGate cache directory must use mode 0700")
    return root


def _validate_private_file(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError(f"{label} must be a private regular file owned by the effective user")


def _read_cache_path(path: Path, username: str) -> dict[str, Any] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        _validate_private_file(metadata, "PushGate cache file")
        if metadata.st_size > 1024 * 1024:
            raise ValueError("PushGate cache file is too large")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            cache = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(cache, dict) or cache.get("username") != username:
        raise ValueError("PushGate cache username binding mismatch")
    return cache


@contextmanager
def _cache_lock(cache_dir: str | Path, username: str) -> Iterator[Path]:
    root = _cache_root(cache_dir, create=True)
    lock_path = cache_path(root, username).with_suffix(".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        _validate_private_file(os.fstat(descriptor), "PushGate cache lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield root
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_cache_path(path: Path, cache: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    descriptor = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        _validate_private_file(os.fstat(descriptor), "PushGate temporary cache file")
        payload = json.dumps(cache, sort_keys=True).encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_cache(
    cache_dir: str | Path,
    username: str,
    cache: dict[str, Any],
    *,
    authoritative_snapshot: bool = False,
    consumed_backup_code_hash: str | None = None,
) -> dict[str, Any]:
    with _cache_lock(cache_dir, username) as root:
        path = cache_path(root, username)
        next_cache = merge_used_backup_codes(
            path,
            cache,
            username,
            authoritative_snapshot=authoritative_snapshot,
            consumed_backup_code_hash=consumed_backup_code_hash,
        )
        next_cache["username"] = username
        next_cache.setdefault("updated_at", datetime.now(timezone.utc).isoformat())
        _write_cache_path(path, next_cache)
        return next_cache


def read_cache(cache_dir: str | Path, username: str) -> dict[str, Any] | None:
    root = _cache_root(cache_dir)
    if not root.exists():
        return None
    return _read_cache_path(cache_path(root, username), username)


def _aware_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def _backup_code_tombstones(cache: dict[str, Any]) -> dict[str, datetime]:
    raw = cache.get(_BACKUP_CODE_TOMBSTONES) or {}
    if not isinstance(raw, dict):
        raise ValueError("PushGate backup-code tombstones must be an object")
    tombstones: dict[str, datetime] = {}
    for code_hash, consumed_at in raw.items():
        if not isinstance(code_hash, str) or not code_hash:
            raise ValueError("PushGate backup-code tombstone hashes must be strings")
        tombstones[code_hash] = _aware_datetime(consumed_at, "PushGate backup-code tombstone time")
    used = cache.get("used_backup_code_hashes") or []
    if not isinstance(used, list) or any(not isinstance(item, str) or not item for item in used):
        raise ValueError("PushGate used backup-code hashes must be a list of strings")
    fallback = (
        _aware_datetime(cache["updated_at"], "PushGate cache update time")
        if cache.get("updated_at")
        else datetime.min.replace(tzinfo=timezone.utc)
    )
    for code_hash in used:
        tombstones.setdefault(code_hash, fallback)
    return tombstones


def _backup_code_hashes(cache: dict[str, Any]) -> list[str]:
    raw = cache.get("backup_code_hashes") or []
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        raise ValueError("PushGate backup-code hashes must be a list of strings")
    return raw


def merge_used_backup_codes(
    path: Path,
    cache: dict[str, Any],
    username: str | None = None,
    *,
    authoritative_snapshot: bool = False,
    consumed_backup_code_hash: str | None = None,
) -> dict[str, Any]:
    next_cache = dict(cache)
    existing = _read_cache_path(path, username or str(next_cache.get("username") or ""))
    tombstones = _backup_code_tombstones(existing) if existing else {}
    snapshot_at = None
    if authoritative_snapshot:
        snapshot_at = _aware_datetime(next_cache.get("updated_at"), "PushGate server cache update time")
        accepted_at = None
        if existing:
            accepted_value = existing.get(_SERVER_SNAPSHOT_AT) or existing.get("updated_at")
            if accepted_value:
                accepted_at = _aware_datetime(accepted_value, "PushGate accepted server cache time")
        if accepted_at is not None and snapshot_at <= accepted_at:
            next_cache = dict(existing)
        else:
            incoming_hashes = set(_backup_code_hashes(next_cache))
            # Retain a spent hash while the server still advertises it. Once a
            # newer accepted snapshot excludes it, the watermark makes every
            # older in-flight snapshot inert, so the tombstone can be retired.
            tombstones = {
                code_hash: consumed_at
                for code_hash, consumed_at in tombstones.items()
                if code_hash in incoming_hashes
            }
            next_cache.pop(_BACKUP_CODE_TOMBSTONES, None)
            next_cache.pop("used_backup_code_hashes", None)
            next_cache[_SERVER_SNAPSHOT_AT] = snapshot_at.isoformat()
    else:
        for code_hash, consumed_at in _backup_code_tombstones(next_cache).items():
            tombstones[code_hash] = max(tombstones.get(code_hash, consumed_at), consumed_at)
        if existing and existing.get(_SERVER_SNAPSHOT_AT):
            next_cache.setdefault(_SERVER_SNAPSHOT_AT, existing[_SERVER_SNAPSHOT_AT])
    if consumed_backup_code_hash:
        tombstones[consumed_backup_code_hash] = datetime.now(timezone.utc)
    if existing:
        if existing.get("last_totp_counter") is not None:
            next_cache["last_totp_counter"] = max(int(existing["last_totp_counter"]), int(next_cache.get("last_totp_counter") or -1))
    if tombstones:
        next_cache[_BACKUP_CODE_TOMBSTONES] = {
            code_hash: consumed_at.isoformat() for code_hash, consumed_at in sorted(tombstones.items())
        }
        next_cache["used_backup_code_hashes"] = sorted(tombstones)
    else:
        next_cache.pop(_BACKUP_CODE_TOMBSTONES, None)
        next_cache.pop("used_backup_code_hashes", None)
    if "backup_code_hashes" in next_cache:
        next_cache["backup_code_hashes"] = [item for item in _backup_code_hashes(next_cache) if item not in tombstones]
    return next_cache


def cache_is_fresh(cache: dict[str, Any] | None, max_age: int = DEFAULT_CACHE_MAX_AGE, now: float | None = None) -> bool:
    if not cache or max_age <= 0 or not cache.get("updated_at"):
        return False
    try:
        updated = datetime.fromisoformat(str(cache["updated_at"]).replace("Z", "+00:00"))
    except ValueError:
        return False
    if updated.tzinfo is None:
        return False
    current = now if now is not None else time.time()
    age = current - updated.timestamp()
    return -_CLOCK_SKEW_SECONDS <= age <= max_age


def cache_binding(cfg: AuthConfig, username: str, system_name: str) -> dict[str, str]:
    return {
        "server": cfg.server,
        "client_id": cfg.client_id,
        "username": username,
        "approver_username": cfg.approver_username or username,
        "system": system_name,
    }


def cache_binding_valid(cache: dict[str, Any] | None, expected: dict[str, str], required: bool) -> bool:
    return bool(cache) and (not required or cache.get("binding") == expected)


def _offline_code_match(cache: dict[str, Any] | None, code: str | None, max_age: int) -> tuple[str | None, int | None]:
    if not cache_is_fresh(cache, max_age) or not code:
        return None, None
    value = str(code)
    secret = cache.get("totp_secret") if cache else None
    if secret:
        totp = pyotp.TOTP(str(secret))
        current_counter = int(time.time()) // totp.interval
        last_counter = int(cache.get("last_totp_counter") or -1)
        for offset in (-1, 0, 1):
            counter = current_counter + offset
            if counter > last_counter and hmac.compare_digest(totp.generate_otp(counter), value):
                return "totp", counter
    code_hash = hash_value(value)
    used = set(cache.get("used_backup_code_hashes") or []) if cache else set()
    if cache and code_hash in set(cache.get("backup_code_hashes") or []) and code_hash not in used:
        return "backup_code", None
    return None, None


def offline_code_kind(cache: dict[str, Any] | None, code: str | None, max_age: int = DEFAULT_CACHE_MAX_AGE) -> str | None:
    return _offline_code_match(cache, code, max_age)[0]


def offline_code_valid(cache: dict[str, Any] | None, code: str | None, max_age: int = DEFAULT_CACHE_MAX_AGE) -> bool:
    return offline_code_kind(cache, code, max_age) is not None


def consume_offline_code(
    cache_dir: str | Path,
    username: str,
    code: str | None,
    max_age: int = DEFAULT_CACHE_MAX_AGE,
    expected_binding: dict[str, str] | None = None,
    binding_required: bool = False,
) -> bool:
    if not code:
        return False
    with _cache_lock(cache_dir, username) as root:
        path = cache_path(root, username)
        cache = _read_cache_path(path, username)
        if expected_binding is not None and not cache_binding_valid(cache, expected_binding, binding_required):
            return False
        kind, counter = _offline_code_match(cache, code, max_age)
        if not kind or not cache:
            return False
        if kind == "totp":
            cache["last_totp_counter"] = counter
        else:
            code_hash = hash_value(str(code))
            cache["backup_code_hashes"] = [item for item in (cache.get("backup_code_hashes") or []) if item != code_hash]
            used = set(cache.get("used_backup_code_hashes") or [])
            used.add(code_hash)
            cache["used_backup_code_hashes"] = sorted(used)
            tombstones = _backup_code_tombstones(cache)
            tombstones[code_hash] = datetime.now(timezone.utc)
            cache[_BACKUP_CODE_TOMBSTONES] = {
                item: consumed_at.isoformat() for item, consumed_at in sorted(tombstones.items())
            }
        _write_cache_path(path, cache)
        return True


def offline_decision(
    cache_dir: str | Path,
    username: str,
    cache: dict[str, Any] | None,
    code: str | None,
    max_age: int = DEFAULT_CACHE_MAX_AGE,
    expected_binding: dict[str, str] | None = None,
    binding_required: bool = False,
) -> int:
    if expected_binding is not None and not cache_binding_valid(cache, expected_binding, binding_required):
        return 1
    if consume_offline_code(cache_dir, username, code, max_age, expected_binding, binding_required):
        return 0
    if cache_is_fresh(cache, max_age) and cache and cache.get("fail_mode") == "open":
        return 0
    return 1


def stdin_offline_code() -> str | None:
    if sys.stdin.closed or sys.stdin.isatty():
        return None
    try:
        value = sys.stdin.read(4096).strip()
    except OSError:
        return None
    return value or None


def preflight(username: str, cfg: AuthConfig | None = None, system_name: str | None = None) -> dict[str, Any]:
    cfg = cfg or config_from_env()
    system_name = cfg.system_name or system_name or os.uname().nodename
    path = "/api/v1/auth/preflight"
    payload = {
        "username": username,
        "approver_username": cfg.approver_username or username,
        "system": system_name,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    with httpx.Client(base_url=cfg.server, timeout=5.0, trust_env=False) as client:
        response = client.post(path, content=body, headers=_headers(cfg, "POST", path, body))
        response.raise_for_status()
        return response.json()["data"]


def _auth_response_data(
    response: httpx.Response,
    username: str,
    expected_request_id: str | None = None,
) -> dict[str, Any]:
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise ValueError("PushGate auth response must contain a data object")
    data = payload["data"]
    if not isinstance(data.get("id"), str) or not data["id"].strip():
        raise ValueError("PushGate auth response must contain a non-empty ID")
    if expected_request_id is not None and data["id"] != expected_request_id:
        raise ValueError("PushGate auth response request binding mismatch")
    if not isinstance(data.get("status"), str):
        raise ValueError("PushGate auth response status must be a string")
    if not isinstance(data.get("cache"), dict) or data["cache"].get("username") != username:
        raise ValueError("PushGate auth response must contain a principal-bound cache")
    return data


def _consume_approved_request(
    client: httpx.Client,
    cfg: AuthConfig,
    request_id: str,
    deadline: float,
) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    path = f"/api/v1/auth/requests/{request_id}/consume"
    try:
        response = client.post(
            path,
            content=b"",
            headers=_headers(cfg, "POST", path, b""),
            timeout=min(5.0, remaining),
        )
        if time.monotonic() >= deadline:
            return False
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            return False
        data = payload["data"]
        if (
            data.get("id") != request_id
            or data.get("status") != "approved"
            or data.get("allowed") is not True
            or data.get("consumed") is not True
        ):
            return False
        _aware_datetime(data.get("consumed_at"), "PushGate approval consumption time")
        return time.monotonic() < deadline
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return False


def _outage_decision(
    cfg: AuthConfig,
    username: str,
    local_cache: dict[str, Any] | None,
    offline_code: str | None,
    expected_binding: dict[str, str],
) -> int:
    try:
        local_cache = read_cache(cfg.cache_dir, username) or local_cache
    except (OSError, ValueError):
        return 1
    if not cache_binding_valid(local_cache, expected_binding, cfg.require_cache_binding):
        return 1
    return offline_decision(
        cfg.cache_dir,
        username,
        local_cache,
        offline_code,
        cfg.cache_max_age,
        expected_binding,
        cfg.require_cache_binding,
    )


def authenticate(
    username: str,
    pam_service: str = "ssh",
    source_ip: str | None = None,
    system_name: str | None = None,
    offline_code: str | None = None,
    cfg: AuthConfig | None = None,
) -> int:
    cfg = cfg or config_from_env()
    system_name = cfg.system_name or system_name or os.uname().nodename
    expected_binding = cache_binding(cfg, username, system_name)
    local_cache = read_cache(cfg.cache_dir, username)
    if not cache_binding_valid(local_cache, expected_binding, cfg.require_cache_binding):
        local_cache = None

    deadline = time.monotonic() + cfg.timeout
    path = "/api/v1/auth/requests"
    payload = {
        "username": username,
        "approver_username": cfg.approver_username or username,
        "system": system_name,
        "pam_service": pam_service,
        "source_ip": source_ip,
        "offline_code": offline_code,
        "client_timeout_seconds": max(0.0, deadline - time.monotonic()),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    offline_code_hash = hash_value(str(offline_code)) if offline_code else None
    try:
        with httpx.Client(base_url=cfg.server, timeout=min(5.0, cfg.timeout), trust_env=False) as client:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 1
            start = client.post(
                path,
                content=body,
                headers=_headers(cfg, "POST", path, body),
                timeout=min(5.0, remaining),
            )
            if time.monotonic() >= deadline:
                return 1
            start.raise_for_status()
            data = _auth_response_data(start, username)
            request_id = data["id"]
            server_cache = dict(data["cache"])
            server_cache["binding"] = expected_binding
            consumed_hash = offline_code_hash if data["status"] == "approved" and data.get("allowed") is True else None
            local_cache = write_cache(
                cfg.cache_dir,
                username,
                server_cache,
                authoritative_snapshot=True,
                consumed_backup_code_hash=consumed_hash,
            )
            if time.monotonic() >= deadline:
                return 1
            if data["status"] != "pending":
                if data["status"] == "approved" and data.get("allowed") is True:
                    return 0 if _consume_approved_request(client, cfg, request_id, deadline) else 1
                return 1
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 1
                time.sleep(min(0.5, remaining))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 1
                poll_path = f"{path}/{request_id}"
                poll = client.get(
                    poll_path,
                    headers=_headers(cfg, "GET", poll_path, b""),
                    timeout=min(5.0, remaining),
                )
                if time.monotonic() >= deadline:
                    return 1
                poll.raise_for_status()
                data = _auth_response_data(poll, username, request_id)
                server_cache = dict(data["cache"])
                server_cache["binding"] = expected_binding
                consumed_hash = offline_code_hash if data["status"] == "approved" and data.get("allowed") is True else None
                local_cache = write_cache(
                    cfg.cache_dir,
                    username,
                    server_cache,
                    authoritative_snapshot=True,
                    consumed_backup_code_hash=consumed_hash,
                )
                if time.monotonic() >= deadline:
                    return 1
                if data["status"] != "pending":
                    if data["status"] == "approved" and data.get("allowed") is True:
                        return 0 if _consume_approved_request(client, cfg, request_id, deadline) else 1
                    return 1
    except httpx.HTTPStatusError as exc:
        if time.monotonic() >= deadline:
            return 1
        if 500 <= exc.response.status_code < 600:
            return _outage_decision(cfg, username, local_cache, offline_code, expected_binding)
        # Non-5xx status errors, including redirects and client failures, must
        # never use cached outage behavior.
        return 1
    except (KeyError, TypeError, ValueError):
        # Malformed successful responses are never an outage and must not use
        # fail-open state.
        return 1
    except httpx.LocalProtocolError:
        # A locally invalid request is a configuration or programming error,
        # not evidence that the PushGate backend is unavailable.
        return 1
    except httpx.RequestError:
        if time.monotonic() >= deadline:
            return 1
        return _outage_decision(cfg, username, local_cache, offline_code, expected_binding)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PushGate PAM helper for pam_exec.")
    parser.add_argument("--user", default=os.environ.get("PAM_USER"))
    parser.add_argument("--service", default=os.environ.get("PAM_SERVICE", "ssh"))
    parser.add_argument("--source-ip", default=os.environ.get("PAM_RHOST"))
    pam_context = bool(os.environ.get("PAM_TYPE")) or os.environ.get("PUSHGATE_PAM_LAUNCHER") == "1"
    env_offline_code = None if pam_context else os.environ.get("PUSHGATE_OFFLINE_CODE")
    parser.add_argument("--offline-code", default=env_offline_code)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    if not args.user:
        print("missing PAM user", file=sys.stderr)
        return 1
    offline_code = args.offline_code
    cfg = config_from_env()
    if args.preflight:
        try:
            print(json.dumps(preflight(args.user, cfg=cfg), sort_keys=True))
            return 0
        except (httpx.HTTPError, KeyError, OSError, ValueError) as exc:
            print(f"PushGate preflight failed: {exc.__class__.__name__}", file=sys.stderr)
            return 2
    stdin_code = stdin_offline_code() if not offline_code else None
    if stdin_code:
        try:
            local_cache = read_cache(cfg.cache_dir, args.user)
        except (OSError, ValueError):
            return 1
        system_name = cfg.system_name or os.uname().nodename
        expected_binding = cache_binding(cfg, args.user, system_name)
        if cache_binding_valid(local_cache, expected_binding, cfg.require_cache_binding) and offline_code_valid(local_cache, stdin_code, cfg.cache_max_age):
            offline_code = stdin_code
    return authenticate(args.user, args.service, args.source_ip, offline_code=offline_code, cfg=cfg)


if __name__ == "__main__":
    raise SystemExit(main())
