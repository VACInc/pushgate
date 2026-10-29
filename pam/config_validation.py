#!/usr/bin/env python3
"""Shared validation for PushGate PAM runtime configuration."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit


_SAFE_INSTALL_PATH_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/+:-"
)


def validate_server_url(server: str) -> str:
    parsed = urlsplit(server)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("PushGate server must be an HTTP(S) origin without embedded credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("PushGate server must be an origin without a path, query, or fragment")
    if parsed.scheme == "http":
        hostname = parsed.hostname.rstrip(".").lower()
        try:
            is_loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = hostname == "localhost"
        if not is_loopback:
            raise ValueError("PushGate requires HTTPS for non-loopback servers")
    return server


def validate_timeout(timeout: int) -> int:
    if not 1 <= timeout <= 600:
        raise ValueError("PushGate timeout must be between 1 and 600 seconds")
    return timeout


def validate_cache_max_age(cache_max_age: int) -> int:
    if not 0 <= cache_max_age <= 604800:
        raise ValueError("PushGate cache maximum age must be between 0 and 604800 seconds")
    return cache_max_age


def validate_install_path(label: str, path: str) -> str:
    if not path.startswith("/") or any(character not in _SAFE_INSTALL_PATH_CHARACTERS for character in path):
        raise ValueError(f"{label} must be an absolute path using only portable shell-safe characters")
    return path


def validate_secure_install_location(label: str, path: str) -> str:
    """Require an install directory to be anchored below trusted root-owned directories."""
    file_path = Path(path)
    if not file_path.is_absolute():
        raise PermissionError(f"{label} must be absolute")
    current = file_path
    while not current.exists():
        if current.parent == current:
            raise FileNotFoundError(path)
        current = current.parent
    while True:
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise PermissionError(f"{label} must not contain symlinks")
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise PermissionError(f"{label} must contain only root-owned directories")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PermissionError(f"{label} must not be writable by non-root users")
        if current.parent == current:
            break
        current = current.parent
    return path


def decode_env_value(value: str) -> str:
    """Decode installer JSON strings while retaining legacy quoted env files."""
    raw = value.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return raw[1:-1]
        if isinstance(decoded, str):
            return decoded
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1]
    return raw


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--cache-max-age", required=True, type=int)
    parser.add_argument("--config-dir", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--venv-dir", required=True)
    parser.add_argument("--libexec-dir", required=True)
    parser.add_argument("--require-root-owned-paths", action="store_true")
    args = parser.parse_args()
    try:
        validate_server_url(args.server.rstrip("/"))
        validate_timeout(args.timeout)
        validate_cache_max_age(args.cache_max_age)
        validate_install_path("PushGate config directory", args.config_dir)
        validate_install_path("PushGate cache directory", args.cache_dir)
        validate_install_path("PushGate virtualenv directory", args.venv_dir)
        validate_install_path("PushGate libexec directory", args.libexec_dir)
        if args.require_root_owned_paths:
            validate_secure_install_location("PushGate config directory", args.config_dir)
            validate_secure_install_location("PushGate cache directory", args.cache_dir)
            validate_secure_install_location("PushGate virtualenv directory", args.venv_dir)
            validate_secure_install_location("PushGate libexec directory", args.libexec_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
