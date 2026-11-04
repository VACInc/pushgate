"""A cache write the disk refuses must not turn a live approval into a denial."""
from __future__ import annotations

import os

import httpx
import pytest

from pam import pushgate_pam
from pam.test_pushgate_pam_security import _cache, _consume_ack, _mock_client


def _approve_after_poll(calls):
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("request-1"))
        status = "pending" if request.method == "POST" else "approved"
        return httpx.Response(
            201 if request.method == "POST" else 200,
            json={"data": {"id": "request-1", "status": status, "allowed": status == "approved", "cache": _cache("alice")}},
        )

    return handler


@pytest.mark.parametrize("errno_value", [28, 30, 122, 5], ids=["ENOSPC", "EROFS", "EDQUOT", "EIO"])
@pytest.mark.parametrize("failing", ["write", "lock"])
def test_live_approval_is_not_blocked_by_an_unwritable_cache(tmp_path, monkeypatch, errno_value, failing):
    """A full or read-only /etc must not lock everyone out: the phone approval is authoritative."""
    calls = []
    _mock_client(monkeypatch, _approve_after_poll(calls))
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)

    def refuse(*_args, **_kwargs):
        raise OSError(errno_value, os.strerror(errno_value))

    monkeypatch.setattr(pushgate_pam, "_write_cache_path" if failing == "write" else "_cache_lock", refuse)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0
    assert ("POST", "/api/v1/auth/requests/request-1/consume") in calls


def test_unwritable_cache_keeps_existing_tombstones(tmp_path, monkeypatch):
    spent = pushgate_pam.hash_value("SPENT-CODE")
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", backup_code_hashes=[spent]), consumed_backup_code_hash=spent)
    before = (tmp_path / pushgate_pam.cache_path(tmp_path, "alice").name).read_bytes()
    calls = []
    _mock_client(monkeypatch, _approve_after_poll(calls))
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(pushgate_pam, "_write_cache_path", lambda *_a, **_k: (_ for _ in ()).throw(OSError(28, "full")))
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0
    assert (tmp_path / pushgate_pam.cache_path(tmp_path, "alice").name).read_bytes() == before
    assert spent in pushgate_pam.read_cache(tmp_path, "alice")["used_backup_code_hashes"]


@pytest.mark.parametrize("server_status", ["approved", "pending"])
def test_spent_offline_code_still_fails_closed_when_the_cache_cannot_record_it(tmp_path, monkeypatch, server_status):
    """The server spent the code; if the local cache cannot record that, a later outage could reuse it."""
    code = "ABCD1234"
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("request-1"))
        status = server_status if request.method == "POST" else "approved"
        return httpx.Response(
            201 if request.method == "POST" else 200,
            json={"data": {"id": "request-1", "status": status, "allowed": status == "approved", "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(pushgate_pam, "_write_cache_path", lambda *_a, **_k: (_ for _ in ()).throw(OSError(28, "full")))
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 1
    assert not any(path.endswith("/consume") for _method, path in calls)


def test_unwritable_cache_mid_poll_outage_still_uses_the_disk_cache_rules(tmp_path, monkeypatch):
    """With the snapshot unrecorded, an outage falls back to what is on disk, exactly as before."""
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example", "id", "secret", str(tmp_path), timeout=5,
        system_name="labbox", require_cache_binding=True,
    )
    binding = pushgate_pam.cache_binding(cfg, "alice", "labbox")
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", fail_mode="closed", binding=binding))

    def handler(request):
        if request.method == "POST":
            return httpx.Response(201, json={"data": {"id": "request-1", "status": "pending", "allowed": False,
                                                      "cache": _cache("alice", fail_mode="open")}})
        raise httpx.ConnectError("outage", request=request)

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(pushgate_pam, "_write_cache_path", lambda *_a, **_k: (_ for _ in ()).throw(OSError(28, "full")))

    # The unrecorded server snapshot said "open", but only the recorded "closed" counts.
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
