"""The helper stops, and never consumes, once its PAM caller has exited."""
from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import pytest

from pam import pushgate_pam
from pam.test_pushgate_pam_security import ROOT, _cache, _consume_ack, _mock_client


def _pending_then_approved(calls):
    """Pending at start and on the first poll, approved from the second poll on."""
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("request-1"))
        polls = sum(1 for method, _path in calls if method == "GET")
        status = "approved" if polls >= 2 else "pending"
        return httpx.Response(
            201 if request.method == "POST" else 200,
            json={"data": {"id": "request-1", "status": status, "allowed": status == "approved", "cache": _cache("alice")}},
        )

    return handler


@pytest.mark.parametrize("parent_exits_after", [1, 2, 3], ids=["before-first-poll", "between-polls", "before-consume"])
def test_helper_never_consumes_an_approval_after_its_pam_caller_is_gone(tmp_path, monkeypatch, parent_exits_after):
    """sshd ends a login at LoginGraceTime and the helper is re-parented.

    The approval that arrives afterwards must not be consumed for a login
    that no longer exists, and the helper must stop polling.
    """
    calls = []
    _mock_client(monkeypatch, _pending_then_approved(calls))
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    checks = {"count": 0}

    def caller_pid():
        checks["count"] += 1
        return 4242 if checks["count"] <= parent_exits_after else 1

    monkeypatch.setattr(pushgate_pam, "_caller_pid", caller_pid)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert not any(path.endswith("/consume") for _method, path in calls)
    assert sum(1 for method, _path in calls if method == "GET") == parent_exits_after - 1


def test_helper_with_a_live_caller_still_consumes(tmp_path, monkeypatch):
    calls = []
    _mock_client(monkeypatch, _pending_then_approved(calls))
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(pushgate_pam, "_caller_pid", lambda: 4242)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0
    assert ("POST", "/api/v1/auth/requests/request-1/consume") in calls


def test_caller_gone_after_an_immediate_approval_is_not_consumed(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("request-1"))
        return httpx.Response(201, json={"data": {"id": "request-1", "status": "approved", "allowed": True,
                                                  "cache": _cache("alice")}})

    _mock_client(monkeypatch, handler)
    checks = {"count": 0}

    def caller_pid():
        checks["count"] += 1
        return 4242 if checks["count"] == 1 else 1

    monkeypatch.setattr(pushgate_pam, "_caller_pid", caller_pid)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=5)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert not any(path.endswith("/consume") for _method, path in calls)


def test_orphaned_helper_process_exits_without_consuming(tmp_path):
    """End to end: a real parent process exits while the helper waits for approval."""
    script = tmp_path / "orphan.py"
    marker = tmp_path / "consumed"
    started = tmp_path / "started"
    script.write_text(
        f"""
import json, sys, threading, time
sys.path.insert(0, {str(ROOT)!r})
import httpx
from datetime import datetime, timezone
from pam import pushgate_pam

def cache():
    return {{"username": "alice", "fail_mode": "closed", "updated_at": datetime.now(timezone.utc).isoformat()}}

def handler(request):
    open({str(started)!r}, "a").close()
    if request.url.path.endswith("/consume"):
        open({str(marker)!r}, "w").write("consumed")
        return httpx.Response(200, json={{"data": {{"id": "r1", "status": "approved", "allowed": True,
            "consumed": True, "consumed_at": datetime.now(timezone.utc).isoformat()}}}})
    approved = request.method == "GET" and time.monotonic() > START + 1.5
    status = "approved" if approved else "pending"
    return httpx.Response(201 if request.method == "POST" else 200,
        json={{"data": {{"id": "r1", "status": status, "allowed": approved, "cache": cache()}}}})

START = time.monotonic()
real = httpx.Client
transport = httpx.MockTransport(handler)
pushgate_pam.httpx.Client = lambda **kw: real(base_url=kw["base_url"], transport=transport, timeout=kw.get("timeout", 5.0))
cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", {str(tmp_path / "cache")!r}, timeout=10)
sys.exit(pushgate_pam.authenticate("alice", cfg=cfg))
"""
    )
    # The intermediate shell plays sshd's PAM process: it starts the helper,
    # waits until the login request is in flight, then exits, as it does when
    # LoginGraceTime ends the login while the approver has not answered yet.
    launcher = subprocess.run(
        ["/bin/sh", "-c", f'"{sys.executable}" "{script}" & echo $!; '
                          f'while [ ! -e "{started}" ]; do sleep 0.05; done'],
        capture_output=True, text=True, check=True, timeout=30,
    )
    helper_pid = int(launcher.stdout.strip())
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            os.kill(helper_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(helper_pid, 9)
        pytest.fail("orphaned helper kept running")
    assert not marker.exists()
