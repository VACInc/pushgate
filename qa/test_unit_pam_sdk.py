from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pyotp
import pytest

from pam import pushgate_pam
from pam.pushgate_pam import AuthConfig, authenticate
from pam.pushgate_pam import consume_offline_code, hash_value, read_cache, read_env_file, write_cache
from qa import pam_live_smoke
from pushgate import PushGateAdminClient, PushGateProtocolError
from pushgate import client as pushgate_client_module


def test_pam_cache_does_not_resurrect_consumed_backup_codes(tmp_path):
    first = hash_value("FIRST-CODE")
    second = hash_value("SECOND-CODE")

    write_cache(tmp_path, "../operator:name", {"username": "operator", "fail_mode": "closed", "backup_code_hashes": [first]})
    assert consume_offline_code(tmp_path, "../operator:name", "FIRST-CODE") is True
    assert consume_offline_code(tmp_path, "../operator:name", "FIRST-CODE") is False

    write_cache(tmp_path, "../operator:name", {"username": "operator", "fail_mode": "closed", "backup_code_hashes": [first, second]})
    cache = read_cache(tmp_path, "../operator:name")
    assert cache is not None
    assert first not in cache["backup_code_hashes"]
    assert first in cache["used_backup_code_hashes"]
    assert consume_offline_code(tmp_path, "../operator:name", "SECOND-CODE") is True


def test_pam_totp_and_env_file_parsing(tmp_path):
    secret = pyotp.random_base32()
    write_cache(tmp_path, "totp-user", {"username": "totp-user", "fail_mode": "closed", "totp_secret": secret})
    assert consume_offline_code(tmp_path, "totp-user", pyotp.TOTP(secret).now()) is True

    env_file = tmp_path / "pushgate.env"
    env_file.write_text(
        """
        # comment
        PUSHGATE_SERVER="https://pushgate.example"
        PUSHGATE_CLIENT_ID='lab-linux'
        PUSHGATE_CLIENT_SECRET = secret-1
        """,
        encoding="utf-8",
    )
    assert read_env_file(str(env_file)) == {
        "PUSHGATE_SERVER": "https://pushgate.example",
        "PUSHGATE_CLIENT_ID": "lab-linux",
        "PUSHGATE_CLIENT_SECRET": "secret-1",
    }


def test_pam_client_rejection_never_uses_fail_open(tmp_path, monkeypatch):
    write_cache(tmp_path, "alice", {"username": "alice", "fail_mode": "open"})
    real_client = httpx.Client

    for status_code in (400, 403, 429):
        transport = httpx.MockTransport(lambda _request, status=status_code: httpx.Response(status, json={"detail": {"code": "rejected"}}))
        monkeypatch.setattr(
            pushgate_pam.httpx,
            "Client",
            lambda **kwargs: real_client(base_url=kwargs["base_url"], transport=transport),
        )
        cfg = AuthConfig("https://pushgate.invalid", "id", "secret", str(tmp_path), timeout=1)
        assert authenticate("alice", cfg=cfg) == 1


def test_live_pam_smoke_uses_the_fixed_sshd_pam_service():
    config = pam_live_smoke.sshd_config(2222)
    assert "PAMServiceName" not in config
    assert "Port 2222" in config
    assert pam_live_smoke.SSHD_PAM_FILE == pam_live_smoke.Path("/etc/pam.d/sshd")
    assert "--service sshd" in pam_live_smoke.sshd_pam_stack()


def test_live_pam_offline_cache_prime_uses_principal_bound_integration(monkeypatch):
    calls: list[tuple] = []

    class Admin:
        def create_integration(self, name, **kwargs):
            calls.append(("create", name, kwargs))
            return {"client_id": kwargs["client_id"], "secret": "secret"}

    monkeypatch.setattr(pam_live_smoke, "write_config", lambda base_url, integration: calls.append(("config", base_url, integration)))
    monkeypatch.setattr(pam_live_smoke, "run_pam_decision", lambda *args: calls.append(("prime", *args)))
    admin = Admin()
    device = {"id": "closed-phone"}

    integration = pam_live_smoke.prime_principal_bound_cache(admin, "http://127.0.0.1:8000", "closeduser", device)

    assert calls[0] == (
        "create",
        "pam-live-offline-closeduser",
        {
            "client_id": "pam-live-offline-closeduser",
            "fail_mode": "closed",
            "principal_username": "closeduser",
        },
    )
    assert calls[1][0:2] == ("config", "http://127.0.0.1:8000")
    assert calls[2] == ("prime", admin, "http://127.0.0.1:8000", "cache-prime", "closeduser", device, "approve", 0)
    assert integration == {"client_id": "pam-live-offline-closeduser", "secret": "secret"}


def test_live_pam_outage_checks_restore_each_cache_integration(monkeypatch):
    calls: list[tuple] = []
    open_integration = {"client_id": "pam-live-linux", "secret": "open-secret"}
    closed_integration = {"client_id": "pam-live-offline-closeduser", "secret": "closed-secret"}

    monkeypatch.setattr(pam_live_smoke, "write_config", lambda base_url, integration: calls.append(("config", base_url, integration)))
    monkeypatch.setattr(
        pam_live_smoke,
        "pam_start",
        lambda service, username, stdin=None: calls.append(("start", service, username, stdin)) or f"{service}:{username}",
    )
    monkeypatch.setattr(
        pam_live_smoke,
        "wait_pam",
        lambda proc, expected, label, stdin=None: calls.append(("wait", proc, expected, label, stdin)),
    )

    pam_live_smoke.run_offline_outage_checks(
        "http://127.0.0.1:8000",
        open_integration,
        closed_integration,
        "BACKUP-CODE",
    )

    assert calls == [
        ("config", "http://127.0.0.1:8000", open_integration),
        ("start", "cache-prime", "openuser", None),
        ("wait", "cache-prime:openuser", 0, "offline fail-open", None),
        ("config", "http://127.0.0.1:8000", closed_integration),
        ("start", "cache-prime", "closeduser", None),
        ("wait", "cache-prime:closeduser", 1, "offline fail-closed", None),
        ("start", "login", "closeduser", "BACKUP-CODE\n"),
        ("wait", "login:closeduser", 0, "offline backup code", "BACKUP-CODE\n"),
    ]


def test_live_pam_smoke_requires_explicit_marker_verified_lima(monkeypatch, tmp_path):
    cidata = tmp_path / "lima-cidata"
    cidata.mkdir()
    (cidata / "lima.env").write_text("LIMA_CIDATA_IID=test\n", encoding="utf-8")
    boot_marker = tmp_path / "lima-boot-done"
    boot_marker.write_text("test\n", encoding="utf-8")
    monkeypatch.setattr(pam_live_smoke, "LIMA_CIDATA_DIR", cidata)
    monkeypatch.setattr(pam_live_smoke, "LIMA_BOOT_MARKER", boot_marker)
    monkeypatch.setattr(pam_live_smoke.Path, "exists", lambda self: False)
    monkeypatch.setattr(pam_live_smoke.os.path, "ismount", lambda _path: True)

    monkeypatch.delenv(pam_live_smoke.DISPOSABLE_ACK, raising=False)
    assert pam_live_smoke.is_disposable_runtime() is False
    monkeypatch.setenv(pam_live_smoke.DISPOSABLE_ACK, "1")
    assert pam_live_smoke.is_disposable_runtime() is True


def test_live_pam_smoke_requires_explicit_marker_in_container(monkeypatch):
    monkeypatch.setattr(
        pam_live_smoke.Path,
        "exists",
        lambda self: str(self) == "/.dockerenv",
    )
    monkeypatch.setattr(pam_live_smoke.os.path, "ismount", lambda _path: False)

    monkeypatch.delenv(pam_live_smoke.DISPOSABLE_ACK, raising=False)
    assert pam_live_smoke.is_disposable_runtime() is False
    monkeypatch.setenv(pam_live_smoke.DISPOSABLE_ACK, "1")
    assert pam_live_smoke.is_disposable_runtime() is True


def test_live_pam_decision_stops_child_when_request_lookup_fails(monkeypatch):
    process = object()
    stopped = []
    monkeypatch.setattr(pam_live_smoke, "pam_start", lambda *_args: process)
    monkeypatch.setattr(
        pam_live_smoke,
        "wait_pending",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing request")),
    )
    monkeypatch.setattr(pam_live_smoke, "stop_process", stopped.append)

    with pytest.raises(RuntimeError, match="missing request"):
        pam_live_smoke.run_pam_decision(
            object(), "http://127.0.0.1:1", "sudo", "alice", {}, "deny", 1
        )

    assert stopped == [process]


def test_sdk_formats_requests_and_handles_empty_deletes():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json={"data": [{"id": "log-1"}]})

    admin = PushGateAdminClient("https://pushgate.example/", "token-1")
    admin.client.close()
    admin.client = httpx.Client(
        base_url="https://pushgate.example",
        headers={"Authorization": "Bearer token-1"},
        transport=httpx.MockTransport(handler),
    )
    try:
        logs = admin.auth_logs(user="alice", system="labbox", result="denied", from_time=datetime(2026, 6, 17, tzinfo=timezone.utc), limit=25, offset=50)
        assert logs == [{"id": "log-1"}]
        request = seen[-1]
        assert request.method == "GET"
        assert request.url.path == "/api/admin/auth-logs"
        assert request.url.params["user"] == "alice"
        assert request.url.params["system"] == "labbox"
        assert request.url.params["result"] == "denied"
        assert request.url.params["from"] == "2026-06-17T00:00:00+00:00"
        assert request.url.params["limit"] == "25"
        assert request.url.params["offset"] == "50"
        assert request.headers["authorization"] == "Bearer token-1"

        assert admin.delete_backup_code("code-1") is None
        assert seen[-1].method == "DELETE"
        assert seen[-1].url.path == "/api/admin/backup-codes/code-1"

        admin.create_integration("proxy", client_id="proxy", fail_mode="closed", system_type="proxy")
        request = seen[-1]
        assert request.method == "POST"
        assert request.url.path == "/api/admin/integrations"
        assert json.loads(request.content) == {
            "name": "proxy",
            "client_id": "proxy",
            "fail_mode": "closed",
            "system_type": "proxy",
            "enabled": True,
        }
    finally:
        admin.close()


def test_sdk_requires_safe_transport_configuration():
    with pytest.raises(ValueError, match="plain HTTP"):
        PushGateAdminClient("http://pushgate.example", "token-1")
    with pytest.raises(ValueError, match="credentials"):
        PushGateAdminClient("https://" + "user:password@pushgate.example", "token-1")
    for base_url in (
        "https://pushgate.example/api",
        "https://pushgate.example?tenant=one",
        "https://pushgate.example#admin",
    ):
        with pytest.raises(ValueError, match="path, query, or fragment"):
            PushGateAdminClient(base_url, "token-1")
    with pytest.raises(ValueError, match="visible ASCII"):
        PushGateAdminClient("https://pushgate.example", "token-1\r\nX-Evil: yes")
    for timeout in (0, -1, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="positive finite"):
            PushGateAdminClient("https://pushgate.example", "token-1", timeout=timeout)

    with PushGateAdminClient("http://127.0.0.1:8000", "token-1") as loopback:
        assert str(loopback.client.base_url) == "http://127.0.0.1:8000"
    with PushGateAdminClient("http://pushgate.example", "token-1", allow_insecure=True) as explicit:
        assert str(explicit.client.base_url) == "http://pushgate.example"


def test_sdk_does_not_follow_redirects_or_leak_auth_header(monkeypatch):
    requests: list[httpx.Request] = []
    constructor: dict[str, object] = {}
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://attacker.invalid/collect"})

    def client_factory(**kwargs):
        constructor.update(kwargs)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(pushgate_client_module.httpx, "Client", client_factory)
    admin = PushGateAdminClient("https://pushgate.example", "super-secret-token")
    try:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            admin.users()
        assert len(requests) == 1
        assert requests[0].url.host == "pushgate.example"
        assert requests[0].headers["authorization"] == "Bearer super-secret-token"
        assert "super-secret-token" not in str(raised.value)
        assert "super-secret-token" not in repr(admin)
        assert constructor["follow_redirects"] is False
        assert constructor["trust_env"] is False
        assert constructor["verify"] is True
    finally:
        admin.close()


@pytest.mark.parametrize("identifier", ("", ".", "..", "user/../../settings", "user?admin=true", "user#fragment"))
def test_sdk_rejects_path_identifier_injection(identifier):
    admin = PushGateAdminClient("https://pushgate.example", "token-1")
    try:
        with pytest.raises(ValueError, match="path identifier"):
            admin.get_user(identifier)
    finally:
        admin.close()


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (httpx.Response(200, text="sensitive-body-token"), "non-JSON"),
        (
            httpx.Response(200, content=b"not-json-sensitive-body-token", headers={"Content-Type": "application/json"}),
            "malformed JSON",
        ),
        (httpx.Response(200, json={"unexpected": "sensitive-body-token"}), "missing its data envelope"),
    ),
)
def test_sdk_rejects_invalid_success_responses_without_echoing_body(response, message):
    admin = PushGateAdminClient("https://pushgate.example", "token-1")
    admin.client.close()
    admin.client = httpx.Client(
        base_url="https://pushgate.example",
        transport=httpx.MockTransport(lambda _request: response),
    )
    try:
        with pytest.raises(PushGateProtocolError, match=message) as raised:
            admin.users()
        assert "sensitive-body-token" not in str(raised.value)
        assert raised.value.__context__ is None
    finally:
        admin.close()


def test_sdk_permissions_are_explicit_boolean_and_fail_closed():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"data": {"id": "role-1"}})

    admin = PushGateAdminClient("https://pushgate.example", "token-1")
    admin.client.close()
    admin.client = httpx.Client(
        base_url="https://pushgate.example",
        transport=httpx.MockTransport(handler),
    )
    try:
        admin.create_role("no-access", {})
        assert json.loads(requests[-1].content)["permissions"] == {"read": False, "write": False, "admin": False}

        admin.update_role("role-1", permissions={"admin": True})
        assert json.loads(requests[-1].content)["permissions"] == {"read": False, "write": False, "admin": True}

        with pytest.raises(TypeError, match="booleans"):
            admin.create_role("ambiguous", {"admin": "false"})
        with pytest.raises(ValueError, match="unknown permissions"):
            admin.create_role("unknown", {"owner": True})
    finally:
        admin.close()
