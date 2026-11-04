"""PAM helper branches: configuration, cache validation, offline codes, outage
handling, deadlines and the command-line entry point. HTTP uses a mock transport."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pyotp
import pytest

from pam import config_validation, pushgate_pam

SERVER = "https://pushgate.example"
REAL_CLIENT = httpx.Client


def now_iso(delta: float = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat()


def cfg_for(tmp_path: Path, **extra) -> pushgate_pam.AuthConfig:
    options = {"timeout": 5, "system_name": "labbox", "require_cache_binding": True}
    options.update(extra)
    return pushgate_pam.AuthConfig(SERVER, "id", "secret", str(tmp_path / "cache"), **options)


def mock_client(monkeypatch, handler) -> list[httpx.Request]:
    seen: list[httpx.Request] = []
    real = REAL_CLIENT

    def record(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(pushgate_pam.httpx, "Client",
                        lambda **kw: real(base_url=kw["base_url"], transport=httpx.MockTransport(record), timeout=kw.get("timeout", 5.0)))
    return seen


def start_response(status: str, request_id: str = "req-1", username: str = "alice", **extra) -> httpx.Response:
    data = {"id": request_id, "status": status, "allowed": status == "approved",
            "cache": {"username": username, "fail_mode": "closed", "updated_at": now_iso()}, **extra}
    return httpx.Response(201, json={"data": data})


def consume_ack(request_id: str = "req-1") -> httpx.Response:
    return httpx.Response(200, json={"data": {"id": request_id, "status": "approved", "allowed": True, "consumed": True,
                                              "consumed_at": now_iso()}})


def bound_cache(cfg, username: str = "alice", **values) -> dict:
    return {"username": username, "fail_mode": "closed", "updated_at": now_iso(),
            "binding": pushgate_pam.cache_binding(cfg, username, "labbox"), **values}


# --- configuration -----------------------------------------------------------------------------


def test_config_requires_credentials_and_valid_ranges() -> None:
    with pytest.raises(ValueError, match="client ID and secret"):
        pushgate_pam.AuthConfig(SERVER, "", "secret")
    with pytest.raises(ValueError, match="client ID and secret"):
        pushgate_pam.AuthConfig(SERVER, "id", "")
    for bad in (0, 601):
        with pytest.raises(ValueError, match="timeout"):
            pushgate_pam.AuthConfig(SERVER, "id", "secret", timeout=bad)
    for bad in (-1, 604801):
        with pytest.raises(ValueError, match="maximum age"):
            pushgate_pam.AuthConfig(SERVER, "id", "secret", cache_max_age=bad)
    assert pushgate_pam.AuthConfig(SERVER + "/", "id", "secret").server == SERVER


@pytest.mark.parametrize(
    "server",
    ["ftp://pushgate.example", "https://", "https://user:pw@pushgate.example", "https://pushgate.example/api",
     "https://pushgate.example?x=1", "https://pushgate.example#f", "http://10.0.0.5", "http://pushgate.example"],
)
def test_server_url_validation_rejects_unsafe_origins(server: str) -> None:
    with pytest.raises(ValueError):
        config_validation.validate_server_url(server)


@pytest.mark.parametrize("server", ["https://pushgate.example", "http://127.0.0.1:8000", "http://localhost.", "http://[::1]:8000"])
def test_server_url_validation_accepts_tls_and_loopback(server: str) -> None:
    assert config_validation.validate_server_url(server) == server


def test_install_path_and_env_value_decoding() -> None:
    assert config_validation.validate_install_path("dir", "/opt/push-gate_1.0/x:y+z") == "/opt/push-gate_1.0/x:y+z"
    for bad in ("relative/path", "/has space", "/semi;colon", "/dollar$"):
        with pytest.raises(ValueError):
            config_validation.validate_install_path("dir", bad)
    decode = config_validation.decode_env_value
    assert decode('  "a\\"b"  ') == 'a"b'
    assert decode('"unterminated \\"') == 'unterminated \\'
    assert decode('"123"') == "123"
    assert decode("'single'") == "single"
    assert decode("plain") == "plain"
    assert decode('"') == '"'


def test_secure_install_location_walks_ancestors(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(PermissionError, match="absolute"):
        config_validation.validate_secure_install_location("dir", "relative")
    real_lstat = os.lstat

    def as_root(path):
        values = list(real_lstat(path))
        values[4] = 0
        values[0] = values[0] & ~0o022
        return os.stat_result(values)

    monkeypatch.setattr(config_validation.os, "lstat", as_root)
    target = tmp_path / "not" / "yet"
    assert config_validation.validate_secure_install_location("dir", str(target)) == str(target)
    monkeypatch.setattr(config_validation.os, "lstat", real_lstat)
    writable = tmp_path / "shared"
    writable.mkdir()
    writable.chmod(0o777)
    with pytest.raises(PermissionError):
        config_validation.validate_secure_install_location("dir", str(writable))
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    monkeypatch.setattr(config_validation.os, "lstat", lambda p: real_lstat(p) if Path(p) == link else as_root(p))
    with pytest.raises(PermissionError, match="symlinks"):
        config_validation.validate_secure_install_location("dir", str(link))

    def foreign(path):
        values = list(as_root(path))
        values[4] = 4242
        return os.stat_result(values)

    monkeypatch.setattr(config_validation.os, "lstat", foreign)
    with pytest.raises(PermissionError, match="root-owned"):
        config_validation.validate_secure_install_location("dir", str(tmp_path))
    monkeypatch.setattr(Path, "exists", lambda self: False)
    with pytest.raises(FileNotFoundError):
        config_validation.validate_secure_install_location("dir", "/a/b")


def test_config_validation_cli(monkeypatch, capsys) -> None:
    base = ["prog", "--server", "https://pushgate.example", "--timeout", "70", "--cache-max-age", "86400",
            "--config-dir", "/etc/pushgate", "--cache-dir", "/var/cache/pushgate", "--venv-dir", "/opt/pg",
            "--libexec-dir", "/usr/local/libexec"]
    monkeypatch.setattr(sys, "argv", base)
    assert config_validation.main() == 0
    monkeypatch.setattr(sys, "argv", base[:2] + ["http://pushgate.example"] + base[3:])
    with pytest.raises(SystemExit) as exited:
        config_validation.main()
    assert exited.value.code == 2 and "HTTPS" in capsys.readouterr().err
    checked = []
    monkeypatch.setattr(config_validation, "validate_secure_install_location", lambda label, path: checked.append(path) or path)
    monkeypatch.setattr(sys, "argv", base + ["--require-root-owned-paths"])
    assert config_validation.main() == 0
    assert checked == ["/etc/pushgate", "/var/cache/pushgate", "/opt/pg", "/usr/local/libexec"]


def test_secure_config_and_cache_path_walks(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(PermissionError, match="absolute"):
        pushgate_pam.validate_secure_config_file("relative.env")
    with pytest.raises(PermissionError, match="absolute"):
        pushgate_pam.validate_secure_cache_location(Path("relative"))
    real_lstat = os.lstat
    config = tmp_path / "pushgate.env"
    config.write_text("X=1\n")
    config.chmod(0o600)

    def rooted(mode_mask: int = 0o022, parent_mode: int | None = None):
        def fake(path):
            values = list(real_lstat(path))
            values[4] = 0
            if Path(path) != config:
                values[0] = (values[0] & ~0o7777) | (parent_mode if parent_mode is not None else (values[0] & 0o7777 & ~mode_mask))
            return os.stat_result(values)
        return fake

    monkeypatch.setattr(pushgate_pam.os, "lstat", rooted())
    pushgate_pam.validate_secure_config_file(str(config))
    monkeypatch.setattr(pushgate_pam.os, "lstat", rooted(parent_mode=0o777))
    with pytest.raises(PermissionError, match="parent directories"):
        pushgate_pam.validate_secure_config_file(str(config))

    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)

    def cache_meta(cache_mode: int, parent_mode: int | None = None, owner: int = 0):
        def fake(path):
            values = list(real_lstat(path))
            values[4] = owner
            if Path(path) == cache:
                values[0] = stat.S_IFDIR | cache_mode
            elif parent_mode is not None:
                values[0] = stat.S_IFDIR | parent_mode
            else:
                values[0] = values[0] & ~0o022
            return os.stat_result(values)
        return fake

    monkeypatch.setattr(pushgate_pam.os, "lstat", cache_meta(0o700))
    pushgate_pam.validate_secure_cache_location(cache)
    pushgate_pam.validate_secure_cache_location(cache / "later" / "deeper")
    monkeypatch.setattr(pushgate_pam.os, "lstat", cache_meta(0o750))
    with pytest.raises(PermissionError, match="0700"):
        pushgate_pam.validate_secure_cache_location(cache)
    monkeypatch.setattr(pushgate_pam.os, "lstat", cache_meta(0o700, parent_mode=0o777))
    with pytest.raises(PermissionError, match="parent directories"):
        pushgate_pam.validate_secure_cache_location(cache)
    monkeypatch.setattr(pushgate_pam.os, "lstat", cache_meta(0o700, owner=1000))
    with pytest.raises(PermissionError, match="root-owned"):
        pushgate_pam.validate_secure_cache_location(cache)


def test_config_from_env_launcher_mode_and_missing_file(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "custom.env"
    config.write_text('# comment\n\nnot-a-pair\nPUSHGATE_SERVER="https://pushgate.example"\nPUSHGATE_CLIENT_ID=id\n'
                      "PUSHGATE_CLIENT_SECRET='s3cret'\nPUSHGATE_TIMEOUT=30\nPUSHGATE_CACHE_DIR=" + str(tmp_path / "c") + "\n")
    checked = []
    monkeypatch.setattr(pushgate_pam, "validate_secure_config_file", lambda path: checked.append(("config", path)))
    monkeypatch.setattr(pushgate_pam, "validate_secure_cache_location", lambda path: checked.append(("cache", str(path))))
    monkeypatch.delenv("PAM_TYPE", raising=False)
    monkeypatch.setenv("PUSHGATE_PAM_LAUNCHER", "1")
    monkeypatch.setenv("PUSHGATE_PAM_CONFIG", str(config))
    monkeypatch.setenv("PUSHGATE_CLIENT_SECRET", "from-env-is-ignored")
    cfg = pushgate_pam.config_from_env()
    assert (cfg.client_secret, cfg.timeout, cfg.require_cache_binding) == ("s3cret", 30, True)
    assert checked == [("config", str(config)), ("cache", str(tmp_path / "c"))]
    assert pushgate_pam.read_env_file(str(tmp_path / "absent.env")) == {}


# --- cache files -------------------------------------------------------------------------------


def test_cache_root_must_be_absolute_and_missing_root_reads_as_empty(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="absolute"):
        pushgate_pam.read_cache("relative", "alice")
    assert pushgate_pam.read_cache(tmp_path / "absent", "alice") is None
    assert pushgate_pam.read_cache(tmp_path, "nobody") is None


def test_cache_file_must_be_private_bounded_and_bound_to_the_user(tmp_path: Path) -> None:
    pushgate_pam.write_cache(tmp_path, "alice", {"fail_mode": "open", "updated_at": now_iso()})
    path = pushgate_pam.cache_path(tmp_path, "alice")
    path.chmod(0o644)
    with pytest.raises(PermissionError, match="private regular file"):
        pushgate_pam.read_cache(tmp_path, "alice")
    path.chmod(0o600)
    path.write_text(json.dumps({"username": "mallory"}))
    with pytest.raises(ValueError, match="binding mismatch"):
        pushgate_pam.read_cache(tmp_path, "alice")
    path.write_text("[]")
    with pytest.raises(ValueError, match="binding mismatch"):
        pushgate_pam.read_cache(tmp_path, "alice")
    path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="too large"):
        pushgate_pam.read_cache(tmp_path, "alice")


@pytest.mark.parametrize(
    "existing",
    [
        {"backup_code_tombstones": ["h"]},
        {"backup_code_tombstones": {"": now_iso()}},
        {"backup_code_tombstones": {"h": 5}},
        {"backup_code_tombstones": {"h": "not a time"}},
        {"backup_code_tombstones": {"h": "2026-01-01T00:00:00"}},
        {"used_backup_code_hashes": "h"},
        {"used_backup_code_hashes": [""]},
    ],
)
def test_malformed_tombstones_fail_closed(tmp_path: Path, existing: dict) -> None:
    path = pushgate_pam.cache_path(tmp_path, "alice")
    pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso()})
    path.write_text(json.dumps({"username": "alice", "updated_at": now_iso(), **existing}))
    with pytest.raises(ValueError):
        pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso()})


def test_snapshot_merge_rules(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="backup-code hashes"):
        pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso(), "backup_code_hashes": "x"}, authoritative_snapshot=True)
    with pytest.raises(ValueError, match="ISO-8601"):
        pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": None}, authoritative_snapshot=True)
    first = pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso(), "last_totp_counter": 9, "backup_code_hashes": ["a", "b"]},
                                     authoritative_snapshot=True)
    assert first["server_snapshot_at"]
    # An older snapshot never replaces a newer accepted one.
    older = pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso(-60), "backup_code_hashes": ["z"]}, authoritative_snapshot=True)
    assert older["backup_code_hashes"] == ["a", "b"]
    # A local (non-snapshot) write keeps the accepted watermark and the highest TOTP counter.
    local = pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso(), "last_totp_counter": 3, "backup_code_hashes": ["a", "b"],
                                                          "backup_code_tombstones": {"a": now_iso()}})
    assert local["server_snapshot_at"] == first["server_snapshot_at"]
    assert local["last_totp_counter"] == 9 and local["backup_code_hashes"] == ["b"] and local["used_backup_code_hashes"] == ["a"]
    # Without any tombstones left, the bookkeeping keys disappear.
    newest = pushgate_pam.write_cache(tmp_path, "alice", {"updated_at": now_iso(5), "backup_code_hashes": ["c"]}, authoritative_snapshot=True)
    assert "backup_code_tombstones" not in newest and "used_backup_code_hashes" not in newest


def test_cache_freshness_edges() -> None:
    fresh = pushgate_pam.cache_is_fresh
    now = time.time()
    assert fresh(None) is False
    assert fresh({"updated_at": now_iso()}, max_age=0) is False
    assert fresh({}) is False
    assert fresh({"updated_at": "garbage"}) is False
    assert fresh({"updated_at": "2026-01-01T00:00:00"}) is False  # naive timestamps are never trusted
    assert fresh({"updated_at": now_iso(299)}, now=now) is True  # small forward clock skew is tolerated
    assert fresh({"updated_at": now_iso(400)}, now=now) is False
    assert fresh({"updated_at": now_iso(-100)}, max_age=60, now=now) is False


# --- offline codes -----------------------------------------------------------------------------


def test_offline_code_matching(tmp_path: Path) -> None:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    cache = {"username": "alice", "updated_at": now_iso(), "totp_secret": secret, "backup_code_hashes": [pushgate_pam.hash_value("BACKUP1")]}
    assert pushgate_pam.offline_code_kind(cache, totp.now()) == "totp"
    assert pushgate_pam.offline_code_kind(cache, "BACKUP1") == "backup_code"
    assert pushgate_pam.offline_code_kind(cache, "nope") is None
    assert pushgate_pam.offline_code_kind(cache, "") is None
    assert pushgate_pam.offline_code_kind({**cache, "updated_at": now_iso(-90000)}, "BACKUP1") is None
    spent = {**cache, "last_totp_counter": int(time.time()) // 30 + 1, "used_backup_code_hashes": [pushgate_pam.hash_value("BACKUP1")]}
    assert pushgate_pam.offline_code_kind(spent, totp.now()) is None
    assert pushgate_pam.offline_code_kind(spent, "BACKUP1") is None
    assert pushgate_pam.consume_offline_code(tmp_path, "alice", None) is False


def test_offline_decision_requires_a_matching_binding(tmp_path: Path) -> None:
    cfg = cfg_for(tmp_path)
    binding = pushgate_pam.cache_binding(cfg, "alice", "labbox")
    cache = {"username": "alice", "fail_mode": "open", "updated_at": now_iso(), "binding": {**binding, "client_id": "other"}}
    pushgate_pam.write_cache(cfg.cache_dir, "alice", cache)
    assert pushgate_pam.offline_decision(cfg.cache_dir, "alice", cache, None, expected_binding=binding, binding_required=True) == 1
    # A valid binding on the caller's copy but not on disk still refuses to spend a code.
    good = {**cache, "binding": binding, "backup_code_hashes": [pushgate_pam.hash_value("CODE")]}
    assert pushgate_pam.consume_offline_code(cfg.cache_dir, "alice", "CODE", expected_binding=binding, binding_required=True) is False
    assert pushgate_pam.offline_decision(cfg.cache_dir, "alice", good, "CODE", expected_binding=binding, binding_required=True) == 0


def test_stdin_offline_code(monkeypatch) -> None:
    class Closed(io.StringIO):
        closed = True

    class Tty(io.StringIO):
        def isatty(self):
            return True

    class Broken(io.StringIO):
        def read(self, *_a):
            raise OSError("gone")

    for stream, expected in ((Closed("x"), None), (Tty("x"), None), (Broken(), None), (io.StringIO("  \n"), None),
                             (io.StringIO(" 123456\n"), "123456")):
        monkeypatch.setattr(sys, "stdin", stream)
        assert pushgate_pam.stdin_offline_code() == expected


# --- online flow -------------------------------------------------------------------------------


def test_pending_then_approved_poll_is_consumed(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _s: None)
    polls = iter(["pending", "approved"])

    def handler(request):
        if request.method == "POST" and request.url.path == "/api/v1/auth/requests":
            return start_response("pending")
        if request.method == "GET":
            return start_response(next(polls))
        return consume_ack()

    seen = mock_client(monkeypatch, handler)
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0
    assert [r.method for r in seen] == ["POST", "GET", "GET", "POST"]
    assert pushgate_pam.read_cache(cfg.cache_dir, "alice")["binding"]["system"] == "labbox"


def test_denied_poll_and_poll_errors_deny(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _s: None)
    for poll in (start_response("denied"), httpx.Response(404, json={}), httpx.Response(500)):
        def handler(request, poll=poll):
            return start_response("pending") if request.method == "POST" else poll

        mock_client(monkeypatch, handler)
        assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_start_response_must_be_bound_and_well_formed(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    for body in ([], {"data": []}, {"data": {"id": "r", "status": 5, "cache": {"username": "alice"}}},
                 {"data": {"id": "r", "status": "approved", "cache": {"username": "mallory"}}}):
        mock_client(monkeypatch, lambda _r, body=body: httpx.Response(201, json=body))
        assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_poll_loop_stops_at_the_deadline(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path, timeout=1)
    clock = [1000.0]
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: clock[0])

    def sleep(seconds):
        clock[0] += seconds

    monkeypatch.setattr(pushgate_pam.time, "sleep", sleep)
    seen = mock_client(monkeypatch, lambda r: start_response("pending"))
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert [r.method for r in seen] == ["POST", "GET"]


def test_poll_returning_after_deadline_is_not_trusted(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path, timeout=2)
    clock = [1000.0]
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))

    def handler(request):
        if request.method == "GET":
            clock[0] += 0.4
        return start_response("pending")

    seen = mock_client(monkeypatch, handler)
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert sum(r.method == "GET" for r in seen) >= 2


def test_zero_remaining_time_never_contacts_the_server(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path, timeout=1)
    ticks = iter([0.0, 0.0, 5.0, 5.0, 5.0])
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: next(ticks))
    seen = mock_client(monkeypatch, lambda r: start_response("approved"))
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert seen == []


def test_consume_with_no_time_left_is_refused(tmp_path: Path, monkeypatch) -> None:
    client = httpx.Client(base_url=SERVER, transport=httpx.MockTransport(lambda r: consume_ack()))
    assert pushgate_pam._consume_approved_request(client, cfg_for(tmp_path), "req-1", time.monotonic() - 1) is False


@pytest.mark.parametrize("late", [lambda r: httpx.Response(503), lambda r: (_ for _ in ()).throw(httpx.ConnectError("down", request=r))],
                         ids=["503", "connect"])
def test_outage_signal_after_deadline_never_uses_fail_open_cache(tmp_path: Path, monkeypatch, late) -> None:
    cfg = cfg_for(tmp_path, timeout=1)
    pushgate_pam.write_cache(cfg.cache_dir, "alice", bound_cache(cfg, fail_mode="open"))
    clock = [1000.0]
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: clock[0])

    def slow(request):
        clock[0] += 5  # the outage is only observed after the PAM deadline
        return late(request)

    mock_client(monkeypatch, slow)
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    # The same outage inside the deadline does use the fresh fail-open cache.
    mock_client(monkeypatch, late)
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0


def test_outage_with_unreadable_cache_denies(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    pushgate_pam.write_cache(cfg.cache_dir, "alice", bound_cache(cfg, fail_mode="open"))
    real_read = pushgate_pam.read_cache
    calls = {"n": 0}

    def flaky(cache_dir, username):
        calls["n"] += 1
        if calls["n"] > 1:
            raise PermissionError("cache replaced")
        return real_read(cache_dir, username)

    monkeypatch.setattr(pushgate_pam, "read_cache", flaky)
    mock_client(monkeypatch, lambda r: httpx.Response(503))
    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_offline_totp_during_outage_is_single_use(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    secret = pyotp.random_base32()
    pushgate_pam.write_cache(cfg.cache_dir, "alice", bound_cache(cfg, totp_secret=secret))
    mock_client(monkeypatch, lambda r: (_ for _ in ()).throw(httpx.ConnectTimeout("down", request=r)))
    code = pyotp.TOTP(secret).now()
    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 0
    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 1


def test_preflight_posts_signed_body(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path, approver_username="bob")
    seen = mock_client(monkeypatch, lambda r: httpx.Response(200, json={"data": {"online_only": True}}))
    assert pushgate_pam.preflight("alice", cfg=cfg) == {"online_only": True}
    request = seen[0]
    assert json.loads(request.content) == {"approver_username": "bob", "system": "labbox", "username": "alice"}
    expected = pushgate_pam.integration_signature("secret", "POST", "/api/v1/auth/preflight", request.content,
                                                  request.headers["x-pushgate-timestamp"], request.headers["x-pushgate-nonce"])
    assert request.headers["x-pushgate-signature"] == expected


# --- command line ------------------------------------------------------------------------------


def test_main_requires_a_user(monkeypatch, capsys) -> None:
    monkeypatch.delenv("PAM_USER", raising=False)
    assert pushgate_pam.main([]) == 1
    assert "missing PAM user" in capsys.readouterr().err


def test_main_preflight_prints_json_or_reports_failure(tmp_path: Path, monkeypatch, capsys) -> None:
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(pushgate_pam, "config_from_env", lambda: cfg)
    monkeypatch.setattr(pushgate_pam, "preflight", lambda user, cfg=None: {"user": user})
    assert pushgate_pam.main(["--user", "alice", "--preflight"]) == 0
    assert json.loads(capsys.readouterr().out) == {"user": "alice"}

    def failing(user, cfg=None):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(pushgate_pam, "preflight", failing)
    assert pushgate_pam.main(["--user", "alice", "--preflight"]) == 2
    assert "PushGate preflight failed: ConnectError" in capsys.readouterr().err


def test_main_forwards_a_locally_valid_stdin_code_only(tmp_path: Path, monkeypatch) -> None:
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(pushgate_pam, "config_from_env", lambda: cfg)
    monkeypatch.setenv("PAM_TYPE", "auth")
    monkeypatch.setattr(pushgate_pam.os, "uname", lambda: os.uname_result(("Linux", "labbox", "", "", "")))
    pushgate_pam.write_cache(cfg.cache_dir, "alice", bound_cache(cfg, backup_code_hashes=[pushgate_pam.hash_value("GOODCODE")]))
    seen = []
    monkeypatch.setattr(pushgate_pam, "authenticate", lambda user, service, source, offline_code=None, cfg=None: seen.append(offline_code) or 0)
    for typed in ("GOODCODE\n", "the-users-password\n"):
        monkeypatch.setattr(pushgate_pam, "stdin_offline_code", lambda typed=typed: typed.strip())
        pushgate_pam.main(["--user", "alice"])
    # The primary password on stdin is never sent to the server.
    assert seen == ["GOODCODE", None]

    def unreadable(cache_dir, username):
        raise PermissionError("bad cache")

    monkeypatch.setattr(pushgate_pam, "read_cache", unreadable)
    assert pushgate_pam.main(["--user", "alice"]) == 1
