from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import httpx
import pyotp
import pytest

from pam import pushgate_pam
from pam import config_validation


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "pam" / "install.sh"


def _cache(username: str, fail_mode: str = "closed", **values):
    return {
        "username": username,
        "fail_mode": fail_mode,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **values,
    }


def _consume_ack(request_id: str):
    return {
        "data": {
            "id": request_id,
            "status": "approved",
            "allowed": True,
            "consumed": True,
            "consumed_at": datetime.now(timezone.utc).isoformat(),
        }
    }


def _mock_client(monkeypatch, handler):
    real_client = httpx.Client
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        pushgate_pam.httpx,
        "Client",
        lambda **kwargs: real_client(base_url=kwargs["base_url"], transport=transport, timeout=kwargs.get("timeout", 5.0)),
    )


def test_pam_context_ignores_untrusted_configuration_environment(tmp_path, monkeypatch):
    config = tmp_path / "pushgate.env"
    cache_dir = tmp_path / "cache"
    config.write_text(
        "\n".join(
            [
                "PUSHGATE_SERVER=https://real.example",
                "PUSHGATE_CLIENT_ID=real-id",
                "PUSHGATE_CLIENT_SECRET=real-secret",
                f"PUSHGATE_CACHE_DIR={cache_dir}",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(pushgate_pam, "DEFAULT_CONFIG_FILE", str(config))
    monkeypatch.setattr(pushgate_pam, "validate_secure_config_file", lambda _path: None)
    monkeypatch.setattr(pushgate_pam, "validate_secure_cache_location", lambda _path: None)
    monkeypatch.setenv("PAM_TYPE", "auth")
    monkeypatch.setenv("PUSHGATE_SERVER", "http://127.0.0.1:9")
    monkeypatch.setenv("PUSHGATE_PAM_CONFIG", str(tmp_path / "attacker.env"))
    monkeypatch.setenv("PUSHGATE_CLIENT_ID", "attacker-id")
    monkeypatch.setenv("PUSHGATE_CLIENT_SECRET", "attacker-secret")
    monkeypatch.setenv("PUSHGATE_CACHE_DIR", str(tmp_path / "attacker-cache"))

    cfg = pushgate_pam.config_from_env()

    assert cfg.server == "https://real.example"
    assert cfg.client_id == "real-id"
    assert cfg.client_secret == "real-secret"
    assert cfg.cache_dir == cache_dir


def _run_installer(*arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(INSTALLER),
            "--server",
            "https://pushgate.example",
            "--client-id",
            "client-id",
            "--client-secret",
            "test-secret",
            "--dry-run",
            *arguments,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    "server",
    [
        "https://pushgate.example",
        "https://pushgate.example/",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_installer_accepts_runtime_safe_server_origins(server):
    result = _run_installer("--server", server)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "server",
    [
        "http://pushgate.example",
        "https://" + "user:password@pushgate.example",
        "https://pushgate.example/api",
        "https://pushgate.example?tenant=lab",
        "https://pushgate.example#fragment",
        "ftp://pushgate.example",
        "https://",
    ],
)
def test_installer_rejects_servers_rejected_by_runtime(server):
    result = _run_installer("--server", server)

    assert result.returncode == 2


@pytest.mark.parametrize(
    ("option", "accepted", "rejected"),
    [
        ("--timeout", ("1", "600"), ("0", "601")),
        ("--cache-max-age", ("0", "604800"), ("604801",)),
    ],
)
def test_installer_enforces_runtime_numeric_boundaries(option, accepted, rejected):
    for value in accepted:
        result = _run_installer(option, value)
        assert result.returncode == 0, result.stderr
    for value in rejected:
        result = _run_installer(option, value)
        assert result.returncode == 2


def test_installer_launcher_supports_nondefault_secure_config_dir(tmp_path, monkeypatch):
    config_dir = tmp_path / "custom-config"
    result = _run_installer(env={**os.environ, "CONFIG_DIR": str(config_dir)})
    assert result.returncode == 0, result.stderr
    assert f"using config {config_dir}/pushgate.env" in result.stdout
    assert "config_validation.py" in result.stdout

    config_dir.mkdir()
    config = config_dir / "pushgate.env"
    cache_dir = tmp_path / "cache"
    config.write_text(
        "\n".join(
            [
                "PUSHGATE_SERVER=https://custom.example",
                "PUSHGATE_CLIENT_ID=custom-id",
                "PUSHGATE_CLIENT_SECRET=custom-secret",
                f"PUSHGATE_CACHE_DIR={cache_dir}",
            ]
        ),
        encoding="utf-8",
    )
    validated = []
    monkeypatch.setenv("PUSHGATE_PAM_LAUNCHER", "1")
    monkeypatch.setenv("PUSHGATE_PAM_CONFIG", str(config))
    monkeypatch.setenv("PUSHGATE_SERVER", "https://attacker.example")
    monkeypatch.setattr(pushgate_pam, "validate_secure_config_file", validated.append)
    monkeypatch.setattr(pushgate_pam, "validate_secure_cache_location", lambda _path: None)

    cfg = pushgate_pam.config_from_env()

    assert validated == [str(config)]
    assert cfg.server == "https://custom.example"
    assert cfg.client_id == "custom-id"


@pytest.mark.parametrize("variable", ["CONFIG_DIR", "VENV_DIR"])
def test_installer_rejects_shell_metacharacters_in_embedded_launcher_paths(tmp_path, variable):
    marker = tmp_path / "injected"
    unsafe_path = f"{tmp_path}/unsafe\";touch${{IFS}}{marker};#"
    result = _run_installer(env={**os.environ, variable: unsafe_path})

    assert result.returncode == 2
    assert "portable shell-safe characters" in result.stderr
    assert not marker.exists()


def test_shared_installer_validation_module_matches_runtime_contract():
    assert config_validation.validate_server_url("https://pushgate.example") == "https://pushgate.example"
    assert config_validation.validate_timeout(600) == 600
    assert config_validation.validate_cache_max_age(604800) == 604800


def test_installer_rejects_cache_path_rejected_by_runtime():
    result = _run_installer(env={**os.environ, "CACHE_DIR": "relative-cache"})

    assert result.returncode == 2
    assert "absolute path" in result.stderr


def test_secure_install_validation_rejects_untrusted_ancestor(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    os.chmod(unsafe, 0o777)

    with pytest.raises(PermissionError, match="root-owned|writable by non-root"):
        config_validation.validate_secure_install_location("PushGate virtualenv directory", str(unsafe / "venv"))


def test_installer_installs_canonical_launcher_in_dry_run():
    result = _run_installer()

    assert result.returncode == 0, result.stderr
    assert "/pushgate_pam using config" in result.stdout
    assert "pushgate_pam.py" in result.stdout


@pytest.mark.parametrize("installed_layout", [False, True])
def test_canonical_helper_runs_under_isolated_mode(tmp_path, installed_layout):
    helper = ROOT / "pam" / "pushgate_pam.py"
    if installed_layout:
        for name in ("pushgate_pam.py", "config_validation.py"):
            shutil.copy2(ROOT / "pam" / name, tmp_path / name)
        helper = tmp_path / "pushgate_pam.py"

    result = subprocess.run(
        [sys.executable, "-I", str(helper), "--help"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "PushGate PAM helper" in result.stdout

    load = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import runpy,sys; module=runpy.run_path(sys.argv[1], run_name='helper_import'); assert callable(module['main'])",
            str(helper),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert load.returncode == 0, load.stderr


def test_json_encoded_installer_values_preserve_literal_quotes(tmp_path):
    client_id = 'client-"quoted"'
    secret = "'quoted-secret'"
    config = tmp_path / "pushgate.env"
    config.write_text(
        f"PUSHGATE_CLIENT_ID={json.dumps(client_id)}\nPUSHGATE_CLIENT_SECRET={json.dumps(secret)}\n",
        encoding="utf-8",
    )

    assert pushgate_pam.read_env_file(str(config)) == {
        "PUSHGATE_CLIENT_ID": client_id,
        "PUSHGATE_CLIENT_SECRET": secret,
    }


def test_non_loopback_plain_http_is_rejected():
    with pytest.raises(ValueError, match="requires HTTPS"):
        pushgate_pam.AuthConfig("http://pushgate.example", "id", "secret")


def test_secure_config_rejects_bad_owner_mode_and_symlink(tmp_path, monkeypatch):
    config = tmp_path / "pushgate.env"
    config.write_text("PUSHGATE_CLIENT_SECRET=secret\n", encoding="utf-8")
    os.chmod(config, 0o600)
    real_lstat = os.lstat

    def with_metadata(*, owner=None, mode=None):
        def fake_lstat(path):
            metadata = real_lstat(path)
            if Path(path) != config:
                return metadata
            values = list(metadata)
            if mode is not None:
                values[0] = stat.S_IFREG | mode
            if owner is not None:
                values[4] = owner
            return os.stat_result(values)

        return fake_lstat

    monkeypatch.setattr(pushgate_pam.os, "lstat", with_metadata(owner=os.geteuid() + 1))
    with pytest.raises(PermissionError, match="root-owned"):
        pushgate_pam.validate_secure_config_file(str(config))

    monkeypatch.setattr(pushgate_pam.os, "lstat", with_metadata(owner=0, mode=0o644))
    with pytest.raises(PermissionError, match="private regular file"):
        pushgate_pam.validate_secure_config_file(str(config))

    monkeypatch.setattr(pushgate_pam.os, "lstat", real_lstat)
    symlink = tmp_path / "pushgate-link.env"
    symlink.symlink_to(config)
    with pytest.raises(PermissionError, match="symlinks"):
        pushgate_pam.validate_secure_config_file(str(symlink))


def test_secure_cache_rejects_bad_owner_mode_and_symlink(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    real_lstat = os.lstat

    def fake_lstat(path):
        metadata = real_lstat(path)
        if Path(path) != cache:
            return metadata
        values = list(metadata)
        values[4] = os.geteuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(pushgate_pam.os, "lstat", fake_lstat)
    with pytest.raises(PermissionError, match="owned by the effective user"):
        pushgate_pam._cache_root(cache)

    monkeypatch.setattr(pushgate_pam.os, "lstat", real_lstat)
    os.chmod(cache, 0o755)
    with pytest.raises(PermissionError, match="0700"):
        pushgate_pam._cache_root(cache)

    os.chmod(cache, 0o700)
    symlink = tmp_path / "cache-link"
    symlink.symlink_to(cache, target_is_directory=True)
    with pytest.raises(PermissionError, match="symlinks"):
        pushgate_pam._cache_root(symlink)


def test_offline_backup_code_is_server_first(tmp_path, monkeypatch):
    code = "ABCD1234"
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", backup_code_hashes=[pushgate_pam.hash_value(code)]))
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            201,
            json={"data": {"id": "r1", "status": "denied", "allowed": False, "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 1
    assert len(seen) == 1


def test_malformed_success_response_fails_closed(tmp_path, monkeypatch):
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "id",
        "secret",
        str(tmp_path),
        timeout=1,
        system_name="labbox",
        require_cache_binding=True,
    )
    cached = _cache("alice", fail_mode="open", binding=pushgate_pam.cache_binding(cfg, "alice", "labbox"))
    pushgate_pam.write_cache(tmp_path, "alice", cached)
    _mock_client(monkeypatch, lambda _request: httpx.Response(201, content=b"not-json"))

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


@pytest.mark.parametrize("malformed_cache", [[], {}, ""])
def test_falsey_malformed_cache_in_success_response_fails_closed(tmp_path, monkeypatch, malformed_cache):
    _mock_client(
        monkeypatch,
        lambda _request: httpx.Response(
            201,
            json={"data": {"id": "r1", "status": "approved", "allowed": True, "cache": malformed_cache}},
        ),
    )
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


@pytest.mark.parametrize("pending_id", ["", None, 7])
def test_malformed_pending_id_denies_before_outage_fallback(tmp_path, monkeypatch, pending_id):
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "id",
        "secret",
        str(tmp_path),
        timeout=1,
        system_name="labbox",
        require_cache_binding=True,
    )
    binding = pushgate_pam.cache_binding(cfg, "alice", "labbox")
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", fail_mode="open", binding=binding))
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                201,
                json={
                    "data": {
                        "id": pending_id,
                        "status": "pending",
                        "allowed": False,
                        "cache": _cache("alice", fail_mode="closed"),
                    }
                },
            )
        return httpx.Response(503)

    _mock_client(monkeypatch, handler)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert len(requests) == 1
    assert pushgate_pam.read_cache(tmp_path, "alice")["fail_mode"] == "open"


def test_poll_response_cannot_switch_auth_request_id(tmp_path, monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                201,
                json={"data": {"id": "request-1", "status": "pending", "allowed": False, "cache": _cache("alice")}},
            )
        if len(requests) == 2:
            return httpx.Response(
                200,
                json={"data": {"id": "request-2", "status": "pending", "allowed": False, "cache": _cache("alice")}},
            )
        return httpx.Response(
            200,
            json={"data": {"id": "request-2", "status": "approved", "allowed": True, "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(pushgate_pam.time, "sleep", lambda _seconds: None)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1
    assert [request.url.path for request in requests] == [
        "/api/v1/auth/requests",
        "/api/v1/auth/requests/request-1",
    ]


def test_auth_start_sends_signed_relative_client_timeout(tmp_path, monkeypatch):
    captured = []

    def handler(request):
        captured.append(request)
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("request-1"))
        return httpx.Response(
            201,
            json={"data": {"id": "request-1", "status": "approved", "allowed": True, "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=2)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0
    request = captured[0]
    payload = json.loads(request.content)
    assert 1.5 <= payload["client_timeout_seconds"] <= 2.0
    assert request.headers["x-pushgate-signature"] == pushgate_pam.integration_signature(
        cfg.client_secret,
        request.method,
        request.url.raw_path.decode("ascii"),
        request.content,
        request.headers["x-pushgate-timestamp"],
        request.headers["x-pushgate-nonce"],
    )
    consume = captured[1]
    assert consume.method == "POST"
    assert consume.url.path == "/api/v1/auth/requests/request-1/consume"
    assert consume.content == b""
    assert consume.headers["x-pushgate-signature"] == pushgate_pam.integration_signature(
        cfg.client_secret,
        consume.method,
        consume.url.raw_path.decode("ascii"),
        b"",
        consume.headers["x-pushgate-timestamp"],
        consume.headers["x-pushgate-nonce"],
    )


@pytest.mark.parametrize("failure", ["http", "malformed", "wrong-id", "not-consumed"])
def test_approved_request_fails_closed_without_valid_consume_ack(tmp_path, monkeypatch, failure):
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", fail_mode="open"))

    def handler(request):
        if not request.url.path.endswith("/consume"):
            return httpx.Response(
                201,
                json={"data": {"id": "request-1", "status": "approved", "allowed": True, "cache": _cache("alice", fail_mode="open")}},
            )
        if failure == "http":
            return httpx.Response(503)
        if failure == "malformed":
            return httpx.Response(200, json={"data": []})
        ack = _consume_ack("other-request" if failure == "wrong-id" else "request-1")
        if failure == "not-consumed":
            ack["data"]["consumed"] = False
        return httpx.Response(200, json=ack)

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_consume_ack_arriving_after_monotonic_deadline_is_rejected(tmp_path, monkeypatch):
    clock = {"now": 0.0}

    def handler(request):
        if request.url.path.endswith("/consume"):
            clock["now"] = 1.01
            return httpx.Response(200, json=_consume_ack("request-1"))
        return httpx.Response(
            201,
            json={"data": {"id": "request-1", "status": "approved", "allowed": True, "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: clock["now"])
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


@pytest.mark.parametrize("delayed_phase", ["start", "poll"])
def test_delayed_auth_response_cannot_approve_after_deadline(tmp_path, monkeypatch, delayed_phase):
    clock = {"now": 0.0}

    def handler(request):
        if delayed_phase == "start" or request.method == "GET":
            clock["now"] = 1.01
            return httpx.Response(
                200 if request.method == "GET" else 201,
                json={"data": {"id": "request-1", "status": "approved", "allowed": True, "cache": _cache("alice")}},
            )
        return httpx.Response(
            201,
            json={"data": {"id": "request-1", "status": "pending", "allowed": False, "cache": _cache("alice")}},
        )

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(pushgate_pam.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        pushgate_pam.time,
        "sleep",
        lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
    )
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_503_uses_fresh_bound_fail_open_cache(tmp_path, monkeypatch):
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "id",
        "secret",
        str(tmp_path),
        timeout=1,
        system_name="labbox",
        require_cache_binding=True,
    )
    cached = _cache("alice", fail_mode="open", binding=pushgate_pam.cache_binding(cfg, "alice", "labbox"))
    pushgate_pam.write_cache(tmp_path, "alice", cached)
    _mock_client(monkeypatch, lambda _request: httpx.Response(503))

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 0


def test_local_protocol_error_never_uses_fail_open_cache(tmp_path, monkeypatch):
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", fail_mode="open"))

    class InvalidRequestClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            raise httpx.LocalProtocolError("invalid local request")

    monkeypatch.setattr(pushgate_pam.httpx, "Client", InvalidRequestClient)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


@pytest.mark.parametrize("invalid_cache", ["stale", "closed", "binding-mismatch"])
def test_503_denies_without_fresh_bound_fail_open_cache(tmp_path, monkeypatch, invalid_cache):
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "id",
        "secret",
        str(tmp_path),
        timeout=1,
        cache_max_age=60,
        system_name="labbox",
        require_cache_binding=True,
    )
    binding = pushgate_pam.cache_binding(cfg, "alice", "labbox")
    cached = _cache("alice", fail_mode="closed" if invalid_cache == "closed" else "open", binding=binding)
    if invalid_cache == "stale":
        cached["updated_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    elif invalid_cache == "binding-mismatch":
        cached["binding"] = {**binding, "client_id": "other-integration"}
    pushgate_pam.write_cache(tmp_path, "alice", cached)
    _mock_client(monkeypatch, lambda _request: httpx.Response(503))

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_403_is_authoritative_with_fresh_bound_fail_open_cache(tmp_path, monkeypatch):
    code = "ABCD1234"
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "id",
        "secret",
        str(tmp_path),
        timeout=1,
        system_name="labbox",
        require_cache_binding=True,
    )
    cached = _cache(
        "alice",
        fail_mode="open",
        binding=pushgate_pam.cache_binding(cfg, "alice", "labbox"),
        backup_code_hashes=[pushgate_pam.hash_value(code)],
    )
    pushgate_pam.write_cache(tmp_path, "alice", cached)
    _mock_client(monkeypatch, lambda _request: httpx.Response(403))

    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 1
    assert pushgate_pam.hash_value(code) in pushgate_pam.read_cache(tmp_path, "alice")["backup_code_hashes"]


def test_pam_context_ignores_offline_code_environment(tmp_path, monkeypatch):
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)
    captured = {}
    monkeypatch.setenv("PAM_TYPE", "auth")
    monkeypatch.setenv("PUSHGATE_OFFLINE_CODE", "attacker-code")
    monkeypatch.setattr(pushgate_pam, "config_from_env", lambda: cfg)
    monkeypatch.setattr(pushgate_pam, "stdin_offline_code", lambda: None)

    def authenticate(_username, _service, _source_ip, offline_code, **_kwargs):
        captured["offline_code"] = offline_code
        return 1

    monkeypatch.setattr(pushgate_pam, "authenticate", authenticate)

    assert pushgate_pam.main(["--user", "alice"]) == 1
    assert captured["offline_code"] is None


def test_poll_outage_uses_latest_closed_cache(tmp_path, monkeypatch):
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", fail_mode="open"))

    def handler(request):
        if request.method == "POST":
            return httpx.Response(
                201,
                json={"data": {"id": "r1", "status": "pending", "allowed": False, "cache": _cache("alice", fail_mode="closed")}},
            )
        raise httpx.ConnectError("poll outage", request=request)

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_stale_fail_open_cache_denies(tmp_path, monkeypatch):
    stale = _cache("alice", fail_mode="open")
    stale["updated_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    pushgate_pam.write_cache(tmp_path, "alice", stale)

    def handler(request):
        raise httpx.ConnectError("outage", request=request)

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1, cache_max_age=60)

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_fail_open_cache_is_bound_to_integration(tmp_path, monkeypatch):
    cached = _cache("alice", fail_mode="open")
    cached["binding"] = {
        "server": "https://pushgate.example",
        "client_id": "other-integration",
        "username": "alice",
        "approver_username": "alice",
        "system": "labbox",
    }
    pushgate_pam.write_cache(tmp_path, "alice", cached)

    def handler(request):
        raise httpx.ConnectError("outage", request=request)

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig(
        "https://pushgate.example",
        "strict-integration",
        "secret",
        str(tmp_path),
        timeout=1,
        system_name="labbox",
        require_cache_binding=True,
    )

    assert pushgate_pam.authenticate("alice", cfg=cfg) == 1


def test_totp_cannot_be_replayed_locally(tmp_path):
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", totp_secret=secret))

    assert pushgate_pam.consume_offline_code(tmp_path, "alice", code) is True
    assert pushgate_pam.consume_offline_code(tmp_path, "alice", code) is False


def test_online_approved_totp_cannot_be_replayed_during_outage(tmp_path, monkeypatch):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    counter = int(datetime.now(timezone.utc).timestamp()) // totp.interval
    code = totp.generate_otp(counter)
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("r1"))
        if len(requests) == 1:
            return httpx.Response(
                201,
                json={
                    "data": {
                        "id": "r1",
                        "status": "approved",
                        "allowed": True,
                        "cache": _cache(
                            "alice",
                            totp_secret=secret,
                            last_totp_counter=counter,
                        ),
                    }
                },
            )
        raise httpx.ConnectError("backend outage", request=request)

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 0
    assert pushgate_pam.read_cache(tmp_path, "alice")["last_totp_counter"] == counter
    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 1


def test_server_consumed_backup_code_survives_later_stale_cache_write(tmp_path, monkeypatch):
    code = "ABCD1234"
    code_hash = pushgate_pam.hash_value(code)
    now = datetime.now(timezone.utc)
    initial_at = (now - timedelta(seconds=3)).isoformat()
    stale_at = (now - timedelta(seconds=2)).isoformat()
    consumed_at = (now - timedelta(seconds=1)).isoformat()
    pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=initial_at, backup_code_hashes=[code_hash]),
    )
    stale_snapshot = _cache("alice", updated_at=stale_at, backup_code_hashes=[code_hash])

    def handler(request):
        if request.url.path.endswith("/consume"):
            return httpx.Response(200, json=_consume_ack("r1"))
        return httpx.Response(
            201,
            json={
                "data": {
                    "id": "r1",
                    "status": "approved",
                    "allowed": True,
                    "cache": _cache("alice", updated_at=consumed_at, backup_code_hashes=[]),
                }
            },
        )

    _mock_client(monkeypatch, handler)
    cfg = pushgate_pam.AuthConfig("https://pushgate.example", "id", "secret", str(tmp_path), timeout=1)

    assert pushgate_pam.authenticate("alice", offline_code=code, cfg=cfg) == 0
    pushgate_pam.write_cache(tmp_path, "alice", stale_snapshot, authoritative_snapshot=True)

    cached = pushgate_pam.read_cache(tmp_path, "alice")
    assert code_hash not in cached["backup_code_hashes"]
    assert code_hash in cached["used_backup_code_hashes"]
    assert pushgate_pam.offline_code_valid(cached, code) is False


def test_newer_snapshot_still_advertising_offline_consumed_code_keeps_tombstone(tmp_path):
    code = "ABCD1234"
    code_hash = pushgate_pam.hash_value(code)
    now = datetime.now(timezone.utc)
    initial_at = (now - timedelta(seconds=2)).isoformat()
    newer_at = (now - timedelta(seconds=1)).isoformat()
    pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=initial_at, backup_code_hashes=[code_hash]),
        authoritative_snapshot=True,
    )
    assert pushgate_pam.consume_offline_code(tmp_path, "alice", code) is True

    cached = pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=newer_at, backup_code_hashes=[code_hash]),
        authoritative_snapshot=True,
    )

    assert code_hash not in cached["backup_code_hashes"]
    assert code_hash in cached["used_backup_code_hashes"]
    assert pushgate_pam.offline_code_valid(cached, code) is False


def test_replacement_snapshot_retires_tombstone_and_older_snapshot_cannot_resurrect(tmp_path):
    spent_code = "ABCD1234"
    replacement_code = "WXYZ5678"
    spent_hash = pushgate_pam.hash_value(spent_code)
    replacement_hash = pushgate_pam.hash_value(replacement_code)
    now = datetime.now(timezone.utc)
    initial_at = (now - timedelta(seconds=3)).isoformat()
    stale_at = (now - timedelta(seconds=2)).isoformat()
    replacement_at = (now - timedelta(seconds=1)).isoformat()
    pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=initial_at, backup_code_hashes=[spent_hash]),
        authoritative_snapshot=True,
    )
    assert pushgate_pam.consume_offline_code(tmp_path, "alice", spent_code) is True

    replaced = pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=replacement_at, backup_code_hashes=[replacement_hash]),
        authoritative_snapshot=True,
    )
    assert spent_hash not in replaced["backup_code_hashes"]
    assert replacement_hash in replaced["backup_code_hashes"]
    assert "used_backup_code_hashes" not in replaced
    assert pushgate_pam._BACKUP_CODE_TOMBSTONES not in replaced

    cached = pushgate_pam.write_cache(
        tmp_path,
        "alice",
        _cache("alice", updated_at=stale_at, backup_code_hashes=[spent_hash]),
        authoritative_snapshot=True,
    )
    assert spent_hash not in cached["backup_code_hashes"]
    assert replacement_hash in cached["backup_code_hashes"]
    assert cached[pushgate_pam._SERVER_SNAPSHOT_AT] == replacement_at


def test_backup_code_consumption_is_atomic(tmp_path):
    code = "ABCD1234"
    pushgate_pam.write_cache(tmp_path, "alice", _cache("alice", backup_code_hashes=[pushgate_pam.hash_value(code)]))
    barrier = Barrier(2)

    def consume():
        barrier.wait()
        return pushgate_pam.consume_offline_code(tmp_path, "alice", code)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: consume(), range(2)))

    assert sorted(results) == [False, True]


def test_installer_prefers_private_secret_file_and_redacts_dry_run(tmp_path):
    secret = "super-secret-value"
    secret_file = tmp_path / "client-secret"
    secret_file.write_text(secret + "\n", encoding="ascii")
    os.chmod(secret_file, 0o600)

    result = subprocess.run(
        [
            str(INSTALLER),
            "--server",
            "https://pushgate.example",
            "--client-id",
            "client-id",
            "--client-secret-file",
            str(secret_file),
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_installer_legacy_secret_dry_run_warns_without_echoing_secret():
    secret = "legacy-super-secret"
    result = subprocess.run(
        [
            str(INSTALLER),
            "--server",
            "https://pushgate.example",
            "--client-id",
            "client-id",
            "--client-secret",
            secret,
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "deprecated" in result.stderr
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize("unsafe_kind", ["mode", "symlink"])
def test_installer_rejects_unsafe_secret_files(tmp_path, unsafe_kind):
    secret_file = tmp_path / "client-secret"
    secret_file.write_text("super-secret-value\n", encoding="ascii")
    os.chmod(secret_file, 0o600)
    candidate = secret_file
    if unsafe_kind == "mode":
        os.chmod(secret_file, 0o644)
    else:
        candidate = tmp_path / "client-secret-link"
        candidate.symlink_to(secret_file)

    result = subprocess.run(
        [
            str(INSTALLER),
            "--server",
            "https://pushgate.example",
            "--client-id",
            "client-id",
            "--client-secret-file",
            str(candidate),
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "super-secret-value" not in result.stdout
    assert "super-secret-value" not in result.stderr


def test_installer_rejects_config_line_injection(tmp_path):
    secret_file = tmp_path / "client-secret"
    secret_file.write_text("super-secret-value\n", encoding="ascii")
    os.chmod(secret_file, 0o600)

    result = subprocess.run(
        [
            str(INSTALLER),
            "--server",
            "https://pushgate.example",
            "--client-id",
            "client-id\nPUSHGATE_CLIENT_SECRET=injected",
            "--client-secret-file",
            str(secret_file),
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "must not contain control characters" in result.stderr
    assert "super-secret-value" not in result.stdout
    assert "super-secret-value" not in result.stderr
