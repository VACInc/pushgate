"""Common env-file spellings must not silently drop PAM settings."""
from __future__ import annotations


import httpx
import pytest

from pam import pushgate_pam
from pam.test_pushgate_pam_security import _cache, _mock_client


def _pam_context_config(tmp_path, monkeypatch, text, encoding="utf-8"):
    config = tmp_path / "pushgate.env"
    config.write_bytes(text.encode(encoding))
    monkeypatch.setattr(pushgate_pam, "DEFAULT_CONFIG_FILE", str(config))
    monkeypatch.setattr(pushgate_pam, "validate_secure_config_file", lambda _path: None)
    monkeypatch.setattr(pushgate_pam, "validate_secure_cache_location", lambda _path: None)
    monkeypatch.setenv("PAM_TYPE", "auth")
    monkeypatch.delenv("PUSHGATE_PAM_LAUNCHER", raising=False)
    return pushgate_pam.config_from_env()


BASE_CONFIG = "PUSHGATE_SERVER=https://pushgate.example\nPUSHGATE_CLIENT_ID=id\nPUSHGATE_CLIENT_SECRET=secret\n"


@pytest.mark.parametrize(
    "line",
    [
        "export PUSHGATE_FAIL_CLOSED_USERS=deploy",
        "export  PUSHGATE_FAIL_CLOSED_USERS=\"deploy\"",
        "PUSHGATE_FAIL_CLOSED_USERS=deploy;svc",
        "PUSHGATE_FAIL_CLOSED_USERS = deploy",
    ],
    ids=["export", "export-quoted", "semicolons", "spaced"],
)
def test_fail_closed_users_are_read_from_common_env_file_spellings(tmp_path, monkeypatch, line):
    cfg = _pam_context_config(tmp_path, monkeypatch, BASE_CONFIG + line + "\n")
    assert "deploy" in cfg.fail_closed_users


def test_byte_order_mark_does_not_hide_the_first_setting(tmp_path, monkeypatch):
    """An editor-added BOM used to turn the first key into an unknown name."""
    text = "PUSHGATE_FAIL_CLOSED_USERS=deploy\n" + BASE_CONFIG
    cfg = _pam_context_config(tmp_path, monkeypatch, text, encoding="utf-8-sig")
    assert cfg.fail_closed_users == {"deploy"}
    text = BASE_CONFIG.replace("https://pushgate.example", "https://first.example")
    cfg = _pam_context_config(tmp_path, monkeypatch, text, encoding="utf-8-sig")
    assert cfg.server == "https://first.example"


def test_exported_fail_closed_user_never_uses_the_fail_open_cache(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    text = BASE_CONFIG + f"PUSHGATE_CACHE_DIR={cache_dir}\nPUSHGATE_SYSTEM_NAME=labbox\nexport PUSHGATE_FAIL_CLOSED_USERS=deploy\n"
    cfg = _pam_context_config(tmp_path, monkeypatch, text)
    binding = pushgate_pam.cache_binding(cfg, "deploy", "labbox")
    pushgate_pam.write_cache(cache_dir, "deploy", _cache("deploy", fail_mode="open", binding=binding))
    _mock_client(monkeypatch, lambda _request: httpx.Response(503))
    assert pushgate_pam.authenticate("deploy", cfg=cfg) == 1


def test_export_prefix_applies_to_every_setting(tmp_path, monkeypatch):
    text = "\n".join(f"export {line}" for line in BASE_CONFIG.splitlines()) + "\nexport PUSHGATE_TIMEOUT=45\n"
    cfg = _pam_context_config(tmp_path, monkeypatch, text)
    assert (cfg.server, cfg.client_id, cfg.client_secret, cfg.timeout) == ("https://pushgate.example", "id", "secret", 45)
