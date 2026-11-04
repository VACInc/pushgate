"""Re-running the installer must keep PUSHGATE_FAIL_CLOSED_USERS."""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from pam import pushgate_pam
from pam.test_pushgate_pam_security import INSTALLER, ROOT


def _installer_dry_run(tmp_path, *arguments, env_extra=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith("PUSHGATE_")}
    env.update(env_extra or {})
    return subprocess.run(
        [
            str(INSTALLER), "--server", "https://pushgate.example", "--client-id", "client-id",
            "--client-secret", "test-secret", "--dry-run", *arguments,
        ],
        cwd=ROOT, env={**env, "CONFIG_DIR": str(tmp_path)}, text=True, capture_output=True, check=False,
    )


@pytest.mark.parametrize(
    "existing",
    ["PUSHGATE_FAIL_CLOSED_USERS=deploy, svc", 'PUSHGATE_FAIL_CLOSED_USERS="deploy, svc"', "export PUSHGATE_FAIL_CLOSED_USERS='deploy, svc'"],
    ids=["plain", "json", "export"],
)
def test_installer_keeps_the_existing_fail_closed_list(tmp_path, existing):
    """Re-running the installer (secret rotation, upgrade) must not drop the list."""
    (tmp_path / "pushgate.env").write_text("PUSHGATE_SERVER=https://old.example\n" + existing + "\n")
    os.chmod(tmp_path / "pushgate.env", 0o600)
    result = _installer_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "DRY-RUN: fail-closed users: deploy, svc" in result.stdout


def test_installer_fail_closed_option_and_environment(tmp_path):
    (tmp_path / "pushgate.env").write_text("PUSHGATE_FAIL_CLOSED_USERS=deploy\n")
    os.chmod(tmp_path / "pushgate.env", 0o600)
    replaced = _installer_dry_run(tmp_path, "--fail-closed-users", "ops backup")
    assert replaced.returncode == 0, replaced.stderr
    assert "DRY-RUN: fail-closed users: ops backup" in replaced.stdout
    cleared = _installer_dry_run(tmp_path, "--fail-closed-users", "")
    assert cleared.returncode == 0, cleared.stderr
    assert "DRY-RUN: fail-closed users: (none)" in cleared.stdout
    from_env = _installer_dry_run(tmp_path, env_extra={"PUSHGATE_FAIL_CLOSED_USERS": "svc"})
    assert "DRY-RUN: fail-closed users: svc" in from_env.stdout
    fresh = _installer_dry_run(tmp_path / "missing")
    assert fresh.returncode == 0, fresh.stderr
    assert "DRY-RUN: fail-closed users: (none)" in fresh.stdout


def test_installer_rejects_control_characters_in_fail_closed_users(tmp_path):
    result = _installer_dry_run(tmp_path / "missing", "--fail-closed-users", "deploy\nPUSHGATE_SERVER=http://evil")
    assert result.returncode == 2
    assert "must not contain control characters" in result.stderr


def test_installer_refuses_to_drop_an_unreadable_existing_list(tmp_path):
    config = tmp_path / "pushgate.env"
    config.write_bytes(b"PUSHGATE_FAIL_CLOSED_USERS=deploy\n\xff\xfe broken\n")
    os.chmod(config, 0o600)
    result = _installer_dry_run(tmp_path)
    assert result.returncode == 2
    assert "--fail-closed-users" in result.stderr
    explicit = _installer_dry_run(tmp_path, "--fail-closed-users", "deploy")
    assert explicit.returncode == 0, explicit.stderr


def test_installer_writes_the_fail_closed_line_the_helper_reads(tmp_path, monkeypatch):
    """The written line must parse back to the same accounts in the helper."""
    text = INSTALLER.read_text()
    assert "PUSHGATE_FAIL_CLOSED_USERS=$FAIL_CLOSED_USERS_CONFIG" in text
    encoded = json.dumps("deploy, svc")
    config = tmp_path / "pushgate.env"
    config.write_text(
        "PUSHGATE_SERVER=https://pushgate.example\nPUSHGATE_CLIENT_ID=id\nPUSHGATE_CLIENT_SECRET=secret\n"
        f"PUSHGATE_FAIL_CLOSED_USERS={encoded}\n"
    )
    monkeypatch.delenv("PAM_TYPE", raising=False)
    monkeypatch.delenv("PUSHGATE_PAM_LAUNCHER", raising=False)
    monkeypatch.delenv("PUSHGATE_FAIL_CLOSED_USERS", raising=False)
    monkeypatch.setenv("PUSHGATE_CONFIG", str(config))
    assert pushgate_pam.config_from_env().fail_closed_users == {"deploy", "svc"}
