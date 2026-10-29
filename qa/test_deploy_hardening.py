import os
import re
import subprocess
from pathlib import Path

import pytest

from qa import android_emulator_e2e


ROOT = Path(__file__).resolve().parents[1]


def run_script(path: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(ROOT / path), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def write_executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def test_compose_smoke_refuses_non_smoke_project_before_docker() -> None:
    env = os.environ.copy()
    env["PUSHGATE_COMPOSE_SMOKE_PROJECT"] = "pushgate-production"

    result = run_script("deploy/compose-smoke.sh", env=env)

    assert result.returncode == 2
    assert "refusing non-smoke Compose project" in result.stderr


@pytest.mark.parametrize(
    "url",
    [
        "https://pushgate.example.com",
        "http://" + "127.0.0.1:8000@pushgate.example.com",
        "http://localhost:8000.pushgate.example.com",
        "http://localhost:8000/production",
    ],
)
def test_compose_smoke_refuses_non_loopback_endpoint_before_docker(url: str) -> None:
    env = os.environ.copy()
    env["PUSHGATE_COMPOSE_SMOKE_PROJECT"] = "pushgate-smoke-contract"
    env["PUSHGATE_COMPOSE_SMOKE_SERVER"] = url

    result = run_script("deploy/compose-smoke.sh", env=env)

    assert result.returncode == 2
    assert "smoke endpoints must" in result.stderr


def test_compose_smoke_isolates_runtime_urls_and_bind_address() -> None:
    smoke = (ROOT / "deploy/compose-smoke.sh").read_text(encoding="utf-8")

    assert "export PUSHGATE_DATABASE_URL=" in smoke
    assert "export PUSHGATE_REDIS_URL=" in smoke
    assert "export PUSHGATE_APP_BIND=127.0.0.1" in smoke
    assert "Admin API accepted an invalid smoke token" in smoke


def test_compose_smoke_refuses_remote_docker_endpoint() -> None:
    env = os.environ.copy()
    env["PUSHGATE_COMPOSE_SMOKE_PROJECT"] = "pushgate-smoke-contract"
    env["DOCKER_HOST"] = "tcp://production.example.com:2376"

    result = run_script("deploy/compose-smoke.sh", env=env)

    assert result.returncode == 2
    assert "refusing destructive Compose smoke against non-local Docker endpoint" in result.stderr


def test_traefik_config_smoke_does_not_render_caller_secrets() -> None:
    smoke = (ROOT / "deploy/traefik-compose-config-smoke.sh").read_text(encoding="utf-8")

    assert "${PUSHGATE_PROXY_AUTH_SECRET:-" not in smoke
    assert smoke.count("--env-file /dev/null") == 2
    assert "export PUSHGATE_DATABASE_URL=" in smoke
    assert "export PUSHGATE_REDIS_URL=" in smoke


def test_lima_smoke_refuses_non_smoke_vm_before_limactl() -> None:
    env = os.environ.copy()
    env["PUSHGATE_LIMA_VM"] = "development"

    result = run_script("deploy/lima-pam-vm-smoke.sh", env=env)

    assert result.returncode == 2
    assert "Refusing to modify non-smoke Lima VM" in result.stderr


def test_pam_smokes_require_explicit_disposable_context_and_pinned_inputs() -> None:
    linux_smoke = (ROOT / "deploy/linux-pam-smoke.sh").read_text(encoding="utf-8")
    lima_smoke = (ROOT / "deploy/lima-pam-vm-smoke.sh").read_text(encoding="utf-8")

    assert "python:3.12-slim@sha256:" in linux_smoke
    assert "--require-hashes --only-binary=:all: -r /workspace/requirements.lock" in linux_smoke
    assert "PUSHGATE_PAM_SMOKE_DISPOSABLE=1 python -I /workspace/qa/pam_live_smoke.py" in linux_smoke
    assert 'PUSHGATE_PAM_SMOKE_DISPOSABLE=1 \\\n' in lima_smoke
    assert '--mount "$ROOT:w"' not in lima_smoke


def test_default_container_images_are_digest_pinned() -> None:
    compose = (ROOT / "deploy/docker-compose.yml").read_text(encoding="utf-8")
    image_values = re.findall(r"^\s*image:\s*(\S+)$", compose, flags=re.MULTILINE)

    assert image_values
    assert all(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) for image in image_values)
    for relative_path in ("deploy/android-build.sh", "deploy/linux-pam-smoke.sh"):
        script = (ROOT / relative_path).read_text(encoding="utf-8")
        assert re.search(r"@sha256:[0-9a-f]{64}", script)


def write_migration_env(path: Path, *extra_lines: str) -> None:
    password = "a" * 64
    lines = [
        f"PUSHGATE_POSTGRES_PASSWORD={password}",
        *extra_lines,
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def test_postgres_password_migration_dry_run_never_contacts_docker(tmp_path: Path) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file)

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        "pushgate-production",
        "--env-file",
        str(env_file),
    )

    assert result.returncode == 0, result.stderr
    assert "No Docker connection was made and no state was changed" in result.stdout


@pytest.mark.parametrize("project_name", ["Production", ".", "pushgate.prod", "-pushgate"])
def test_postgres_password_migration_rejects_non_compose_project_names(
    tmp_path: Path, project_name: str
) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file)

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        project_name,
        "--env-file",
        str(env_file),
    )

    assert result.returncode != 0
    assert "--project-name" in result.stderr


def test_postgres_password_migration_rejects_insecure_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file)
    env_file.chmod(0o640)

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        "pushgate-production",
        "--env-file",
        str(env_file),
    )

    assert result.returncode != 0
    assert "must not grant group or world permissions" in result.stderr


def test_postgres_password_migration_rejects_database_url_override(tmp_path: Path) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file, "PUSHGATE_DATABASE_URL=postgresql://example.invalid/prod")

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        "pushgate-production",
        "--env-file",
        str(env_file),
    )

    assert result.returncode != 0
    assert "database URL overrides are not supported" in result.stderr


def test_postgres_password_migration_apply_refuses_running_server(tmp_path: Path) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file)
    tools = tmp_path / "bin"
    tools.mkdir()
    write_executable(
        tools / "docker",
        """
case "$*" in
  *"ps --all -q server") echo server-id ;;
  *".State.Status"*"server-id") echo running ;;
  *) echo "unexpected docker invocation: $*" >&2; exit 90 ;;
esac
""",
    )
    env = os.environ.copy()
    env["PATH"] = f"{tools}:{env['PATH']}"

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        "pushgate-production",
        "--env-file",
        str(env_file),
        "--apply",
        env=env,
    )

    assert result.returncode != 0
    assert "must be fully stopped before rotating" in result.stderr


def test_postgres_password_migration_apply_refuses_unexpected_volume(tmp_path: Path) -> None:
    env_file = tmp_path / "pushgate.env"
    write_migration_env(env_file)
    tools = tmp_path / "bin"
    tools.mkdir()
    write_executable(
        tools / "docker",
        """
case "$*" in
  *"ps --all -q server") echo server-id ;;
  *".State.Status"*"server-id") echo exited ;;
  *"ps --status running -q postgres") echo postgres-id ;;
  *".Mounts"*"postgres-id") echo "bind " ;;
  *) echo "unexpected docker invocation: $*" >&2; exit 90 ;;
esac
""",
    )
    env = os.environ.copy()
    env["PATH"] = f"{tools}:{env['PATH']}"

    result = run_script(
        "deploy/migrate-postgres-password.sh",
        "--project-name",
        "pushgate-production",
        "--env-file",
        str(env_file),
        "--apply",
        env=env,
    )

    assert result.returncode != 0
    assert "data mount is not the expected volume" in result.stderr


@pytest.mark.parametrize("serial", ["device-1234", "emulator-", "emulator-5554x"])
def test_android_e2e_refuses_non_emulator_serials(serial: str) -> None:
    with pytest.raises(android_emulator_e2e.E2EFailure, match="non-emulator serial"):
        android_emulator_e2e.validate_emulator_serial(serial)


def test_android_e2e_redacts_sensitive_adb_command(tmp_path: Path) -> None:
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\necho leaked-enrollment-payload >&2\nexit 1\n", encoding="utf-8")
    adb.chmod(0o755)
    target = android_emulator_e2e.DeviceTarget(
        kind="phone",
        serial="emulator-5554",
        package="org.pushgate.phone",
        activity=".MainActivity",
        apk=tmp_path / "phone.apk",
        enroll_label="Enroll",
        title="PushGate",
    )

    with pytest.raises(android_emulator_e2e.E2EFailure) as exc_info:
        android_emulator_e2e.AdbDevice(adb, target).shell(
            "secret-enrollment-payload", check=True, sensitive=True
        )

    message = str(exc_info.value)
    assert "redacted sensitive adb command" in message
    assert "secret-enrollment-payload" not in message
    assert "leaked-enrollment-payload" not in message


def test_android_e2e_reserves_private_new_database(tmp_path: Path) -> None:
    db_path = tmp_path / "state" / "pushgate.db"

    android_emulator_e2e.reserve_new_database(db_path)

    assert db_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(android_emulator_e2e.E2EFailure, match="refusing to reuse existing"):
        android_emulator_e2e.reserve_new_database(db_path)


def test_android_e2e_uses_ephemeral_admin_token_and_new_database() -> None:
    e2e = (ROOT / "qa/android_emulator_e2e.py").read_text(encoding="utf-8")

    assert "secrets.token_urlsafe(32)" in e2e
    assert 'ADMIN_TOKEN = "' not in e2e
    assert "refusing to reuse existing Android E2E database path" in e2e
    assert 'DISPOSABLE_ACK = "PUSHGATE_ANDROID_E2E_DISPOSABLE"' in e2e


def test_android_shell_runners_validate_targets_before_avd_mutation() -> None:
    for relative_path in (
        "deploy/android-emulator-e2e-smoke.sh",
        "deploy/android-instrumented-tests.sh",
        "deploy/android-emulator-smoke.sh",
    ):
        runner = (ROOT / relative_path).read_text(encoding="utf-8")
        assert "Refusing non-smoke phone AVD" in runner
        assert "Refusing non-smoke Wear AVD" in runner
        assert "Refusing to reuse $serial" in runner
        assert 'case "$(uname -m)"' in runner
        if "validate_emulator_serial" in runner:
            assert runner.index('validate_emulator_serial "$PHONE_SERIAL"') < runner.index(
                'ensure_avd "$PHONE_AVD"'
            )
            assert runner.index('validate_emulator_serial "$WEAR_SERIAL"') < runner.index(
                'ensure_avd "$WEAR_AVD"'
            )


def test_quick_android_smoke_portably_discovers_sdk_tools_and_host_abi() -> None:
    runner = (ROOT / "deploy/android-emulator-smoke.sh").read_text(encoding="utf-8")

    assert '"$HOME/android-sdk" "$HOME/Android/Sdk" "$HOME/Library/Android/sdk"' in runner
    assert '"$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"' in runner
    assert '"$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"' in runner
    assert 'case "$(uname -m)"' in runner
    assert 'PUSHGATE_ADB:-$SDK_ROOT/platform-tools/adb' in runner
    assert 'PUSHGATE_EMULATOR:-$SDK_ROOT/emulator/emulator' in runner


def test_android_build_refuses_insecure_signing_store_before_docker(tmp_path: Path) -> None:
    signing_store = tmp_path / "release.jks"
    signing_store.write_text("not-a-real-keystore", encoding="utf-8")
    signing_store.chmod(0o644)
    env = os.environ.copy()
    env["PUSHGATE_ANDROID_SIGNING_STORE_FILE"] = str(signing_store)

    result = run_script("deploy/android-build.sh", env=env)

    assert result.returncode != 0
    assert "must not grant group or world permissions" in result.stderr


def test_android_release_build_requires_complete_signing_configuration() -> None:
    env = os.environ.copy()
    env["PUSHGATE_ANDROID_BUILD_TYPE"] = "release"
    env.pop("PUSHGATE_ANDROID_SIGNING_STORE_FILE", None)
    env.pop("PUSHGATE_ANDROID_SIGNING_STORE_PASSWORD", None)
    env.pop("PUSHGATE_ANDROID_SIGNING_KEY_ALIAS", None)
    env.pop("PUSHGATE_ANDROID_SIGNING_KEY_PASSWORD", None)

    result = run_script("deploy/android-build.sh", env=env)

    assert result.returncode == 2
    assert "Release builds require" in result.stderr


def test_apk_packaging_requires_checksum_tool() -> None:
    packaging = (ROOT / "deploy/package-android-apks.sh").read_text(encoding="utf-8")

    assert "shasum or sha256sum is required to package APK checksums" in packaging
