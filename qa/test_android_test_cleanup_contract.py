from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("project", ["android-phone", "android-wear"])
def test_connected_test_cleanup_requires_explicit_emulator_target(project: str) -> None:
    build_file = (ROOT / project / "app" / "build.gradle.kts").read_text()

    assert 'System.getenv("PUSHGATE_ALLOW_TEST_APP_UNINSTALL") == "1"' in build_file
    assert 'System.getenv("ANDROID_SERIAL")?.trim()' in build_file
    assert 'Regex("""emulator-\\d+""").matches(serial)' in build_file
    assert "connectedDeviceSerials" not in build_file


@pytest.mark.parametrize(
    ("project", "application_id"),
    [
        ("android-phone", "org.pushgate.phone"),
        ("android-wear", "org.pushgate.wear"),
    ],
)
def test_android_application_ids_remain_upgrade_compatible(project: str, application_id: str) -> None:
    build_file = (ROOT / project / "app" / "build.gradle.kts").read_text()

    assert f'applicationId = "{application_id}"' in build_file


def test_release_packaging_checks_each_deployed_application_identity() -> None:
    packaging = (ROOT / "deploy" / "package-android-apks.sh").read_text()

    assert '"$PHONE_SOURCE" org.pushgate.phone "$PHONE_EXPECTED_CERT"' in packaging
    assert '"$WEAR_SOURCE" org.pushgate.wear "$WEAR_EXPECTED_CERT"' in packaging
    assert "Phone and Wear release APK signing certificates do not match" not in packaging


def test_emulator_runner_scopes_destructive_cleanup_opt_in() -> None:
    runner = (ROOT / "deploy" / "android-instrumented-tests.sh").read_text()

    assert "emulator-[0-9]*" in runner
    assert "PUSHGATE_ALLOW_TEST_APP_UNINSTALL=1 ANDROID_SERIAL=\"$serial\"" in runner
