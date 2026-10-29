import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _write_tool(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def test_release_packaging_portably_selects_latest_sdk_tools(tmp_path: Path) -> None:
    sdk_root = tmp_path / "Android SDK"
    log = tmp_path / "tools.log"

    for version in ("9.0.0", "10.0.0"):
        failure = 'echo "old apksigner selected" >&2\nexit 91\n' if version == "9.0.0" else ""
        _write_tool(
            sdk_root / "build-tools" / version / "apksigner",
            f'printf \'apksigner {version}\\n\' >> "$PUSHGATE_TEST_TOOL_LOG"\n'
            + failure
            + "if [ \"${2:-}\" = \"--print-certs\" ]; then\n"
            + "  echo 'Signer #1 certificate SHA-256 digest: AABB'\n"
            + "fi\n",
        )

    for version in ("9.0", "10.0"):
        failure = 'echo "old apkanalyzer selected" >&2\nexit 92\n' if version == "9.0" else ""
        _write_tool(
            sdk_root / "cmdline-tools" / version / "bin" / "apkanalyzer",
            f'printf \'apkanalyzer {version}\\n\' >> "$PUSHGATE_TEST_TOOL_LOG"\n'
            + failure
            + "case \"$2\" in\n"
            + "  debuggable) echo false ;;\n"
            + "  application-id)\n"
            + "    case \"$3\" in\n"
            + "      *phone*) echo org.pushgate.phone ;;\n"
            + "      *) echo org.pushgate.wear ;;\n"
            + "    esac\n"
            + "    ;;\n"
            + "esac\n",
        )

    phone_apk = tmp_path / "phone-release.apk"
    wear_apk = tmp_path / "wear-release.apk"
    phone_apk.touch()
    wear_apk.touch()

    env = os.environ.copy()
    env.update(
        {
            "ANDROID_SDK_ROOT": str(sdk_root),
            "ANDROID_HOME": str(sdk_root),
            "PUSHGATE_ANDROID_BUILD_TYPE": "release",
            "PUSHGATE_SKIP_ANDROID_BUILD": "1",
            "PUSHGATE_PHONE_RELEASE_APK": str(phone_apk),
            "PUSHGATE_WEAR_RELEASE_APK": str(wear_apk),
            "PUSHGATE_APK_OUT": str(tmp_path / "output"),
            "PUSHGATE_TEST_TOOL_LOG": str(log),
            "PATH": "/usr/bin:/bin",
        }
    )
    env.pop("PUSHGATE_APKSIGNER", None)
    env.pop("PUSHGATE_APKANALYZER", None)

    result = subprocess.run(
        ["sh", str(ROOT / "deploy" / "package-android-apks.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "apksigner 10.0.0",
        "apkanalyzer 10.0",
        "apkanalyzer 10.0",
        "apksigner 10.0.0",
        "apksigner 10.0.0",
        "apkanalyzer 10.0",
        "apkanalyzer 10.0",
        "apksigner 10.0.0",
    ]
