from __future__ import annotations

import csv
import io
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_python_distribution_retains_single_upgrade_owner() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["name"] == "pushgate"
    assert metadata["project"]["version"] == "1.0.2"
    assert {"pushgate", "server", "pam"} <= set(metadata["tool"]["setuptools"]["packages"])

    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    assert "via pushgate (pyproject.toml" in lock


def _write_migration_wheel(path: Path, version: str, *, legacy_sentinel: bool) -> None:
    dist_info = f"pushgate-{version}.dist-info"
    files = {
        "pushgate/__init__.py": f'VERSION = "{version}"\n',
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: pushgate\n"
            f"Version: {version}\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: PushGate migration test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    if legacy_sentinel:
        files["pushgate/removed_after_0_1.py"] = "OLD_OWNER = True\n"

    record_path = f"{dist_info}/RECORD"
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for filename in files:
        writer.writerow((filename, "", ""))
    writer.writerow((record_path, "", ""))
    files[record_path] = record.getvalue()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for filename, content in files.items():
            wheel.writestr(filename, content)


def test_pushgate_0_1_upgrades_in_place_without_overlapping_distribution_owners(
    tmp_path: Path,
) -> None:
    old_wheel = tmp_path / "pushgate-0.1.0-py3-none-any.whl"
    new_wheel = tmp_path / "pushgate-0.2.0-py3-none-any.whl"
    _write_migration_wheel(old_wheel, "0.1.0", legacy_sentinel=True)
    _write_migration_wheel(new_wheel, "0.2.0", legacy_sentinel=False)

    environment = tmp_path / "environment"
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    python = environment / "bin" / "python"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(old_wheel)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--upgrade",
            str(new_wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    proof = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import importlib.metadata as m, pathlib, pushgate; "
                "root = pathlib.Path(pushgate.__file__).parent; "
                "owners = [(d.metadata['Name'], d.version) for d in m.distributions() "
                "if d.metadata['Name'].lower() == 'pushgate']; "
                "print(pushgate.VERSION); print(owners); "
                "print((root / 'removed_after_0_1.py').exists())"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert proof.stdout.splitlines() == [
        "0.2.0",
        "[('pushgate', '0.2.0')]",
        "False",
    ]
