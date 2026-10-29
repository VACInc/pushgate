from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pam.pushgate_pam import hash_value, write_cache


def run_helper(cache_dir: Path, username: str, offline_code: str | None = None, stdin_code: str | None = None) -> int:
    env = os.environ.copy()
    env.update(
        {
            "PUSHGATE_SERVER": "http://127.0.0.1:9",
            "PUSHGATE_CLIENT_ID": "smoke",
            "PUSHGATE_CLIENT_SECRET": "smoke",
            "PUSHGATE_CACHE_DIR": str(cache_dir),
            "PUSHGATE_TIMEOUT": "1",
        }
    )
    args = [sys.executable, "pam/pushgate_pam.py", "--user", username, "--service", "ssh"]
    if offline_code:
        args.extend(["--offline-code", offline_code])
    return subprocess.run(args, env=env, input=stdin_code, text=True, check=False).returncode


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        write_cache(cache_dir, "openuser", {"username": "openuser", "fail_mode": "open"})
        write_cache(cache_dir, "closeduser", {"username": "closeduser", "fail_mode": "closed"})
        write_cache(
            cache_dir,
            "backupuser",
            {"username": "backupuser", "fail_mode": "closed", "backup_code_hashes": [hash_value("ABCD1234"), hash_value("WXYZ5678")]},
        )
        assert run_helper(cache_dir, "openuser") == 0
        assert run_helper(cache_dir, "closeduser") == 1
        assert run_helper(cache_dir, "backupuser", "ABCD1234") == 0
        assert run_helper(cache_dir, "backupuser", "ABCD1234") == 1
        assert run_helper(cache_dir, "backupuser", stdin_code="WXYZ5678") == 0
        assert run_helper(cache_dir, "backupuser", stdin_code="WXYZ5678") == 1
    print("PAM smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
