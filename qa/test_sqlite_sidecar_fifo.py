"""A FIFO at the SQLite database path or a sidecar name fails startup instead of hanging it.

Opening a FIFO read-only blocks until a writer appears, so the regular-file check
after the open was never reached and the server hung before serving anything.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from server.app.db import Database


@pytest.mark.parametrize("name", ["pushgate.db", "pushgate.db-journal", "pushgate.db-wal", "pushgate.db-shm"])
def test_fifo_in_place_of_a_database_file_is_rejected_promptly(tmp_path: Path, name: str) -> None:
    database = tmp_path / "pushgate.db"
    if name != database.name:
        database.touch(mode=0o600)
    os.mkfifo(tmp_path / name, 0o600)
    outcome: dict[str, BaseException | None] = {}

    def open_database() -> None:
        try:
            Database(f"sqlite:///{database}")
            outcome["error"] = None
        except BaseException as exc:  # noqa: BLE001 - reported below
            outcome["error"] = exc

    worker = threading.Thread(target=open_database, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        # Unblock the stuck open so the test process can exit, then fail.
        with open(tmp_path / name, "wb", buffering=0):
            pass
        worker.join(timeout=5)
        pytest.fail(f"opening {name} as a FIFO blocked startup")
    assert isinstance(outcome["error"], RuntimeError)
    assert "regular" in str(outcome["error"])


def test_regular_database_files_still_open_and_are_made_private(tmp_path: Path) -> None:
    database = tmp_path / "pushgate.db"
    for name in ("pushgate.db", "pushgate.db-wal"):
        (tmp_path / name).touch(mode=0o640)
    Database(f"sqlite:///{database}").init()
    for name in ("pushgate.db", "pushgate.db-wal"):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o600
