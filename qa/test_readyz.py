"""/readyz answers 200 only while the database answers.

/healthz stays liveness only. /readyz runs one `SELECT 1` at a time, reuses the
result for a second, and gives up after a timeout, so probes never load or
hang on the database.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from server.app.config import Settings
from server.app.main import create_app

from test_db_stall_isolation import ADMIN_TOKEN, healthz_answers, run_in_thread


class ReadyProbe:
    """Counts readiness queries; can fail them or hold them open."""

    def __init__(self, engine) -> None:
        self.count = 0
        self.fail = False
        self.hold = False
        self.entered = threading.Event()
        self.release = threading.Event()
        event.listen(engine, "before_cursor_execute", self._before)

    def _before(self, _conn, _cursor, statement, _params, _context, _many) -> None:
        if statement.strip().lower() != "select 1":
            return
        self.count += 1
        if self.fail:
            raise OperationalError(statement, {}, Exception("database is down"))
        if self.hold:
            self.entered.set()
            self.release.wait(timeout=30)


def make_app(tmp_path: Path, **extra):
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 'ready.db'}", bootstrap_token=ADMIN_TOKEN, **extra))


def test_readyz_is_200_while_the_database_answers(tmp_path) -> None:
    app = make_app(tmp_path)
    probe = ReadyProbe(app.state.db.engine)
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 200, response.text
        assert response.json() == {"ok": True, "service": "pushgate", "database": "ok"}
        assert probe.count == 1


def test_readyz_is_503_when_the_database_fails_and_recovers(tmp_path) -> None:
    app = make_app(tmp_path)
    app.state.readiness["reuse"] = 0.0
    probe = ReadyProbe(app.state.db.engine)
    with TestClient(app) as client:
        probe.fail = True
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"ok": False, "service": "pushgate", "database": "unavailable"}
        assert "database is down" not in response.text
        # Liveness is unaffected.
        assert client.get("/healthz").status_code == 200
        probe.fail = False
        assert client.get("/readyz").status_code == 200


def test_stalled_database_gives_503_within_the_timeout_and_one_query(tmp_path) -> None:
    app = make_app(tmp_path)
    app.state.readiness.update(timeout=0.3, reuse=0.0)
    probe = ReadyProbe(app.state.db.engine)
    with TestClient(app) as client:
        probe.hold = True
        try:
            started = time.monotonic()
            assert client.get("/readyz").status_code == 503
            assert time.monotonic() - started < 2.0
            assert probe.entered.is_set()
            # The stuck query is still running: later probes wait on it instead of
            # starting another one, and liveness still answers.
            assert client.get("/readyz").status_code == 503
            assert probe.count == 1
            assert healthz_answers(client)
        finally:
            probe.hold = False
            probe.release.set()
        deadline = time.monotonic() + 5
        while client.get("/readyz").status_code != 200 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert client.get("/readyz").status_code == 200


def test_readyz_reuses_a_fresh_result_and_is_not_rate_limited(tmp_path) -> None:
    app = make_app(tmp_path, rate_limit_per_minute=1)
    probe = ReadyProbe(app.state.db.engine)
    with TestClient(app) as client:
        threads = [run_in_thread(lambda: client.get("/readyz")) for _ in range(5)]
        for thread, _result in threads:
            thread.join(5)
        assert [result["value"].status_code for _thread, result in threads] == [200] * 5
        assert probe.count == 1
