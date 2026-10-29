"""A stalled database connection must never freeze the event loop.

During a Patroni failover a pooled PostgreSQL socket can hang until TCP gives
up. With one uvicorn worker, any synchronous SQL on the event loop then stops
every request, including /healthz. These tests hold SQL open with a gate and
check that /healthz still answers.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from server.app.config import Settings
from server.app.db import Database
from server.app.main import create_app


ADMIN_TOKEN = "test-admin-token-0123456789abcdef"
HEALTH_DEADLINE_SECONDS = 3.0


class SqlGate:
    """Blocks matching SQL statements until released."""

    def __init__(self, engine, marker: str) -> None:
        self.marker = marker
        self.armed = False
        self.entered = threading.Event()
        self.release = threading.Event()
        event.listen(engine, "before_cursor_execute", self._before)

    def _before(self, _conn, _cursor, statement, _params, _context, _many) -> None:
        if self.armed and self.marker in statement.lower():
            self.entered.set()
            self.release.wait(timeout=30)


def run_in_thread(fn) -> tuple[threading.Thread, dict]:
    result: dict = {}

    def target() -> None:
        try:
            result["value"] = fn()
        except Exception as exc:  # pragma: no cover - surfaced by the assert
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, result


def healthz_answers(client: TestClient) -> bool:
    thread, result = run_in_thread(lambda: client.get("/healthz"))
    thread.join(HEALTH_DEADLINE_SECONDS)
    return not thread.is_alive() and "value" in result and result["value"].status_code == 200


def make_app(tmp_path: Path):
    return create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'stall.db'}",
            bootstrap_token=ADMIN_TOKEN,
        )
    )


def test_stalled_expiry_sweep_does_not_block_healthz(tmp_path: Path) -> None:
    app = make_app(tmp_path)
    # The expiry sweep starts by pruning replay nonces every second.
    gate = SqlGate(app.state.db.engine, "nonces")
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        gate.armed = True
        try:
            assert gate.entered.wait(5), "expiry sweep never reached the database"
            assert healthz_answers(client), "/healthz stalled behind the expiry sweep"
        finally:
            gate.armed = False
            gate.release.set()


def signed_headers(client_id: str) -> dict[str, str]:
    # The signature is checked after the integration lookup, so any value
    # reaches the database.
    return {
        "Content-Type": "application/json",
        "X-PushGate-Client-Id": client_id,
        "X-PushGate-Timestamp": str(int(time.time())),
        "X-PushGate-Nonce": f"nonce-{time.monotonic_ns()}",
        "X-PushGate-Signature": "0" * 64,
    }


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/auth/requests/some-request"),
        ("POST", "/api/v1/auth/requests"),
        ("POST", "/api/v1/auth/preflight"),
        ("POST", "/api/v1/auth/requests/some-request/consume"),
        ("POST", "/api/v1/proxy/verify"),
    ],
)
def test_stalled_auth_request_does_not_block_healthz(tmp_path: Path, method: str, path: str) -> None:
    app = make_app(tmp_path)
    gate = SqlGate(app.state.db.engine, "from integrations")
    with TestClient(app) as client:
        gate.armed = True
        request_thread, request_result = run_in_thread(
            lambda: client.request(method, path, content=b"{}", headers=signed_headers("stall-client"))
        )
        try:
            assert gate.entered.wait(5), "request never reached the database"
            assert healthz_answers(client), f"/healthz stalled behind {method} {path}"
        finally:
            gate.armed = False
            gate.release.set()
            request_thread.join(10)
        assert not request_thread.is_alive()
        assert request_result["value"].status_code == 403


def test_healthz_does_not_need_a_threadpool_worker(tmp_path: Path) -> None:
    app = make_app(tmp_path)
    route = next(route for route in app.routes if getattr(route, "path", None) == "/healthz")
    import inspect

    # A sync route waits for a free worker thread; with every worker stuck on
    # the database, a sync /healthz would hang too.
    assert inspect.iscoroutinefunction(route.endpoint)


def test_postgres_engine_fails_fast_on_dead_connections() -> None:
    url = "postgresql+psycopg://pushgate:secret@db.invalid:5432/pushgate"
    options = Database.engine_options(url)
    assert options["pool_pre_ping"] is True
    assert 0 < options["pool_recycle"] <= 600
    connect_args = options["connect_args"]
    assert connect_args["connect_timeout"] <= 10
    assert connect_args["keepalives"] == 1
    assert connect_args["keepalives_idle"] * 1 + connect_args["keepalives_interval"] * connect_args["keepalives_count"] <= 30
    assert connect_args["tcp_user_timeout"] <= 30000

    engine = Database(url).engine
    assert engine.pool._pre_ping is True
    assert engine.pool._recycle == options["pool_recycle"]
    engine.dispose()


def test_postgres_url_parameters_override_engine_defaults() -> None:
    url = "postgresql+psycopg://pushgate:secret@db.invalid/pushgate?connect_timeout=3&keepalives_idle=7"
    connect_args = Database.engine_options(url)["connect_args"]
    assert "connect_timeout" not in connect_args
    assert "keepalives_idle" not in connect_args
    assert connect_args["keepalives_interval"] == 3


def test_sqlite_engine_keeps_thread_sharing() -> None:
    assert Database.engine_options("sqlite:////tmp/x.db") == {"connect_args": {"check_same_thread": False}}
