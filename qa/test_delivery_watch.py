"""Unanswered-push watch (2026-10-29: phone ntfy subscription dropped, 15 requests in a row expired silently)."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.delivery_watch import UnansweredWatch
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, create_device, create_integration, create_user, decide, start_auth


def test_streak_warns_then_errors_and_resets(caplog) -> None:
    watch = UnansweredWatch(threshold=3, logger=logging.getLogger("t.watch"))
    with caplog.at_level(logging.WARNING, logger="t.watch"):
        assert watch.unanswered("aaaaaaaa-1", "upx") == 1
        assert watch.unanswered("bbbbbbbb-2", None) == 2
        assert not [r for r in caplog.records if r.levelno == logging.ERROR]
        assert watch.unanswered("cccccccc-3", "minis") == 3
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "push_channel_suspect streak=3" in errors[0].getMessage()
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings[0] == "push_unanswered request=aaaaaaaa system=upx streak=1"
    assert "system=-" in warnings[1]
    watch.answered()
    assert watch.unanswered("dddddddd-4", "upx") == 1


def test_expired_pending_requests_feed_the_watch_and_a_decision_resets_it(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'watch.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app) as client:
        user = create_user(client, "watch-user")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "watch-integration", principal_username=user["username"])
        ids = []
        for n in range(2):
            started = start_auth(client, integration, user["username"], f"watch-{n}", system=f"host{n}",
                                 client_timeout_seconds=1)
            assert started.status_code == 201
            ids.append(started.json()["data"]["id"])
        deadline = time.time() + 15
        while app.state.unanswered_watch.streak < 2 and time.time() < deadline:
            time.sleep(0.2)
        assert app.state.unanswered_watch.streak == 2      # background expiry saw two unanswered pushes
        answered = start_auth(client, integration, user["username"], "watch-answered", system="host9")
        assert answered.status_code == 201
        decision = decide(client, answered.json()["data"]["id"], device["id"], key)
        assert decision.json()["data"]["status"] == "approved"
        assert app.state.unanswered_watch.streak == 0
