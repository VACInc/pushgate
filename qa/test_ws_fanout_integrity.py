"""The phone stream sends what SQL says, never what the fan-out carried.

Redis Pub/Sub (or the in-process fan-out) is only a wake-up signal. Anyone who
can publish to it must not be able to put their own approval text, a request of
another user, or a fake decision on an approver's screen.
"""
import json
import os
from pathlib import Path

import pytest
import redis
from fastapi.testclient import TestClient

from qa.test_server_hardening import (
    ADMIN_TOKEN,
    create_device,
    create_integration,
    create_user,
    decide,
    signed_ws_path,
    start_auth,
)
from server.app.config import Settings
from server.app.main import create_app


def forge(client: TestClient, device_id: str, event: dict) -> None:
    client.portal.call(client.app.state.push_fanout.publish, [device_id], event)


def test_forged_fanout_events_are_rebuilt_or_dropped(tmp_path: Path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'fanout.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app) as client:
        owner = create_user(client, "fanout-owner")
        other = create_user(client, "fanout-other")
        device, key = create_device(client, owner["id"])
        integration = create_integration(client, "fanout-host")
        others_request = start_auth(client, integration, other["username"], "fanout-other-req").json()["data"]

        with client.websocket_connect(signed_ws_path(device["id"], key, "fanout-ws")) as ws:
            assert ws.receive_json() == {"type": "pending", "data": []}
            real = start_auth(client, integration, owner["username"], "fanout-real").json()["data"]
            announced = ws.receive_json()
            assert announced["type"] == "auth_request" and announced["data"]["id"] == real["id"]
            genuine_text = announced["data"]["push_text"]
            assert "fanout-owner" in genuine_text

            # 1. A real pending id with attacker-chosen text: the text is rebuilt from SQL.
            forge(client, device["id"], {
                "type": "auth_request",
                "data": {**announced["data"], "push_text": "Backup job requests nothing", "system": "harmless",
                         "username": "nobody", "expires_at": "2999-01-01T00:00:00+00:00"},
            })
            rebuilt = ws.receive_json()
            assert rebuilt["type"] == "auth_request"
            assert rebuilt["data"]["id"] == real["id"]
            assert rebuilt["data"]["push_text"] == genuine_text
            assert rebuilt["data"]["username"] == "fanout-owner"
            assert rebuilt["data"]["expires_at"] == announced["data"]["expires_at"]

            # 2. Dropped: unknown ids, another user's request, a fake decision for
            #    a still-pending request, unknown event types and non-dict noise.
            forge(client, device["id"], {"type": "auth_request", "data": {"id": "does-not-exist", "push_text": "x"}})
            forge(client, device["id"], {"type": "auth_request", "data": {"id": others_request["id"], "push_text": "x"}})
            forge(client, device["id"], {"type": "auth_decided", "data": {"id": real["id"], "status": "denied"}})
            forge(client, device["id"], {"type": "enroll_new_server", "data": {"id": real["id"], "url": "https://x"}})
            forge(client, device["id"], {"type": "auth_request"})

            # The next frame the phone sees is the genuine decision, nothing forged before it.
            assert decide(client, real["id"], device["id"], key).json()["data"]["status"] == "approved"
            decided = ws.receive_json()
            assert decided["type"] == "auth_decided"
            assert decided["data"]["id"] == real["id"] and decided["data"]["status"] == "approved"

            # 3. A forged "request" for a settled id only reports the true settled state.
            forge(client, device["id"], {"type": "auth_request", "data": {"id": real["id"], "status": "pending", "expires_at": "x"}})
            settled = ws.receive_json()
            assert settled["type"] == "auth_decided"
            assert settled["data"] == decided["data"]

            # 4. Security notices keep only the device's own id.
            forge(client, device["id"], {"type": "device_security_changed", "data": {"id": "someone-else", "extra": 1}})
            assert ws.receive_json() == {"type": "device_security_changed", "data": {"id": device["id"]}}


REDIS_URL = os.environ.get("PUSHGATE_TEST_REDIS_URL")


@pytest.mark.skipif(not REDIS_URL, reason="set PUSHGATE_TEST_REDIS_URL to a disposable Redis")
def test_message_injected_directly_into_redis_is_rebuilt_from_sql(tmp_path: Path) -> None:
    app = create_app(Settings(
        database_url=f"sqlite:///{tmp_path / 'redis-fanout.db'}", bootstrap_token=ADMIN_TOKEN, redis_url=REDIS_URL,
    ))
    with TestClient(app) as client:
        owner = create_user(client, "redis-owner")
        device, key = create_device(client, owner["id"])
        integration = create_integration(client, "redis-host")
        with client.websocket_connect(signed_ws_path(device["id"], key, "redis-ws")) as ws:
            assert ws.receive_json()["type"] == "pending"
            real = start_auth(client, integration, owner["username"], "redis-real").json()["data"]
            announced = ws.receive_json()
            assert announced["data"]["id"] == real["id"]
            # Any Redis client on the network publishes to the device channel.
            raw = redis.Redis.from_url(REDIS_URL)
            try:
                raw.publish(f"pushgate:device:{device['id']}", json.dumps({
                    "type": "auth_request",
                    "data": {"id": real["id"], "push_text": "Printer requests toner", "expires_at": "2999"},
                }))
            finally:
                raw.close()
            received = ws.receive_json()
            assert received["data"]["id"] == real["id"]
            assert received["data"]["push_text"] == announced["data"]["push_text"]
