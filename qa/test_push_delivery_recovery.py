import asyncio
import json
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from server.app import push
from server.app.config import Settings
from server.app.main import create_app
from server.app.push import FanoutDisconnected, PushFanout, RedisPushFanout
from server.app.models import AuthRequest
from qa.test_server_hardening import ADMIN_TOKEN, create_device, create_user, create_integration, signed_ws_path


def test_idle_phone_disconnect_releases_subscription(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'ws.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app) as client:
        user = create_user(client, "phone-owner")
        device, key = create_device(client, user["id"])
        with client.websocket_connect(signed_ws_path(device["id"], key, "disconnect")) as ws:
            assert ws.receive_json()["type"] == "pending"
            assert app.state.push_fanout._subscribers[device["id"]]
            ws.close()
            deadline = time.monotonic() + 1
            while app.state.push_fanout._subscribers and time.monotonic() < deadline:
                time.sleep(0.01)
            assert not app.state.push_fanout._subscribers
            assert not app.state.push_fanout._seen


def test_overflow_keeps_replay_signal_until_consumed():
    async def scenario():
        fanout = PushFanout()
        queue = await fanout.subscribe("phone")
        for index in range(50):
            await fanout.publish(["phone"], {"type": "auth_request", "data": {"id": str(index)}})
        assert isinstance(queue.get_nowait(), FanoutDisconnected)
        assert queue.empty()
        fanout.unsubscribe("phone", queue)
        assert not fanout._disconnected
    asyncio.run(scenario())


def test_reconnect_replays_every_pending_request_in_bounded_pages(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'replay.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app) as client:
        user = create_user(client, "replay-owner")
        device, key = create_device(client, user["id"])
        integration = create_integration(client, "replay-integration")
        expires = datetime.now(timezone.utc) + timedelta(minutes=2)
        with app.state.db.SessionLocal() as db:
            db.add_all([
                AuthRequest(id=f"request-{i:04}", user_id=user["id"], integration_id=integration["id"],
                            username=user["username"], system="test", expires_at=expires)
                for i in range(205)
            ])
            db.commit()
        with client.websocket_connect(signed_ws_path(device["id"], key, "replay-all")) as ws:
            pages = [ws.receive_json()["data"] for _ in range(3)]
            assert list(map(len, pages)) == [100, 100, 5]
            assert len({r["id"] for page in pages for r in page}) == 205


def test_redis_waits_for_ready_and_closes_on_resubscription(monkeypatch):
    class PubSub:
        def __init__(self):
            self.messages = asyncio.Queue()
        async def subscribe(self, channel):
            pass
        async def listen(self):
            while True:
                yield await self.messages.get()
        async def aclose(self):
            pass

    class Redis:
        def pubsub(self):
            return pubsub
        async def aclose(self):
            pass

    options = []
    def from_url(url, **kwargs):
        options.append(kwargs)
        return Redis()

    monkeypatch.setattr(push.aioredis.Redis, "from_url", staticmethod(from_url))

    async def scenario():
        nonlocal pubsub
        pubsub = PubSub()
        fanout = RedisPushFanout("redis://unused")
        subscribing = asyncio.create_task(fanout.subscribe("phone"))
        await asyncio.sleep(0.01)
        assert not subscribing.done()
        await pubsub.messages.put({"type": "subscribe"})
        queue = await asyncio.wait_for(subscribing, 1)
        assert options[-1]["socket_timeout"] is None
        payload = {"type": "auth_request", "data": {"id": "request"}}
        await pubsub.messages.put({"type": "message", "data": json.dumps(payload)})
        assert await asyncio.wait_for(queue.get(), 1) == payload
        await pubsub.messages.put({"type": "subscribe"})
        assert isinstance(await asyncio.wait_for(queue.get(), 1), FanoutDisconnected)
        fanout.unsubscribe("phone", queue)
        assert not fanout._tasks

    pubsub = None
    asyncio.run(scenario())


def test_ntfy_wakeup_posts_one_bounded_notification_without_request_identifiers(monkeypatch):
    import asyncio
    import httpx

    from server.app.push import FcmPushProvider, NoopPushProvider, NtfyWakeupProvider, build_push_provider

    posts: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    def handle(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(200, json={"id": "ntfy-1"})

    def mock_async_client(*args, **kwargs):
        return real_async_client(*args, transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", mock_async_client)
    provider = NtfyWakeupProvider("https://ntfy.example/pushgate", "Bearer tk_test", "high", NoopPushProvider())
    payload = {
        "type": "auth_request",
        "data": {
            "id": "request-secret-id",
            "username": "serviceuser",
            "approver_username": "operator",
            "system": "server02",
            "pam_service": "sshd",
            "source_ip": "192.0.2.5",
        },
    }
    result = asyncio.run(provider.notify_auth_request([{"id": "phone-1", "push_token": None}], payload))
    assert result == {"sent": 1, "wakeup": "ntfy"}
    assert len(posts) == 1
    post = posts[0]
    assert str(post.url) == "https://ntfy.example/pushgate"
    assert post.headers["Title"] == "PushGate: approve serviceuser@server02"
    assert post.headers["Priority"] == "high"
    assert post.headers["Authorization"] == "Bearer tk_test"
    body = post.content.decode()
    assert "Open the PushGate app" in body and "serviceuser@server02" in body and "192.0.2.5" in body
    assert "request-secret-id" not in body

    # Composition: FCM stays inside when configured; nothing without a URL.
    assert isinstance(build_push_provider(None, None, "x").inner, NoopPushProvider)
    composed = build_push_provider("tok", "proj", "https://fcm.example/{project_id}", "https://ntfy.example/t", None, "default")
    assert isinstance(composed, NtfyWakeupProvider) and isinstance(composed.inner.inner, FcmPushProvider)


def test_unifiedpush_endpoint_devices_receive_bounded_json_and_credential_only_on_configured_host(monkeypatch):
    import asyncio
    import json
    import httpx

    from server.app.push import NoopPushProvider, UnifiedPushProvider, build_push_provider, unifiedpush_body

    posts: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    def handle(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(200, json={"id": "up-1"})

    def mock_async_client(*args, **kwargs):
        return real_async_client(*args, transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", mock_async_client)
    provider = UnifiedPushProvider(NoopPushProvider(), "Basic test-only", "ntfy.example", "ntfy.example,other.example")
    payload = {"type": "auth_request", "data": {"id": "request-1", "username": "serviceuser", "system": "server02", "expires_at": "2026-09-22T20:00:00Z"}}
    devices = [
        {"id": "phone-1", "push_token": "https://ntfy.example/upAbc123?up=1"},
        {"id": "phone-2", "push_token": "https://other.example/upXyz?up=1"},
        {"id": "phone-3", "push_token": "fcm-token"},
        {"id": "phone-4", "push_token": None},
    ]
    result = asyncio.run(provider.notify_auth_request(devices, payload))
    assert result == {"sent": 2, "unifiedpush": 2}
    assert [str(p.url) for p in posts] == ["https://ntfy.example/upAbc123?up=1", "https://other.example/upXyz?up=1"]
    assert posts[0].headers["Authorization"] == "Basic test-only"
    assert "Authorization" not in posts[1].headers
    body = json.loads(posts[0].content)
    assert body["type"] == "auth_request" and body["device_id"] == "phone-1"
    inner = json.loads(body["payload"])
    assert inner["type"] == "auth_request" and inner["data"]["id"] == "request-1" and inner["data"]["system"] == "server02"
    assert len(posts[0].content) <= 4000

    # Oversized events are trimmed to the challenge fields, never dropped.
    big = {"type": "auth_request", "data": {"id": "r", "username": "u", "system": "s", "geolocation": {"blob": "x" * 5000}}}
    wire = unifiedpush_body("phone-1", big)
    assert len(wire) <= 4000
    assert "geolocation" not in json.loads(json.loads(wire)["payload"])["data"]

    composed = build_push_provider(None, None, "x", None, None, "high", None, None)
    assert isinstance(composed, UnifiedPushProvider) and isinstance(composed.inner, NoopPushProvider)


def test_decision_and_timeout_publish_auth_decided_to_every_approver_device(tmp_path, monkeypatch):
    """Phones must learn that a request settled elsewhere or timed out so they can clear their prompts."""
    import asyncio
    import httpx
    from datetime import datetime, timedelta, timezone

    from qa.test_server_hardening import decide, start_auth

    posts: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    def handle(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(200, json={"id": "up-1"})

    def mock_async_client(*args, **kwargs):
        return real_async_client(*args, transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", mock_async_client)
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'decided.db'}", bootstrap_token=ADMIN_TOKEN, unifiedpush_allowed_hosts="ntfy.example"))
    with TestClient(app) as client:
        user = create_user(client, "decided-owner")
        phone, phone_key = create_device(client, user["id"])
        watch, _watch_key = create_device(client, user["id"])
        integration = create_integration(client, "decided-integration")
        # The watch registered a UnifiedPush endpoint; the phone is on the WebSocket.
        with app.state.db.SessionLocal() as db:
            from server.app.models import Device
            row = db.get(Device, watch["id"])
            row.push_token = "https://ntfy.example/upWatch?up=1"
            db.commit()
        with client.websocket_connect(signed_ws_path(phone["id"], phone_key, "decided-ws")) as ws:
            assert ws.receive_json()["type"] == "pending"
            started = start_auth(client, integration, user["username"], "decided-1").json()["data"]
            assert ws.receive_json()["type"] == "auth_request"
            posts.clear()
            assert decide(client, started["id"], phone["id"], phone_key).json()["data"]["status"] == "approved"
            decided = ws.receive_json()
            assert decided["type"] == "auth_decided"
            assert decided["data"]["id"] == started["id"] and decided["data"]["status"] == "approved"
            deadline = time.monotonic() + 3
            while not posts and time.monotonic() < deadline:
                time.sleep(0.02)
            assert posts, "UnifiedPush device did not receive the auth_decided event"
            body = json.loads(posts[-1].content)
            assert body["type"] == "auth_decided" and body["device_id"] == watch["id"]
            assert body["data"]["id"] == started["id"] and body["data"]["status"] == "approved"

            # Server-side timeout also notifies.
            expiring = start_auth(client, integration, user["username"], "decided-2").json()["data"]
            assert ws.receive_json()["type"] == "auth_request"
            with app.state.db.SessionLocal() as db:
                row = db.get(AuthRequest, expiring["id"])
                row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                db.commit()
            timed_out = ws.receive_json()
            assert timed_out["type"] == "auth_decided"
            assert timed_out["data"]["id"] == expiring["id"] and timed_out["data"]["status"] == "timeout"


def test_unifiedpush_allowed_hosts_gate_registration_and_delivery(tmp_path, monkeypatch):
    import asyncio
    import base64
    import httpx
    import uuid
    from server.app.push import UnifiedPushProvider, NoopPushProvider, unifiedpush_endpoint_allowed

    assert unifiedpush_endpoint_allowed("fcm-token", "ntfy.example")
    assert not unifiedpush_endpoint_allowed("https://anything.example/up1", None)
    assert unifiedpush_endpoint_allowed("https://ntfy.example/up1?up=1", "ntfy.example, other.example")
    assert not unifiedpush_endpoint_allowed("https://evil.example/up1", "ntfy.example")

    posts: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    def handle(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(200)

    monkeypatch.setattr("server.app.push.httpx.AsyncClient", lambda *a, **k: real_async_client(*a, transport=httpx.MockTransport(handle), **k))
    provider = UnifiedPushProvider(NoopPushProvider(), None, None, "ntfy.example")
    devices = [{"id": "ok", "push_token": "https://ntfy.example/upA"}, {"id": "bad", "push_token": "https://evil.example/upB"}]
    result = asyncio.run(provider.notify_auth_request(devices, {"type": "auth_request", "data": {"id": "r"}}))
    assert result == {"sent": 1, "unifiedpush": 1}
    assert [str(p.url) for p in posts] == ["https://ntfy.example/upA"]

    # Registration through the signed push-token route is refused for a foreign host.
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'allowed.db'}", bootstrap_token=ADMIN_TOKEN, unifiedpush_allowed_hosts="ntfy.example"))
    with TestClient(app) as client:
        user = create_user(client, "allowed-owner")
        device, key = create_device(client, user["id"])

        def upload(endpoint: str):
            ts = str(int(time.time()))
            nonce = uuid.uuid4().hex
            signature = base64.b64encode(key.sign(f"push_token.{device['id']}.{ts}.{nonce}.{endpoint}".encode())).decode()
            return client.post(f"/api/v1/devices/{device['id']}/push-token", json={"push_token": endpoint, "timestamp": ts, "nonce": nonce, "signature": signature})

        assert upload("https://evil.example/upB").status_code == 422
        assert upload("https://ntfy.example/upA").status_code == 200
        assert upload("plain-fcm-token").status_code == 200
