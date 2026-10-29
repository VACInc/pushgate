from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import Iterable
from contextlib import suppress
from typing import Any

import httpx

try:
    import redis.asyncio as aioredis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - dependency is installed in normal builds
    aioredis = None

    class RedisError(Exception):
        pass


class FanoutDisconnected:
    """The consumer must reconnect and replay durable pending requests."""


class PushFanout:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._seen: dict[int, list[str]] = {}
        self._disconnected: set[int] = set()

    async def subscribe(self, device_id: str) -> asyncio.Queue:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=20)
        self._subscribers[device_id].add(queue)
        self._seen[id(queue)] = []
        return queue

    def unsubscribe(self, device_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers[device_id].discard(queue)
        self._seen.pop(id(queue), None)
        self._disconnected.discard(id(queue))
        if not self._subscribers[device_id]:
            self._subscribers.pop(device_id, None)

    async def publish(self, device_ids: Iterable[str], payload: dict[str, Any]) -> None:
        for device_id in set(device_ids):
            for queue in list(self._subscribers.get(device_id, ())):
                self._put(queue, payload)

    def _put(self, queue: asyncio.Queue[dict[str, Any]], payload: dict[str, Any]) -> None:
        if id(queue) in self._disconnected:
            return
        event_key = self._event_key(payload)
        seen = self._seen.setdefault(id(queue), [])
        if event_key in seen:
            return
        seen.append(event_key)
        del seen[:-50]
        if queue.full():
            self._disconnect(queue)
            return
        queue.put_nowait(payload)

    def _disconnect(self, queue: asyncio.Queue) -> None:
        self._disconnected.add(id(queue))
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait(FanoutDisconnected())

    @staticmethod
    def _event_key(payload: dict[str, Any]) -> str:
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict) and data.get("id"):
            return f"{payload.get('type')}:{data['id']}:{data.get('status')}:{data.get('expires_at')}"
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class RedisPushFanout(PushFanout):
    def __init__(self, redis_url: str) -> None:
        super().__init__()
        if aioredis is None:
            raise RuntimeError("redis package is required for RedisPushFanout")
        self.redis_url = redis_url
        self._publisher = aioredis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        self._tasks: dict[tuple[str, int], asyncio.Task[None]] = {}

    async def subscribe(self, device_id: str) -> asyncio.Queue:
        queue = await super().subscribe(device_id)
        ready = asyncio.get_running_loop().create_future()
        self._tasks[(device_id, id(queue))] = asyncio.create_task(self._relay(device_id, queue, ready))
        try:
            await asyncio.wait_for(ready, timeout=2)
        except Exception as exc:
            self.unsubscribe(device_id, queue)
            raise ConnectionError("Push subscription unavailable") from exc
        except BaseException:
            self.unsubscribe(device_id, queue)
            raise
        return queue

    def unsubscribe(self, device_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        task = self._tasks.pop((device_id, id(queue)), None)
        if task:
            task.cancel()
        super().unsubscribe(device_id, queue)

    async def publish(self, device_ids: Iterable[str], payload: dict[str, Any]) -> None:
        targets = set(device_ids)
        await super().publish(targets, payload)
        try:
            message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            for device_id in targets:
                await self._publisher.publish(self._channel(device_id), message)
        except RedisError:
            return

    async def _relay(self, device_id: str, queue: asyncio.Queue, ready: asyncio.Future) -> None:
        # Pub/Sub is long-lived; subscription readiness and loss are explicit.
        client = aioredis.Redis.from_url(self.redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=None)
        pubsub = client.pubsub()
        try:
            await pubsub.subscribe(self._channel(device_id))
            async for message in pubsub.listen():
                if message.get("type") == "subscribe":
                    if ready.done():
                        # Redis automatically re-subscribed after a loss. Messages
                        # in that gap are not durable; force the phone to replay.
                        break
                    ready.set_result(None)
                    continue
                if message.get("type") != "message":
                    continue
                self._put(queue, json.loads(message["data"]))
        except (RedisError, ValueError, TypeError) as exc:
            if not ready.done():
                ready.set_exception(exc)
        finally:
            if not ready.done():
                ready.set_exception(ConnectionError("Push subscription ended before readiness"))
            if queue in self._subscribers.get(device_id, ()):
                self._disconnect(queue)
            with suppress(Exception):
                await pubsub.aclose()
            with suppress(Exception):
                await client.aclose()

    @staticmethod
    def _channel(device_id: str) -> str:
        return f"pushgate:device:{device_id}"


class PushProvider:
    async def notify_auth_request(self, devices: Iterable[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
        return {"sent": 0}

    async def notify_event(self, devices: Iterable[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
        """Deliver a small lifecycle event (e.g. auth_decided) so phones can clear stale prompts."""
        return {"sent": 0}


class NoopPushProvider(PushProvider):
    pass


class FcmPushProvider(PushProvider):
    def __init__(self, access_token: str | None, project_id: str | None, endpoint: str) -> None:
        self.access_token = access_token
        self.project_id = project_id
        self.endpoint = endpoint

    async def notify_auth_request(self, devices: Iterable[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
        targets = [
            (str(device["id"]), device["push_token"])
            for device in devices
            if device.get("id") and device.get("push_token")
        ]
        if not self.access_token or not self.project_id or not targets:
            return {"sent": 0}
        endpoint = self.endpoint.format(project_id=self.project_id)
        serialized_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sent = 0
        async with httpx.AsyncClient(timeout=5.0) as client:
            for device_id, token in targets:
                data = {
                    "type": "auth_request",
                    "device_id": device_id,
                    "payload": serialized_payload,
                }
                response = await client.post(
                    endpoint,
                    json={"message": {"token": token, "data": data, "android": {"priority": "high"}}},
                    headers={"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"},
                )
                response.raise_for_status()
                sent += 1
        return {"sent": sent}

    async def notify_event(self, devices: Iterable[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
        targets = [
            (str(device["id"]), device["push_token"])
            for device in devices
            if device.get("id") and device.get("push_token")
        ]
        if not self.access_token or not self.project_id or not targets:
            return {"sent": 0}
        endpoint = self.endpoint.format(project_id=self.project_id)
        serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
        sent = 0
        async with httpx.AsyncClient(timeout=5.0) as client:
            for device_id, token in targets:
                data = {"type": str(event.get("type", "")), "device_id": device_id, "payload": serialized}
                response = await client.post(
                    endpoint,
                    json={"message": {"token": token, "data": data, "android": {"priority": "high"}}},
                    headers={"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"},
                )
                response.raise_for_status()
                sent += 1
        return {"sent": sent}


class NtfyWakeupProvider(PushProvider):
    """Wake the approver's phone through a private ntfy topic.

    The PushGate phone app only receives requests over its WebSocket while it is
    in the foreground unless FCM is configured. Until FCM (a Google project and
    an APK rebuild) exists, this posts one bounded notification per push
    attempt naming who is logging in where, so the human opens the app and the
    pending request is replayed to it. It never carries request identifiers,
    secrets, or approval capability: approval still happens only in the app.
    Delivery failure is logged by the caller and never blocks authentication.
    """

    def __init__(self, url: str, auth: str | None, priority: str, inner: PushProvider) -> None:
        self.url = url
        self.auth = auth
        self.priority = priority
        self.inner = inner

    async def notify_auth_request(self, devices: Iterable[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
        devices = list(devices)
        inner = await self.inner.notify_auth_request(devices, payload)
        data = payload.get("data") if isinstance(payload, dict) else None
        data = data if isinstance(data, dict) else {}
        username = str(data.get("username") or "?")
        approver = str(data.get("approver_username") or username)
        system = str(data.get("system") or "?")
        service = str(data.get("pam_service") or "")
        source = str(data.get("source_ip") or "")
        title = f"PushGate: approve {username}@{system}"
        body = f"Open the PushGate app to approve {username}@{system}"
        if service:
            body += f" ({service})"
        if source:
            body += f" from {source}"
        body += f". Approver: {approver}."
        headers = {
            "Title": title,
            "Priority": self.priority,
            "Tags": "key,pushgate",
        }
        if self.auth:
            headers["Authorization"] = self.auth
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(self.url, content=body.encode("utf-8"), headers=headers)
            response.raise_for_status()
        return {"sent": int(inner.get("sent", 0)) + 1, "wakeup": "ntfy"}

    async def notify_event(self, devices: Iterable[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
        return await self.inner.notify_event(devices, event)


UNIFIEDPUSH_MAX_BYTES = 4000


def is_unifiedpush_endpoint(token: str | None) -> bool:
    """A UnifiedPush endpoint is an HTTPS URL; FCM registration tokens never are."""
    return isinstance(token, str) and token.startswith("https://")


def allowed_host_set(allowed_hosts: str | None) -> set[str]:
    return {item.strip().lower() for item in (allowed_hosts or "").split(",") if item.strip()}


def unifiedpush_endpoint_allowed(token: str | None, allowed_hosts: str | None) -> bool:
    """FCM tokens are separate; HTTPS endpoints require an explicit trusted host."""
    if not is_unifiedpush_endpoint(token):
        return True
    allowed = allowed_host_set(allowed_hosts)
    if not allowed:
        return False
    try:
        host = (httpx.URL(token).host or "").lower()
    except (ValueError, TypeError, httpx.InvalidURL):
        return False
    return host in allowed


def unifiedpush_body(device_id: str, payload: dict[str, Any]) -> bytes:
    """Compact JSON the phone's UnifiedPush receiver understands, bounded to the UP message limit.

    Same shape the FCM path delivers: {"type":"auth_request","device_id":...,"payload":<json>}.
    If the full event does not fit, keep only the fields the challenge needs.
    """
    data = payload.get("data") if isinstance(payload, dict) else None
    data = dict(data) if isinstance(data, dict) else {}
    body = {"type": "auth_request", "device_id": device_id, "payload": json.dumps({"type": "auth_request", "data": data}, sort_keys=True, separators=(",", ":"))}
    wire = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(wire) <= UNIFIEDPUSH_MAX_BYTES:
        return wire
    keep = ("id", "username", "approver_username", "system", "pam_service", "source_ip", "status",
            "created_at", "expires_at", "requested_at", "require_biometric", "device_id")
    trimmed = {k: data[k] for k in keep if k in data}
    body["payload"] = json.dumps({"type": "auth_request", "data": trimmed}, sort_keys=True, separators=(",", ":"))
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class UnifiedPushProvider(PushProvider):
    """Deliver to devices whose push token is a UnifiedPush endpoint (self-hosted ntfy).

    The phone registers with its UnifiedPush distributor (the ntfy app) and
    uploads the endpoint URL through the existing signed push-token route.
    The distributor wakes the PushGate app in the background; no Google.
    An Authorization header is attached only for endpoints on the configured
    host so a foreign endpoint never receives the ntfy credential. Devices with
    ordinary FCM tokens fall through to the inner provider.
    """

    def __init__(self, inner: PushProvider, auth: str | None = None, auth_host: str | None = None, allowed_hosts: str | None = None) -> None:
        self.inner = inner
        self.auth = auth
        self.auth_host = (auth_host or "").strip().lower() or None
        self.allowed_hosts = allowed_hosts

    def _deliverable(self, device: dict[str, Any]) -> bool:
        return unifiedpush_endpoint_allowed(device.get("push_token"), self.allowed_hosts)

    def _headers(self, endpoint: str) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth and self.auth_host:
            host = httpx.URL(endpoint).host.lower()
            if host == self.auth_host:
                headers["Authorization"] = self.auth
        return headers

    async def notify_auth_request(self, devices: Iterable[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
        devices = list(devices)
        up_devices = [d for d in devices if is_unifiedpush_endpoint(d.get("push_token")) and self._deliverable(d)]
        others = [d for d in devices if not is_unifiedpush_endpoint(d.get("push_token"))]
        result = await self.inner.notify_auth_request(others, payload) if others else {"sent": 0}
        sent = int(result.get("sent", 0))
        if not up_devices:
            return {"sent": sent}
        async with httpx.AsyncClient(timeout=5.0) as client:
            for device in up_devices:
                endpoint = device["push_token"]
                response = await client.post(endpoint, content=unifiedpush_body(str(device.get("id", "")), payload), headers=self._headers(endpoint))
                response.raise_for_status()
                sent += 1
        return {"sent": sent, "unifiedpush": len(up_devices)}

    async def notify_event(self, devices: Iterable[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
        devices = list(devices)
        up_devices = [d for d in devices if is_unifiedpush_endpoint(d.get("push_token")) and self._deliverable(d)]
        others = [d for d in devices if not is_unifiedpush_endpoint(d.get("push_token"))]
        result = await self.inner.notify_event(others, event) if others else {"sent": 0}
        sent = int(result.get("sent", 0))
        data = event.get("data") if isinstance(event, dict) else None
        data = dict(data) if isinstance(data, dict) else {}
        async with httpx.AsyncClient(timeout=5.0) as client:
            for device in up_devices:
                endpoint = device["push_token"]
                body = {"type": str(event.get("type", "")), "device_id": str(device.get("id", "")), "data": data}
                wire = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if len(wire) > UNIFIEDPUSH_MAX_BYTES:
                    body["data"] = {"id": data.get("id"), "status": data.get("status")}
                    wire = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                response = await client.post(endpoint, content=wire, headers=self._headers(endpoint))
                response.raise_for_status()
                sent += 1
        return {"sent": sent, "unifiedpush": len(up_devices)}


def build_push_provider(
    access_token: str | None,
    project_id: str | None,
    endpoint: str,
    ntfy_url: str | None = None,
    ntfy_auth: str | None = None,
    ntfy_priority: str = "high",
    unifiedpush_auth: str | None = None,
    unifiedpush_auth_host: str | None = None,
    unifiedpush_allowed_hosts: str | None = None,
) -> PushProvider:
    provider: PushProvider
    if access_token and project_id:
        provider = FcmPushProvider(access_token, project_id, endpoint)
    else:
        provider = NoopPushProvider()
    # UnifiedPush needs no server-side switch: any device whose push token is
    # an endpoint URL is delivered this way; the credential is optional.
    provider = UnifiedPushProvider(provider, unifiedpush_auth, unifiedpush_auth_host, unifiedpush_allowed_hosts)
    if ntfy_url:
        return NtfyWakeupProvider(ntfy_url, ntfy_auth, ntfy_priority, provider)
    return provider


def build_push_fanout(redis_url: str | None) -> PushFanout:
    if redis_url:
        return RedisPushFanout(redis_url)
    return PushFanout()
