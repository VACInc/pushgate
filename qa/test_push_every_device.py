"""Push delivery tries every device even when one token or provider fails.

A dead token on one phone must not leave the approver's other devices without
the request. Once every device has been tried, the first error is raised so the
caller still logs it.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from server.app.push import FcmPushProvider, NtfyWakeupProvider, PushProvider, UnifiedPushProvider

FCM_ENDPOINT = "https://fcm.example/v1/projects/{project_id}/messages:send"


class Recorder:
    """Mock transport: records every request and fails the ones named in `fail`."""

    def __init__(self, monkeypatch, fail: dict[str, object]) -> None:
        self.seen: list[str] = []
        self.fail = fail
        real_async_client = httpx.AsyncClient

        def handle(request: httpx.Request) -> httpx.Response:
            key = self.key(request)
            self.seen.append(key)
            outcome = self.fail.get(key)
            if isinstance(outcome, Exception):
                raise outcome
            if isinstance(outcome, int):
                return httpx.Response(outcome, request=request)
            return httpx.Response(200, json={"ok": True})

        monkeypatch.setattr(
            "server.app.push.httpx.AsyncClient",
            lambda *a, **k: real_async_client(*a, transport=httpx.MockTransport(handle), **k),
        )

    @staticmethod
    def key(request: httpx.Request) -> str:
        if request.url.host == "fcm.example":
            return json.loads(request.content)["message"]["token"]
        return str(request.url)


class FailingInner(PushProvider):
    def __init__(self) -> None:
        self.calls = 0

    async def notify_auth_request(self, devices, payload):
        self.calls += 1
        raise RuntimeError("inner provider down")

    async def notify_event(self, devices, event):
        self.calls += 1
        raise RuntimeError("inner provider down")


PAYLOAD = {"type": "auth_request", "data": {"id": "request-1", "username": "u", "system": "s"}}
EVENT = {"type": "auth_decided", "data": {"id": "request-1", "status": "approved"}}
FCM_DEVICES = [{"id": f"phone-{n}", "push_token": f"token-{n}"} for n in (1, 2, 3)]


@pytest.mark.parametrize("method", ["notify_auth_request", "notify_event"])
def test_fcm_tries_every_device_then_raises_the_first_error(monkeypatch, method) -> None:
    recorder = Recorder(monkeypatch, {"token-1": httpx.ConnectError("refused"), "token-2": 404})
    provider = FcmPushProvider("fcm-access-token", "fcm-project", FCM_ENDPOINT)
    body = PAYLOAD if method == "notify_auth_request" else EVENT

    with pytest.raises(httpx.ConnectError):
        asyncio.run(getattr(provider, method)(FCM_DEVICES, body))

    assert recorder.seen == ["token-1", "token-2", "token-3"]


@pytest.mark.parametrize("method", ["notify_auth_request", "notify_event"])
def test_fcm_without_failures_still_reports_every_send(monkeypatch, method) -> None:
    Recorder(monkeypatch, {})
    provider = FcmPushProvider("fcm-access-token", "fcm-project", FCM_ENDPOINT)
    body = PAYLOAD if method == "notify_auth_request" else EVENT
    assert asyncio.run(getattr(provider, method)(FCM_DEVICES, body)) == {"sent": 3}


@pytest.mark.parametrize("method", ["notify_auth_request", "notify_event"])
def test_unifiedpush_tries_every_endpoint_after_a_failed_one(monkeypatch, method) -> None:
    first, second = "https://ntfy.example/upA?up=1", "https://ntfy.example/upB?up=1"
    recorder = Recorder(monkeypatch, {first: 503})
    provider = UnifiedPushProvider(PushProvider(), None, None, "ntfy.example")
    devices = [{"id": "a", "push_token": first}, {"id": "b", "push_token": second}]
    body = PAYLOAD if method == "notify_auth_request" else EVENT

    with pytest.raises(httpx.HTTPStatusError) as raised:
        asyncio.run(getattr(provider, method)(devices, body))

    assert raised.value.response.status_code == 503
    assert recorder.seen == [first, second]


@pytest.mark.parametrize("method", ["notify_auth_request", "notify_event"])
def test_unifiedpush_devices_still_get_pushed_when_the_inner_provider_fails(monkeypatch, method) -> None:
    endpoint = "https://ntfy.example/upA?up=1"
    recorder = Recorder(monkeypatch, {})
    inner = FailingInner()
    provider = UnifiedPushProvider(inner, None, None, "ntfy.example")
    devices = [{"id": "fcm-phone", "push_token": "fcm-token"}, {"id": "up-phone", "push_token": endpoint}]
    body = PAYLOAD if method == "notify_auth_request" else EVENT

    with pytest.raises(RuntimeError, match="inner provider down"):
        asyncio.run(getattr(provider, method)(devices, body))

    assert inner.calls == 1
    assert recorder.seen == [endpoint]


def test_unifiedpush_raises_an_inner_failure_even_without_endpoint_devices(monkeypatch) -> None:
    Recorder(monkeypatch, {})
    provider = UnifiedPushProvider(FailingInner(), None, None, "ntfy.example")
    with pytest.raises(RuntimeError, match="inner provider down"):
        asyncio.run(provider.notify_auth_request([{"id": "fcm-phone", "push_token": "fcm-token"}], PAYLOAD))


def test_ntfy_wakeup_still_posts_when_the_inner_provider_fails(monkeypatch) -> None:
    topic = "https://ntfy.example/pushgate"
    recorder = Recorder(monkeypatch, {})
    provider = NtfyWakeupProvider(topic, None, "high", FailingInner())

    with pytest.raises(RuntimeError, match="inner provider down"):
        asyncio.run(provider.notify_auth_request([{"id": "phone-1", "push_token": "fcm-token"}], PAYLOAD))

    assert recorder.seen == [topic]


def test_ntfy_wakeup_failure_is_still_raised(monkeypatch) -> None:
    topic = "https://ntfy.example/pushgate"
    Recorder(monkeypatch, {topic: 500})
    provider = NtfyWakeupProvider(topic, None, "high", PushProvider())
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(provider.notify_auth_request([{"id": "phone-1", "push_token": None}], PAYLOAD))
