from __future__ import annotations

import json
import time
from typing import Any, Protocol

try:
    import redis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - dependency is installed in normal builds
    redis = None

    class RedisError(Exception):
        pass


class AuthState(Protocol):
    def put_pending(self, request_id: str, payload: dict[str, Any], ttl_seconds: int) -> None:
        ...

    def get(self, request_id: str) -> dict[str, Any] | None:
        ...

    def delete(self, request_id: str) -> None:
        ...


class MemoryAuthState:
    def __init__(self) -> None:
        self._items: dict[str, tuple[dict[str, Any], float]] = {}

    def put_pending(self, request_id: str, payload: dict[str, Any], ttl_seconds: int) -> None:
        self._items[request_id] = (payload, time.monotonic() + max(1, ttl_seconds))

    def get(self, request_id: str) -> dict[str, Any] | None:
        item = self._items.get(request_id)
        if not item:
            return None
        payload, expires_at = item
        if time.monotonic() > expires_at:
            self._items.pop(request_id, None)
            return None
        return payload

    def delete(self, request_id: str) -> None:
        self._items.pop(request_id, None)


class RedisAuthState:
    def __init__(self, redis_url: str, client: Any | None = None) -> None:
        if redis is None and client is None:
            raise RuntimeError("redis package is required for RedisAuthState")
        self.client = client or redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        self.fallback = MemoryAuthState()

    def put_pending(self, request_id: str, payload: dict[str, Any], ttl_seconds: int) -> None:
        try:
            self.client.setex(self._key(request_id), max(1, ttl_seconds), json.dumps(payload, sort_keys=True, separators=(",", ":")))
        except RedisError:
            self.fallback.put_pending(request_id, payload, ttl_seconds)

    def get(self, request_id: str) -> dict[str, Any] | None:
        try:
            raw = self.client.get(self._key(request_id))
        except RedisError:
            return self.fallback.get(request_id)
        if not raw:
            return self.fallback.get(request_id)
        return json.loads(raw)

    def delete(self, request_id: str) -> None:
        try:
            self.client.delete(self._key(request_id))
        except RedisError:
            pass
        self.fallback.delete(request_id)

    @staticmethod
    def _key(request_id: str) -> str:
        return f"pushgate:auth:{request_id}"


def build_auth_state(redis_url: str | None) -> AuthState:
    if redis_url:
        return RedisAuthState(redis_url)
    return MemoryAuthState()
