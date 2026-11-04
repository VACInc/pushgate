"""Bound HTTP request bodies before any route reads them.

Several routes must read the whole body before they can verify a signature
(the signature covers the body), so without a cap an anonymous client could
make the server buffer an unbounded body per request.
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

TOO_LARGE = {"code": "body_too_large", "message": "request body is too large"}


class BodyTooLarge(Exception):
    """Raised into the route when a streamed body passes the limit."""


class RequestBodyLimit:
    """413 for a declared Content-Length over the limit, or once a streamed body passes it.

    A streamed body is cut off by raising from receive(). Frameworks may catch
    that and answer something else (FastAPI reports a body parse error), so
    once the limit is passed this middleware replaces whatever answer the
    application sends with the 413.
    """

    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]], max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = -1
                if declared < 0 or declared > self.max_bytes:
                    await self._reject(send)
                    return

        received = 0
        exceeded = False
        started = False

        async def bounded_receive() -> Message:
            nonlocal received, exceeded
            if exceeded:
                raise BodyTooLarge()
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body") or b"")
                if received > self.max_bytes:
                    exceeded = True
                    raise BodyTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                if not started:
                    started = True
                    await self._reject(send)
                return
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not started:
            started = True
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps({"detail": TOO_LARGE}, separators=(",", ":")).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
