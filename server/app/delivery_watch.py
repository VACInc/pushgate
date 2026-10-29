"""Unanswered-push watch: make silent push loss visible in the server log.

PushGate cannot see whether a wake-up reached the phone: ntfy accepts a UnifiedPush publish even when no
subscriber is connected and its answer carries no subscriber count. The observable symptom is requests
that expire while still pending (no device ever decided). One of those is normal (the human ignored it);
a streak is the signature of a dead push channel, as on 2026-10-29 when the phone's ntfy app dropped its
subscription and 15 requests in a row expired. Each unanswered expiry logs a WARNING; from `threshold`
in a row on it logs an ERROR naming the likely cause. Any device decision resets the streak.
"""
from __future__ import annotations

import logging
import threading

LOG = logging.getLogger("pushgate.delivery")


class UnansweredWatch:
    def __init__(self, threshold: int = 3, logger: logging.Logger | None = None) -> None:
        self.threshold = max(1, int(threshold))
        self.log = logger or LOG
        self.streak = 0
        self._lock = threading.Lock()

    def unanswered(self, request_id: str, system: str | None) -> int:
        """A pending request expired with no device decision. Returns the current streak."""
        with self._lock:
            self.streak += 1
            streak = self.streak
        self.log.warning(
            "push_unanswered request=%s system=%s streak=%d", str(request_id)[:8], system or "-", streak
        )
        if streak >= self.threshold:
            self.log.error(
                "push_channel_suspect streak=%d: %d auth requests in a row expired with no device decision; "
                "the phone is probably not receiving pushes (check its UnifiedPush distributor/ntfy subscription)",
                streak,
                streak,
            )
        return streak

    def answered(self) -> None:
        """A device decided a request in time: the push channel works."""
        with self._lock:
            self.streak = 0
