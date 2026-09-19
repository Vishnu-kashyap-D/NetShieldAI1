from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    """In-memory sliding-window event counter, keyed by an arbitrary string.

    Used for failed-login throttling and chatbot request throttling (see routers/auth.py and
    routers/chat.py). Deliberately tiny and dependency-free. State lives in this process's
    memory, so it is per-worker: a multi-worker deployment would need a shared store (Redis,
    the DB) for the limits to hold across workers -- the same single-process assumption the
    rest of this backend already makes (see detection_service.reload_engine).

    Safe to call from FastAPI's thread pool (sync routes run in real OS threads).
    """

    # Bound on distinct keys held at once, so a flood of unique keys (e.g. a login spray across
    # random emails) can't grow this dict without limit.
    _MAX_KEYS = 10_000

    def __init__(self, max_events: int, window_seconds: float):
        self._max_events = max_events
        self._window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _live_events(self, key: str, now: float) -> deque[float] | None:
        """Drops expired events for `key`; returns its remaining events, or None if it has none."""
        events = self._events.get(key)
        if events is None:
            return None
        cutoff = now - self._window
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            del self._events[key]
            return None
        return events

    def _sweep(self, now: float) -> None:
        for key in list(self._events):
            self._live_events(key, now)

    def retry_after(self, key: str) -> float:
        """Seconds until `key` may act again; 0.0 when it isn't currently limited."""
        now = time.monotonic()
        with self._lock:
            events = self._live_events(key, now)
            if events is None or len(events) < self._max_events:
                return 0.0
            return max(0.0, events[0] + self._window - now)

    def record(self, key: str) -> None:
        """Records one event for `key` (e.g. one failed login)."""
        now = time.monotonic()
        with self._lock:
            if key not in self._events and len(self._events) >= self._MAX_KEYS:
                self._sweep(now)
            self._events.setdefault(key, deque()).append(now)

    def acquire(self, key: str) -> float:
        """Atomic check-then-record for "one request = one event" limits (chat).

        Returns 0.0 and records the request if `key` is under its limit; otherwise records
        nothing and returns how many seconds until it would be allowed again.
        """
        now = time.monotonic()
        with self._lock:
            events = self._live_events(key, now)
            if events is not None and len(events) >= self._max_events:
                return max(0.0, events[0] + self._window - now)
            if key not in self._events and len(self._events) >= self._MAX_KEYS:
                self._sweep(now)
            self._events.setdefault(key, deque()).append(now)
            return 0.0

    def clear(self, key: str) -> None:
        """Forgets `key` entirely (e.g. after a successful login)."""
        with self._lock:
            self._events.pop(key, None)
