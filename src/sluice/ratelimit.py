"""Token-bucket rate limiting for tool calls."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Hashable

_UNITS = {
    "s": 1, "sec": 1, "second": 1,
    "m": 60, "min": 60, "minute": 60,
    "h": 3600, "hour": 3600,
    "d": 86400, "day": 86400,
}
_RATE_RE = re.compile(r"^\s*(\d+)\s*/\s*([a-z]+?)s?\s*$", re.IGNORECASE)


def parse_rate(spec: str) -> tuple[int, float]:
    """``"10/minute"`` -> ``(10, 60.0)``."""
    m = _RATE_RE.match(spec)
    if not m or m.group(2).lower() not in _UNITS:
        raise ValueError(f"invalid rate limit {spec!r}; expected e.g. '10/minute'")
    count = int(m.group(1))
    if count <= 0:
        raise ValueError(f"rate limit count must be positive: {spec!r}")
    return count, float(_UNITS[m.group(2).lower()])


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[Hashable, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: Hashable, capacity: int, period: float, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        refill = capacity / period
        with self._lock:
            tokens, last = self._buckets.get(key, (float(capacity), now))
            tokens = min(float(capacity), tokens + (now - last) * refill)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True
