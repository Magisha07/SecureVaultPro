"""
SecureVault - Behavioral Intrusion Detection System (IDS)
=========================================================
- Token Bucket: rate-limit operations (detect high-speed access).
- Pattern detection: sequential access (e.g. iterating all items in order).
Session is blocked if BOTH high speed AND sequential pattern are detected.
"""

import time
from collections import deque
from typing import List, Optional, Tuple


class TokenBucket:
    """
    Token bucket algorithm: refill tokens at fixed rate, consume per operation.
    If consumption exceeds refill, bucket empties => high speed detected.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        capacity: max tokens.
        refill_rate: tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, amount: int = 1) -> bool:
        """
        Consume `amount` tokens. Returns True if allowed, False if rate exceeded.
        """
        self._refill()
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class SequentialPatternDetector:
    """
    Detects sequential access: e.g. access pattern [1,2,3,4,...] or [a,b,c,...].
    We track last N resource IDs; if they form a strictly increasing sequence
    over a window, flag as sequential.
    """

    def __init__(self, window_size: int = 5):
        self.window_size = window_size
        self._recent: deque = deque(maxlen=window_size)
        # Map resource_id -> numeric order for comparison (use hash if string)
        self._id_to_ord: dict = {}
        self._next_ord = 0

    def _ordinal(self, resource_id: str) -> int:
        if resource_id not in self._id_to_ord:
            self._id_to_ord[resource_id] = self._next_ord
            self._next_ord += 1
        return self._id_to_ord[resource_id]

    def record_access(self, resource_id: str) -> None:
        self._recent.append(self._ordinal(resource_id))

    def is_sequential(self) -> bool:
        """
        True if last `window_size` accesses are strictly increasing (sequential).
        """
        if len(self._recent) < self.window_size:
            return False
        recent = list(self._recent)
        for i in range(1, len(recent)):
            if recent[i] <= recent[i - 1]:
                return False
        return True


class BehavioralIDS:
    """
    Combines Token Bucket (speed) and Sequential Pattern detection.
    Block session only when BOTH conditions are true.
    """

    def __init__(
        self,
        bucket_capacity: int = 10,
        refill_rate: float = 2.0,
        pattern_window: int = 5,
    ):
        self.token_bucket = TokenBucket(bucket_capacity, refill_rate)
        self.pattern_detector = SequentialPatternDetector(pattern_window)
        self._blocked = False

    def record_and_check(self, resource_id: str) -> Tuple[bool, str]:
        """
        Record an access (e.g. search/download) and check if session should be blocked.
        Returns (allowed, message). If blocked, allowed=False.
        """
        if self._blocked:
            return False, "Session blocked by Behavioral IDS (previous violation)."

        # Speed check
        if not self.token_bucket.consume(1):
            self.pattern_detector.record_access(resource_id)
            if self.pattern_detector.is_sequential():
                self._blocked = True
                return False, (
                    "Behavioral IDS: High speed + sequential access pattern detected. Session blocked."
                )
            return False, "Rate limit exceeded. Slow down."

        # Record for pattern analysis
        self.pattern_detector.record_access(resource_id)
        if self.pattern_detector.is_sequential():
            # Sequential but under rate limit - allow but could log
            pass
        return True, "OK"

    def is_blocked(self) -> bool:
        return self._blocked

    def reset(self) -> None:
        """Reset on logout or after cooldown (demo)."""
        self._blocked = False
        self.token_bucket.tokens = float(self.token_bucket.capacity)
        self.token_bucket.last_refill = time.monotonic()
        self.pattern_detector._recent.clear()
