"""Rate limiting module using token bucket algorithm."""
import asyncio
import time
from typing import Dict, Optional
from collections import defaultdict


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum tokens (requests_per_minute)
            refill_rate: Tokens per second (capacity / 60)
        """
        self.capacity = capacity
        self.refill_rate = refill_rate / 60.0  # Convert RPM to per-second
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()

    def allow_request(self) -> bool:
        """
        Check if a request is allowed.

        Returns:
            True if tokens available, False if rate limited
        """
        now = time.monotonic()
        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )
        self.last_refill = now

        # Try to consume a token
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Async-safe in-memory rate limiter."""

    def __init__(self, default_rpm: int = 60):
        """
        Initialize rate limiter.

        Args:
            default_rpm: Default requests per minute
        """
        self.default_rpm = default_rpm
        self.buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.default_rpm, self.default_rpm)
        )
        self.lock = asyncio.Lock()

    async def is_allowed(
        self,
        key: str,
        limit: Optional[int] = None
    ) -> bool:
        """
        Check if request is allowed for given key.

        Args:
            key: Rate limit key (e.g., client IP)
            limit: Override limit for this key (requests per minute)

        Returns:
            True if allowed, False if rate limited
        """
        async with self.lock:
            # Create new bucket if needed with custom limit
            if limit and key not in self.buckets:
                self.buckets[key] = TokenBucket(limit, limit)

            bucket = self.buckets[key]
            return bucket.allow_request()

    async def cleanup_old_buckets(self, ttl_seconds: float = 3600.0) -> None:
        """
        Remove old buckets to prevent unbounded memory growth.

        Args:
            ttl_seconds: Time-to-live for unused buckets
        """
        async with self.lock:
            now = time.monotonic()
            expired = [
                key for key, bucket in self.buckets.items()
                if now - bucket.last_refill > ttl_seconds
            ]
            for key in expired:
                del self.buckets[key]

