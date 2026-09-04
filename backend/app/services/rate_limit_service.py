"""Low-latency application rate limiting backed by Redis with a local fallback."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitPolicy:
    limit: int
    window_seconds: int


POLICIES = {
    "login": RateLimitPolicy(limit=10, window_seconds=300),
    "registration": RateLimitPolicy(limit=5, window_seconds=3600),
    "password_reset": RateLimitPolicy(limit=5, window_seconds=3600),
    "mfa": RateLimitPolicy(limit=5, window_seconds=300),
    "api": RateLimitPolicy(limit=settings.RATE_LIMIT_REQUESTS, window_seconds=settings.RATE_LIMIT_WINDOW),
}

_INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""


def request_is_allowed(count: int, policy: RateLimitPolicy) -> bool:
    """Pure fixed-window decision shared by runtime enforcement and simulations."""
    return count <= policy.limit


class RateLimiter:
    """Atomic fixed-window limiter that avoids a Temporal round trip per request."""

    def __init__(self) -> None:
        self._redis = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=settings.RATE_LIMIT_REDIS_TIMEOUT_SECONDS,
            socket_timeout=settings.RATE_LIMIT_REDIS_TIMEOUT_SECONDS,
        )
        self._fallback: dict[str, tuple[int, float]] = {}
        self._fallback_lock = asyncio.Lock()
        self._warned_about_fallback = False

    async def check(self, key: str, limit_type: str) -> dict[str, Any]:
        policy = POLICIES.get(limit_type, POLICIES["api"])
        now = time.time()
        bucket = int(now // policy.window_seconds)
        redis_key = f"rate_limit:v2:{limit_type}:{key}:{bucket}"

        try:
            count, ttl = await self._redis.eval(
                _INCREMENT_SCRIPT,
                1,
                redis_key,
                policy.window_seconds,
            )
            count = int(count)
            retry_after = max(1, int(ttl))
        except (redis.RedisError, OSError) as exc:
            if not self._warned_about_fallback:
                logger.warning("Redis rate limiter unavailable; using process-local fallback: %s", exc)
                self._warned_about_fallback = True
            count, retry_after = await self._check_fallback(redis_key, policy.window_seconds, now)

        reset_at = datetime.fromtimestamp(now + retry_after, tz=timezone.utc).isoformat()
        return {
            "allowed": request_is_allowed(count, policy),
            "remaining": max(0, policy.limit - count),
            "reset_time": reset_at,
            "current_count": count,
            "limit": policy.limit,
            "retry_after": retry_after if count > policy.limit else None,
            "blocked_reason": "Too many requests" if count > policy.limit else None,
        }

    async def _check_fallback(self, key: str, window_seconds: int, now: float) -> tuple[int, int]:
        async with self._fallback_lock:
            count, expires_at = self._fallback.get(key, (0, now + window_seconds))
            if expires_at <= now:
                count, expires_at = 0, now + window_seconds
            count += 1
            self._fallback[key] = (count, expires_at)
            expired = [stored_key for stored_key, (_, expiry) in self._fallback.items() if expiry <= now]
            for stored_key in expired:
                self._fallback.pop(stored_key, None)
            return count, max(1, int(expires_at - now))

    async def reset(self) -> int:
        """Clear active fixed-window buckets from Redis and local fallback state."""
        cleared = 0
        try:
            keys = [key async for key in self._redis.scan_iter(match="rate_limit:v2:*")]
            if keys:
                cleared = int(await self._redis.delete(*keys))
        except (redis.RedisError, OSError) as exc:
            logger.warning("Redis rate-limit reset unavailable: %s", exc)
        async with self._fallback_lock:
            cleared += len(self._fallback)
            self._fallback.clear()
        return cleared

    async def close(self) -> None:
        await self._redis.aclose()


rate_limiter = RateLimiter()
