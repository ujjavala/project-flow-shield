"""Tests for the atomic Redis-backed rate-limit service."""

from unittest.mock import AsyncMock

import pytest

from app.services.rate_limit_service import POLICIES, RateLimiter


@pytest.mark.asyncio
async def test_request_at_limit_is_allowed_and_next_is_blocked():
    limiter = RateLimiter()
    policy = POLICIES["login"]
    limiter._redis.eval = AsyncMock(
        side_effect=[
            [policy.limit, 120],
            [policy.limit + 1, 119],
        ]
    )

    at_limit = await limiter.check("ip_hash", "login")
    over_limit = await limiter.check("ip_hash", "login")

    assert at_limit["allowed"] is True
    assert at_limit["remaining"] == 0
    assert over_limit["allowed"] is False
    assert over_limit["retry_after"] == 119

    await limiter.close()


@pytest.mark.asyncio
async def test_password_reset_uses_dedicated_policy():
    limiter = RateLimiter()
    limiter._redis.eval = AsyncMock(return_value=[1, 3000])

    result = await limiter.check("ip_hash", "password_reset")

    assert result["allowed"] is True
    assert result["limit"] == 5
    assert result["remaining"] == 4

    await limiter.close()


@pytest.mark.asyncio
async def test_reset_clears_redis_and_process_local_buckets():
    limiter = RateLimiter()

    async def keys():
        for key in ("rate_limit:v2:login:a:1", "rate_limit:v2:api:b:1"):
            yield key

    limiter._redis.scan_iter = lambda **_: keys()
    limiter._redis.delete = AsyncMock(return_value=2)
    limiter._fallback["local-bucket"] = (3, 9999999999)

    cleared = await limiter.reset()

    assert cleared == 3
    limiter._redis.delete.assert_awaited_once_with(
        "rate_limit:v2:login:a:1",
        "rate_limit:v2:api:b:1",
    )
    assert limiter._fallback == {}
    await limiter.close()
