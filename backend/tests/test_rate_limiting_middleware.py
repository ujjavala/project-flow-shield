"""Integration tests for authentication endpoint rate limiting."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app.middleware.security import RateLimitingMiddleware


def make_request(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers or [],
            "client": ("203.0.113.10", 1234),
            "scheme": "https",
            "server": ("test", 443),
            "query_string": b"",
        }
    )


def test_authentication_routes_use_specific_policies():
    middleware = RateLimitingMiddleware(FastAPI())

    assert middleware._determine_limit_type(make_request("/user/login")) == "login"
    assert middleware._determine_limit_type(make_request("/user/register")) == "registration"
    assert middleware._determine_limit_type(make_request("/user/password-reset/request")) == "password_reset"
    assert middleware._determine_limit_type(make_request("/user/password-reset/confirm")) == "password_reset"


def test_untrusted_forwarded_header_does_not_change_identifier():
    middleware = RateLimitingMiddleware(FastAPI())
    plain = make_request("/user/login")
    spoofed = make_request("/user/login", [(b"x-forwarded-for", b"198.51.100.5")])

    assert middleware._get_client_identifier(plain) == middleware._get_client_identifier(spoofed)


@pytest.mark.asyncio
async def test_blocked_authentication_request_returns_429_with_headers():
    app = FastAPI()
    app.add_middleware(RateLimitingMiddleware)

    @app.post("/user/login")
    async def login():
        return {"called": True}

    blocked = {
        "allowed": False,
        "remaining": 0,
        "reset_time": "2026-09-04T12:00:00+00:00",
        "current_count": 11,
        "limit": 10,
        "retry_after": 42,
        "blocked_reason": "Too many requests",
    }

    with patch("app.middleware.security.rate_limiter.check", new=AsyncMock(return_value=blocked)) as check:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/user/login")

    assert response.status_code == 429
    assert response.json()["error"] == "rate_limit_exceeded"
    assert response.headers["retry-after"] == "42"
    assert response.headers["x-ratelimit-limit"] == "10"
    assert response.headers["x-ratelimit-remaining"] == "0"
    assert check.await_args.args[1] == "login"


@pytest.mark.asyncio
async def test_allowed_request_receives_rate_limit_headers():
    app = FastAPI()
    app.add_middleware(RateLimitingMiddleware)

    @app.post("/user/register")
    async def register():
        return {"called": True}

    allowed = {
        "allowed": True,
        "remaining": 4,
        "reset_time": "2026-09-04T12:00:00+00:00",
        "current_count": 1,
        "limit": 5,
        "retry_after": None,
        "blocked_reason": None,
    }

    with patch("app.middleware.security.rate_limiter.check", new=AsyncMock(return_value=allowed)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/user/register")

    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"] == "5"
    assert response.headers["x-ratelimit-remaining"] == "4"
    assert response.headers["x-rate-limit-type"] == "registration"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/health", "/health/live", "/health/ready", "/metrics"])
async def test_infrastructure_probes_bypass_rate_limiting(path):
    app = FastAPI()
    app.add_middleware(RateLimitingMiddleware)

    @app.get(path)
    async def probe():
        return {"ready": True}

    with patch("app.middleware.security.rate_limiter.check", new=AsyncMock()) as check:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get(path)

    assert response.status_code == 200
    check.assert_not_awaited()
