"""Password-login integration tests for authoritative risk outcomes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.api.user import UserLogin, login
from app.models.user import User
from app.services.risk_policy_service import RiskFeatures, RiskPolicyError


def login_request(ip_address: str = "203.0.113.10") -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/user/login",
            "headers": [(b"user-agent", b"test-browser")],
            "client": (ip_address, 443),
            "server": ("test", 80),
            "scheme": "https",
            "query_string": b"",
        }
    )


def verified_user() -> User:
    return User(
        id="user-1",
        email="person@example.com",
        hashed_password="hash",
        is_active=True,
        is_verified=True,
        is_superuser=False,
        role="user",
        totp_enabled=False,
    )


@pytest.mark.asyncio
async def test_deterministic_deny_prevents_session_creation():
    user = verified_user()
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = lookup
    decision = SimpleNamespace(id="decision-1", outcome="deny")

    with patch("app.api.user.verify_password", return_value=True), patch(
        "app.api.user.build_login_features", new=AsyncMock(return_value=RiskFeatures(source_ip_blocked=True))
    ), patch("app.api.user.evaluate_and_persist", new=AsyncMock(return_value=decision)), patch(
        "app.api.user.create_session_tokens", new=AsyncMock()
    ) as create_tokens:
        login_input = UserLogin(email=user.email, password="not-persisted")
        request = login_request()
        response = Response()
        with pytest.raises(HTTPException) as raised:
            await login(login_input, request, response, db)

    assert raised.value.status_code == 403
    assert raised.value.detail == "Authentication denied by security policy"
    create_tokens.assert_not_awaited()


@pytest.mark.asyncio
async def test_risk_engine_failure_fails_closed_before_session_creation():
    user = verified_user()
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = lookup

    with patch("app.api.user.verify_password", return_value=True), patch(
        "app.api.user.build_login_features", new=AsyncMock(return_value=RiskFeatures())
    ), patch(
        "app.api.user.evaluate_and_persist",
        new=AsyncMock(side_effect=RiskPolicyError("audit unavailable")),
    ), patch("app.api.user.settings.RISK_POLICY_FAIL_CLOSED", True), patch(
        "app.api.user.create_session_tokens", new=AsyncMock()
    ) as create_tokens:
        login_input = UserLogin(email=user.email, password="not-persisted")
        request = login_request()
        response = Response()
        with pytest.raises(HTTPException) as raised:
            await login(login_input, request, response, db)

    assert raised.value.status_code == 503
    create_tokens.assert_not_awaited()
