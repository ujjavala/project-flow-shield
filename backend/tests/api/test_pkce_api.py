"""API contract tests for the OAuth 2.1 PKCE endpoints."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.routes import pkce
from app.models.pkce import PKCEUtils
from app.services.pkce_service import PKCEGrantError


@pytest.fixture
def challenge():
    verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    return verifier, PKCEUtils.generate_code_challenge(verifier)


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(pkce.router)

    db = AsyncMock()
    user = SimpleNamespace(id="user-123", is_active=True, is_verified=True)

    async def override_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[pkce.get_db] = override_db
    app.dependency_overrides[pkce._current_user] = override_user

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        yield test_client


@pytest.mark.asyncio
async def test_authorize_issues_code_and_preserves_state(client, challenge):
    _, code_challenge = challenge
    payload = {
        "client_id": "public-client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read",
        "state": "state-value-1234567890",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_type": "code",
    }

    with patch("app.api.routes.pkce.issue_authorization_code", return_value=("raw-code", 600)) as issue:
        response = await client.post("/oauth2/pkce/authorize", json=payload)

    assert response.status_code == 200
    assert response.json() == {
        "code": "raw-code",
        "state": payload["state"],
        "expires_in": 600,
    }
    issue.assert_awaited_once()


@pytest.mark.asyncio
async def test_authorize_rejects_plain_challenge_before_issuing_code(client):
    payload = {
        "client_id": "public-client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read",
        "state": "state-value-1234567890",
        "code_challenge": "x" * 43,
        "code_challenge_method": "plain",
        "response_type": "code",
    }

    with patch("app.api.routes.pkce.issue_authorization_code") as issue:
        response = await client.post("/oauth2/pkce/authorize", json=payload)

    assert response.status_code == 422
    issue.assert_not_called()


@pytest.mark.asyncio
async def test_token_invalid_grant_has_oauth_shape_and_no_store_headers(client, challenge):
    verifier, _ = challenge
    payload = {
        "grant_type": "authorization_code",
        "code": "invalid-code",
        "client_id": "public-client",
        "redirect_uri": "http://localhost:3000/callback",
        "code_verifier": verifier,
    }

    with patch("app.api.routes.pkce.redeem_authorization_code", side_effect=PKCEGrantError()):
        response = await client.post("/oauth2/pkce/token", json=payload)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_token_success_is_not_cacheable(client, challenge):
    verifier, _ = challenge
    payload = {
        "grant_type": "authorization_code",
        "code": "valid-code",
        "client_id": "public-client",
        "redirect_uri": "http://localhost:3000/callback",
        "code_verifier": verifier,
    }
    token_data = {
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "token_type": "Bearer",
        "expires_in": 1800,
        "scope": "read",
    }

    with patch("app.api.routes.pkce.redeem_authorization_code", return_value=token_data):
        response = await client.post("/oauth2/pkce/token", json=payload)

    assert response.status_code == 200
    assert response.json() == token_data
    assert response.headers["cache-control"] == "no-store"
