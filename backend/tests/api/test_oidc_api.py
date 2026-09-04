"""API contract tests for OIDC discovery, JWKS, and UserInfo."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.routes import oidc


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(oidc.router)
    db = AsyncMock()

    async def override_db():
        yield db

    app.dependency_overrides[oidc.get_db] = override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        yield test_client, db


@pytest.mark.asyncio
async def test_discovery_advertises_authorization_code_s256_and_rs256(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(oidc.settings, "OIDC_ISSUER", "https://issuer.example/")

    response = await test_client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == "https://issuer.example"
    assert body["response_types_supported"] == ["code"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    assert body["jwks_uri"] == "https://issuer.example/oauth2/jwks"


@pytest.mark.asyncio
async def test_jwks_never_returns_private_key_material(client):
    test_client, _ = client
    public_jwk = {"kty": "RSA", "kid": "active", "use": "sig", "alg": "RS256", "n": "abc", "e": "AQAB"}

    with patch("app.api.routes.oidc.get_jwks", return_value={"keys": [public_jwk]}):
        response = await test_client.get("/oauth2/jwks")

    assert response.status_code == 200
    assert response.json() == {"keys": [public_jwk]}
    assert "d" not in response.json()["keys"][0]
    assert response.headers["cache-control"] == "public, max-age=300"


@pytest.mark.asyncio
async def test_userinfo_returns_only_claims_authorized_by_scope(client):
    test_client, db = client
    token_record = SimpleNamespace(
        user_id="user-123",
        client_id="client-123",
        scope="openid email",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = token_record
    db.execute.return_value = lookup
    db.get.return_value = SimpleNamespace(
        id="user-123",
        email="person@example.com",
        is_verified=True,
        is_active=True,
        first_name="Private",
        last_name="Person",
        username="person",
        profile_picture=None,
    )

    with patch("app.api.routes.oidc.verify_token", return_value={
        "sub": "user-123", "client_id": "client-123", "type": "access"
    }):
        response = await test_client.get(
            "/oauth2/userinfo", headers={"Authorization": "Bearer access-token"}
        )

    assert response.status_code == 200
    assert response.json() == {
        "sub": "user-123", "email": "person@example.com", "email_verified": True
    }
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_userinfo_rejects_non_oidc_access_token(client):
    test_client, db = client
    token_record = SimpleNamespace(
        user_id="user-123",
        client_id="client-123",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = token_record
    db.execute.return_value = lookup

    with patch("app.api.routes.oidc.verify_token", return_value={
        "sub": "user-123", "client_id": "client-123", "type": "access"
    }):
        response = await test_client.get(
            "/oauth2/userinfo", headers={"Authorization": "Bearer access-token"}
        )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
