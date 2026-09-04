"""Focused tests for durable PKCE issuance and redemption."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.pkce import PKCERequest, PKCETokenRequest, PKCEUtils
from app.services.pkce_service import (
    PKCEClientError,
    PKCEGrantError,
    get_registered_client,
    issue_authorization_code,
    redeem_authorization_code,
)
from app.services.session_service import IssuedTokens


@pytest.fixture
def public_client():
    return SimpleNamespace(
        client_id="public-client",
        client_secret=None,
        is_confidential=False,
        is_active=True,
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
        scope="read write",
    )


@pytest.fixture
def pkce_pair():
    verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    return verifier, PKCEUtils.generate_code_challenge(verifier)


@pytest.mark.asyncio
async def test_issued_code_is_hashed_at_rest(public_client, pkce_pair):
    verifier, challenge = pkce_pair
    db = AsyncMock()
    db.add = MagicMock()
    request = PKCERequest(
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        scope="read",
        state="state-value-1234567890",
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client):
        raw_code, expires_in = await issue_authorization_code(db, request, "user-123")

    stored_grant = db.add.call_args.args[0]
    assert stored_grant.code != raw_code
    assert len(stored_grant.code) == 64
    assert stored_grant.code_challenge == challenge
    assert stored_grant.code_challenge_method == "S256"
    assert expires_in <= 600
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_oidc_request_persists_nonce_and_authentication_time(public_client, pkce_pair):
    _, challenge = pkce_pair
    public_client.scope = "openid profile email"
    db = AsyncMock()
    db.add = MagicMock()
    auth_time = datetime(2026, 9, 4, tzinfo=timezone.utc)
    request = PKCERequest(
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        scope="openid",
        state="state-value-1234567890",
        nonce="nonce-value",
        code_challenge=challenge,
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client):
        await issue_authorization_code(db, request, "user-123", auth_time)

    stored_grant = db.add.call_args.args[0]
    assert stored_grant.nonce == "nonce-value"
    assert stored_grant.auth_time == auth_time


@pytest.mark.asyncio
async def test_registered_redirect_uri_requires_exact_match(public_client):
    db = AsyncMock()
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = public_client
    db.execute.return_value = lookup

    with pytest.raises(PKCEClientError):
        await get_registered_client(db, public_client.client_id, public_client.redirect_uris[0] + "/attacker")

    with pytest.raises(PKCEClientError):
        await get_registered_client(db, public_client.client_id, public_client.redirect_uris[0] + "#fragment")


@pytest.mark.asyncio
async def test_valid_public_client_grant_is_consumed_once(public_client, pkce_pair):
    verifier, challenge = pkce_pair
    db = AsyncMock()
    db.add = MagicMock()
    grant = SimpleNamespace(
        id="grant-1",
        user_id="user-123",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = grant
    consume = MagicMock()
    consume.scalar_one_or_none.return_value = grant.id
    db.execute.side_effect = [lookup, consume]
    db.get.return_value = SimpleNamespace(id="user-123", email="user@example.com", is_active=True, role="user", is_superuser=False)
    request = PKCETokenRequest(
        code="raw-authorization-code",
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        code_verifier=verifier,
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client), \
         patch("app.services.pkce_service.create_session_tokens", return_value=IssuedTokens("access-token", "refresh-token", "session-1")):
        result = await redeem_authorization_code(db, request)

    assert result["access_token"] == "access-token"
    assert result["refresh_token"] == "refresh-token"
    assert db.execute.await_count == 2
    db.commit.assert_awaited_once()
    assert db.add.call_args.args[0].client_id == public_client.client_id


@pytest.mark.asyncio
async def test_oidc_grant_returns_id_token_with_bound_context(public_client, pkce_pair):
    verifier, challenge = pkce_pair
    db = AsyncMock()
    db.add = MagicMock()
    grant = SimpleNamespace(
        id="grant-1",
        user_id="user-123",
        scope="openid",
        nonce="nonce-value",
        auth_time=datetime(2026, 9, 4, tzinfo=timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = grant
    consume = MagicMock()
    consume.scalar_one_or_none.return_value = grant.id
    db.execute.side_effect = [lookup, consume]
    db.get.return_value = SimpleNamespace(id="user-123", email="user@example.com", is_active=True, role="user", is_superuser=False)
    request = PKCETokenRequest(
        code="raw-authorization-code",
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        code_verifier=verifier,
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client), \
         patch("app.services.pkce_service.create_session_tokens", return_value=IssuedTokens("access-token", "refresh-token", "session-1")), \
         patch("app.services.pkce_service.issue_id_token", return_value="id-token") as issue:
        result = await redeem_authorization_code(db, request)

    assert result["id_token"] == "id-token"
    issue.assert_called_once_with(
        subject="user-123",
        audience=public_client.client_id,
        auth_time=grant.auth_time,
        nonce="nonce-value",
    )


@pytest.mark.asyncio
async def test_wrong_verifier_does_not_consume_grant(public_client, pkce_pair):
    _, challenge = pkce_pair
    db = AsyncMock()
    grant = SimpleNamespace(
        id="grant-1",
        user_id="user-123",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = grant
    db.execute.return_value = lookup
    request = PKCETokenRequest(
        code="raw-authorization-code",
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        code_verifier="z" * 43,
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client):
        with pytest.raises(PKCEGrantError):
            await redeem_authorization_code(db, request)

    assert db.execute.await_count == 1
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_concurrent_loser_cannot_receive_tokens(public_client, pkce_pair):
    verifier, challenge = pkce_pair
    db = AsyncMock()
    grant = SimpleNamespace(
        id="grant-1",
        user_id="user-123",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = grant
    consume = MagicMock()
    consume.scalar_one_or_none.return_value = None
    db.execute.side_effect = [lookup, consume]
    request = PKCETokenRequest(
        code="raw-authorization-code",
        client_id=public_client.client_id,
        redirect_uri=public_client.redirect_uris[0],
        code_verifier=verifier,
    )

    with patch("app.services.pkce_service.get_registered_client", return_value=public_client):
        with pytest.raises(PKCEGrantError):
            await redeem_authorization_code(db, request)

    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()
