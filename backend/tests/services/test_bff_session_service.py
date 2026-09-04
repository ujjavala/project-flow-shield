"""Security-focused tests for Redis-backed browser sessions."""

import hashlib
import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services import bff_session_service as service


@pytest.mark.asyncio
async def test_create_session_hashes_browser_handle_and_stores_server_side_tokens():
    redis = AsyncMock()
    with (
        patch.object(service, "from_url", return_value=redis),
        patch.object(service, "new_session_id", return_value="raw-browser-session"),
        patch.object(service, "new_csrf_token", return_value="csrf-secret"),
    ):
        browser_session_id, csrf_token = await service.create_bff_session(
            user_id="user-1",
            access_token="access-secret",
            refresh_token="refresh-secret",
            session_id="auth-session-1",
            is_admin=False,
        )

    assert browser_session_id == "raw-browser-session"
    assert csrf_token == "csrf-secret"
    key, ttl, encoded = redis.setex.await_args.args
    assert key == "bff:session:" + hashlib.sha256(b"raw-browser-session").hexdigest()
    assert "raw-browser-session" not in key
    assert ttl == service.settings.BFF_SESSION_EXPIRE_SECONDS
    payload = json.loads(encoded)
    assert payload["access_token"] == "access-secret"
    assert payload["refresh_token"] == "refresh-secret"
    assert payload["csrf_digest"] == hashlib.sha256(b"csrf-secret").hexdigest()
    redis.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored",
    [
        "not-json",
        "[]",
        '{"access_token":"only-one-field"}',
        json.dumps(
            {
                "user_id": "user-1",
                "access_token": "access",
                "refresh_token": "refresh",
                "auth_session_id": "auth-session",
                "is_admin": "false",
                "csrf_digest": "0" * 64,
            }
        ),
    ],
)
async def test_malformed_session_is_deleted_and_rejected(stored):
    redis = AsyncMock()
    redis.get.return_value = stored
    with patch.object(service, "from_url", return_value=redis):
        result = await service.get_bff_session("browser-session")

    assert result is None
    redis.delete.assert_awaited_once()
    redis.expire.assert_not_awaited()
    redis.aclose.assert_awaited_once()


def test_csrf_requires_matching_cookie_header_and_session_digest():
    token = "csrf-secret"
    session = {"csrf_digest": hashlib.sha256(token.encode()).hexdigest()}

    assert service.valid_csrf(session, token, token)
    assert not service.valid_csrf(session, token, "different")
    assert not service.valid_csrf(session, None, token)
    assert not service.valid_csrf({}, token, token)


@pytest.mark.asyncio
async def test_update_tokens_preserves_session_metadata():
    original = {
        "user_id": "user-1",
        "access_token": "old-access",
        "refresh_token": "old-refresh",
        "auth_session_id": "auth-session-1",
        "is_admin": True,
        "csrf_digest": "a" * 64,
    }
    redis = AsyncMock()
    with (
        patch.object(service, "get_bff_session", AsyncMock(return_value=original.copy())),
        patch.object(service, "from_url", return_value=redis),
    ):
        updated = await service.update_bff_tokens("browser-session", "new-access", "new-refresh")

    assert updated is True
    payload = json.loads(redis.setex.await_args.args[2])
    assert payload == {**original, "access_token": "new-access", "refresh_token": "new-refresh"}
    redis.aclose.assert_awaited_once()
