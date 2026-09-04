"""Focused security tests for session and refresh-token lifecycle."""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.auth_security import AuthSession
from app.models.user import RefreshToken, User
from app.services.session_service import (
    RefreshTokenReuseDetected,
    create_session_tokens,
    rotate_refresh_token,
    utcnow,
)
from app.utils.security import hash_one_time_token, verify_token


def user() -> User:
    return User(id="user-1", email="user@example.com", hashed_password="unused", is_active=True, is_verified=True)


@pytest.mark.asyncio
async def test_session_issuance_persists_only_refresh_token_hash():
    db = AsyncMock()
    db.add = MagicMock()

    issued = await create_session_tokens(db, user(), authentication_method="password")

    added = [call.args[0] for call in db.add.call_args_list]
    session = next(item for item in added if isinstance(item, AuthSession))
    refresh = next(item for item in added if isinstance(item, RefreshToken))
    assert refresh.token_hash == hash_one_time_token(issued.refresh_token)
    assert issued.refresh_token not in refresh.token_hash
    assert refresh.session_id == session.id == issued.session_id
    assert verify_token(issued.access_token)["sid"] == session.id
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_refresh_rotates_once_in_same_family():
    raw = "r" * 64
    current = RefreshToken(
        id="token-1", user_id="user-1", session_id="session-1", family_id="family-1",
        token_hash=hash_one_time_token(raw), expires_at=utcnow() + timedelta(days=1), is_revoked=False,
    )
    session = AuthSession(
        id="session-1", user_id="user-1", authentication_method="password",
        expires_at=utcnow() + timedelta(days=2), last_seen_at=utcnow(),
    )
    db = AsyncMock()
    db.add = MagicMock()
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = current
    db.execute.return_value = lookup
    db.get.side_effect = [session, user()]

    issued = await rotate_refresh_token(db, raw)

    replacement = db.add.call_args.args[0]
    assert current.used_at is not None and current.is_revoked is True
    assert replacement.family_id == current.family_id
    assert replacement.parent_id == current.id
    assert replacement.token_hash == hash_one_time_token(issued.refresh_token)
    assert replacement.token_hash != current.token_hash
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_family_and_session():
    raw = "r" * 64
    current = RefreshToken(
        id="token-1", user_id="user-1", session_id="session-1", family_id="family-1",
        token_hash=hash_one_time_token(raw), expires_at=utcnow() + timedelta(days=1),
        is_revoked=True, used_at=utcnow(),
    )
    db = AsyncMock()
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = current
    db.execute.side_effect = [lookup, MagicMock(), MagicMock()]

    with pytest.raises(RefreshTokenReuseDetected):
        await rotate_refresh_token(db, raw)

    assert db.execute.await_count == 3
    db.commit.assert_awaited_once()
