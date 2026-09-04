"""Database-backed sessions and rotating opaque refresh tokens.

Refresh tokens are bearer credentials, so only SHA-256 digests are persisted. A
used token is evidence of replay: the whole family and its session are revoked.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.auth_security import AuthSession
from app.models.user import RefreshToken, User
from app.utils.security import create_access_token, hash_one_time_token


class InvalidRefreshToken(Exception):
    pass


class RefreshTokenReuseDetected(InvalidRefreshToken):
    pass


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    session_id: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_expired(value: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= utcnow()


def _new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def refresh_token_is_reuse(token: RefreshToken) -> bool:
    """A rotated or revoked token is replay evidence, regardless of its age."""
    return token.used_at is not None or bool(token.is_revoked)


def _access_token(user: User, session: AuthSession, extra_claims: dict | None = None) -> str:
    claims = {
        "sub": user.id,
        "email": user.email,
        "sid": session.id,
        "auth_method": session.authentication_method,
    }
    if session.authentication_method == "admin":
        claims.update({"role": user.role, "is_admin": bool(user.is_superuser or user.role in {"admin", "moderator"}), "session_type": "admin"})
    if extra_claims:
        claims.update(extra_claims)
    return create_access_token(claims)


async def create_session_tokens(
    db: AsyncSession,
    user: User,
    *,
    authentication_method: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    device_name: str | None = None,
    extra_claims: dict | None = None,
    commit: bool = True,
) -> IssuedTokens:
    now = utcnow()
    expires_at = now + timedelta(days=settings.AUTH_SESSION_EXPIRE_DAYS)
    session = AuthSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        authentication_method=authentication_method,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:1024] or None,
        device_name=(device_name or "")[:100] or None,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    )
    raw_refresh = _new_refresh_token()
    refresh = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        session_id=session.id,
        family_id=str(uuid.uuid4()),
        token_hash=hash_one_time_token(raw_refresh),
        expires_at=min(expires_at, now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)),
        created_at=now,
        is_revoked=False,
    )
    db.add(session)
    db.add(refresh)
    if commit:
        await db.commit()
    return IssuedTokens(_access_token(user, session, extra_claims), raw_refresh, session.id)


async def rotate_refresh_token(db: AsyncSession, raw_token: str) -> IssuedTokens:
    digest = hash_one_time_token(raw_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == digest).with_for_update()
    )
    current = result.scalar_one_or_none()
    if current is None:
        raise InvalidRefreshToken()

    now = utcnow()
    if refresh_token_is_reuse(current):
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == current.family_id)
            .values(is_revoked=True, revoked_at=now)
        )
        await db.execute(
            update(AuthSession)
            .where(AuthSession.id == current.session_id)
            .values(revoked_at=now)
        )
        await db.commit()
        raise RefreshTokenReuseDetected()

    if is_expired(current.expires_at):
        current.is_revoked = True
        current.revoked_at = now
        await db.commit()
        raise InvalidRefreshToken()

    session = await db.get(AuthSession, current.session_id)
    user = await db.get(User, current.user_id)
    if session is None or user is None or not user.is_active or session.revoked_at is not None or is_expired(session.expires_at):
        current.is_revoked = True
        current.revoked_at = now
        await db.commit()
        raise InvalidRefreshToken()

    replacement_raw = _new_refresh_token()
    replacement = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=current.user_id,
        session_id=current.session_id,
        family_id=current.family_id,
        parent_id=current.id,
        token_hash=hash_one_time_token(replacement_raw),
        expires_at=min(session.expires_at, now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)),
        created_at=now,
        is_revoked=False,
    )
    current.used_at = now
    current.replaced_by_id = replacement.id
    current.is_revoked = True
    current.revoked_at = now
    session.last_seen_at = now
    db.add(replacement)
    await db.commit()
    return IssuedTokens(_access_token(user, session), replacement_raw, session.id)


async def revoke_session(db: AsyncSession, session_id: str, user_id: str) -> bool:
    now = utcnow()
    result = await db.execute(
        update(AuthSession)
        .where(AuthSession.id == session_id, AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now)
        .returning(AuthSession.id)
    )
    revoked = result.scalar_one_or_none() is not None
    if revoked:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == session_id, RefreshToken.is_revoked.is_(False))
            .values(is_revoked=True, revoked_at=now)
        )
    await db.commit()
    return revoked
