"""Single session-aware authentication boundary for bearer access tokens."""

from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth_security import AuthSession
from app.models.user import User
from app.services.session_service import is_expired
from app.utils.security import verify_token


@dataclass(frozen=True)
class AccessPrincipal:
    user: User
    session: AuthSession
    claims: dict


async def resolve_access_principal(
    raw_token: str | None,
    db: AsyncSession,
    *,
    require_admin_session: bool = False,
) -> AccessPrincipal:
    """Validate an access JWT and bind it to a live database session and user."""
    payload = verify_token(raw_token) if raw_token else None
    if (
        not payload
        or payload.get("type") != "access"
        or not payload.get("sub")
        or not payload.get("sid")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = await db.get(AuthSession, payload["sid"])
    user = await db.get(User, payload["sub"])
    if (
        session is None
        or user is None
        or session.user_id != user.id
        or not user.is_active
        or session.revoked_at is not None
        or is_expired(session.expires_at)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if require_admin_session and (
        session.authentication_method != "admin"
        or payload.get("session_type") != "admin"
        or payload.get("is_admin") is not True
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative session required",
        )

    return AccessPrincipal(user=user, session=session, claims=payload)
