from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.models.auth_security import AuthSession
from app.models.user import User
from app.services.principal_service import resolve_access_principal
from app.services.session_service import utcnow


def principal_records(*, revoked=False, auth_method="password"):
    user = User(id="user-1", email="user@example.test", is_active=True)
    session = AuthSession(
        id="session-1",
        user_id=user.id,
        authentication_method=auth_method,
        expires_at=utcnow() + timedelta(hours=1),
        revoked_at=utcnow() if revoked else None,
    )
    db = AsyncMock()
    db.get = AsyncMock(side_effect=[session, user])
    return db


@pytest.mark.asyncio
async def test_live_access_token_resolves_to_session_bound_principal():
    db = principal_records()
    claims = {"type": "access", "sub": "user-1", "sid": "session-1"}

    with patch("app.services.principal_service.verify_token", return_value=claims):
        principal = await resolve_access_principal("opaque-jwt", db)

    assert principal.user.id == "user-1"
    assert principal.session.id == "session-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [None, {}, {"type": "refresh", "sub": "user-1", "sid": "session-1"}, {"type": "access", "sub": "user-1"}])
async def test_non_access_or_unbound_tokens_are_rejected(claims):
    db = AsyncMock()
    with patch("app.services.principal_service.verify_token", return_value=claims):
        with pytest.raises(HTTPException) as exc:
            await resolve_access_principal("opaque-jwt", db)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_revoked_session_is_rejected_immediately():
    db = principal_records(revoked=True)
    claims = {"type": "access", "sub": "user-1", "sid": "session-1"}

    with patch("app.services.principal_service.verify_token", return_value=claims):
        with pytest.raises(HTTPException) as exc:
            await resolve_access_principal("opaque-jwt", db)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_user_session_cannot_be_used_as_admin_session():
    db = principal_records(auth_method="password")
    claims = {
        "type": "access",
        "sub": "user-1",
        "sid": "session-1",
        "is_admin": True,
        "session_type": "admin",
    }

    with patch("app.services.principal_service.verify_token", return_value=claims):
        with pytest.raises(HTTPException) as exc:
            await resolve_access_principal("opaque-jwt", db, require_admin_session=True)
    assert exc.value.status_code == 403
