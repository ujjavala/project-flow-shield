"""BFF route tests for live-session validation and token non-disclosure."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.api.routes import bff


@pytest.mark.asyncio
async def test_session_status_rejects_revoked_underlying_auth_session():
    request = SimpleNamespace(cookies={"bff_session": "browser-session"})
    stored = {"access_token": "revoked-access-token"}
    db = AsyncMock()

    with (
        patch.object(bff, "get_bff_session", AsyncMock(return_value=stored)),
        patch.object(
            bff,
            "resolve_access_principal",
            AsyncMock(side_effect=HTTPException(status_code=401, detail="Session is invalid")),
        ),
        patch.object(bff, "delete_bff_session", AsyncMock()) as delete_session,
    ):
        result = await bff.session_status(request, db)

    assert result == {"authenticated": False}
    delete_session.assert_awaited_once_with("browser-session")


@pytest.mark.asyncio
async def test_session_status_returns_only_minimal_identity_metadata():
    request = SimpleNamespace(cookies={"bff_session": "browser-session"})
    stored = {
        "access_token": "server-only-access-token",
        "refresh_token": "server-only-refresh-token",
        "is_admin": True,
    }
    user = SimpleNamespace(id="user-1", role="admin", is_superuser=True)
    principal = SimpleNamespace(user=user)

    with (
        patch.object(bff, "get_bff_session", AsyncMock(return_value=stored)),
        patch.object(bff, "resolve_access_principal", AsyncMock(return_value=principal)),
    ):
        result = await bff.session_status(request, AsyncMock())

    assert result == {"authenticated": True, "user": {"id": "user-1", "is_admin": True}}
    serialized = str(result)
    assert "server-only-access-token" not in serialized
    assert "server-only-refresh-token" not in serialized


@pytest.mark.asyncio
async def test_me_uses_live_principal_and_never_returns_tokens():
    request = SimpleNamespace(cookies={"bff_session": "browser-session"})
    stored = {"access_token": "server-only-access-token"}
    user = SimpleNamespace(id="user-1", email="owner@example.test", role="user", is_superuser=False)

    with (
        patch.object(bff, "get_bff_session", AsyncMock(return_value=stored)),
        patch.object(
            bff,
            "resolve_access_principal",
            AsyncMock(return_value=SimpleNamespace(user=user)),
        ) as resolve,
    ):
        result = await bff.me(request, AsyncMock())

    resolve.assert_awaited_once()
    assert result == {
        "id": "user-1",
        "email": "owner@example.test",
        "role": "user",
        "is_admin": False,
    }
    assert "token" not in str(result).lower()
