"""Focused authorization tests for IAM management."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.iam_management import _internal_error, _require_scope_access, router
from app.services.iam_service import IAMService
from app.utils.iam_decorators import IAMContext


@pytest.mark.asyncio
async def test_iam_mutation_requires_bearer_authentication():
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/iam/roles",
            json={"name": "operator", "display_name": "Operator", "scope": "global"},
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_non_superuser_cannot_mutate_global_iam():
    user = SimpleNamespace(id="user-1", is_superuser=False)
    service = AsyncMock()
    context = SimpleNamespace(user=user, iam_service=service)

    with pytest.raises(HTTPException) as raised:
        await _require_scope_access(context, "global")

    assert raised.value.status_code == 403
    service.get_user_accessible_scopes.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_mutation_requires_exact_access():
    user = SimpleNamespace(id="user-1", is_superuser=False)
    service = AsyncMock()
    service.get_user_accessible_scopes.return_value = [{"id": "scope-a"}]
    context = SimpleNamespace(user=user, iam_service=service)

    await _require_scope_access(context, "scope-a")
    with pytest.raises(HTTPException) as raised:
        await _require_scope_access(context, "scope-b")

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_superuser_permission_evaluation_is_explicit():
    user = SimpleNamespace(id="admin-1", is_active=True, is_superuser=True)
    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = user_result

    result = await IAMService(db)._evaluate_permission_direct(
        user_id="admin-1",
        permission_name="iam.roles.create",
    )

    assert result["access_granted"] is True
    assert result["reason"] == "superuser"


@pytest.mark.asyncio
async def test_scope_aware_permission_requires_role_scope_assignment():
    permission = SimpleNamespace(is_scope_aware=True, scope_types=None)
    assignment_result = MagicMock()
    assignment_result.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = assignment_result

    allowed = await IAMService(db)._is_permission_applicable_to_scope(
        permission=permission,
        scope_id="scope-b",
        user_id="user-1",
        role_id="role-1",
    )

    assert allowed is False


@pytest.mark.asyncio
async def test_permission_evaluation_error_is_fail_closed_and_sanitized():
    db = AsyncMock()
    service = IAMService(db)
    service._get_cached_permission_evaluation = AsyncMock(return_value=None)
    service._evaluate_permission_direct = AsyncMock(
        side_effect=RuntimeError("database credentials and internal topology")
    )

    result = await service.evaluate_user_permission(
        user_id="user-1",
        permission_name="user.read",
    )

    assert result["access_granted"] is False
    assert result["reason"] == "evaluation_error"
    assert "database" not in result["reason"]


def test_iam_internal_error_does_not_expose_exception_details(caplog):
    canary = "password=database-secret"

    error = _internal_error("list_roles", RuntimeError(canary))

    assert error.status_code == 500
    assert error.detail == "IAM service operation failed"
    assert canary not in caplog.text
    assert "RuntimeError" in caplog.text
