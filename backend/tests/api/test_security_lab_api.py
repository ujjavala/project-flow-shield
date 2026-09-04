"""Admin API contract tests for listing, running, and persisting lab evidence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api import security_lab


@pytest.mark.asyncio
async def test_scenario_catalog_requires_admin_authentication():
    app = FastAPI()
    app.include_router(security_lab.router)

    async def override_db():
        yield AsyncMock()

    app.dependency_overrides[security_lab.get_db] = override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        response = await test_client.get("/admin/security-lab/scenarios")

    assert response.status_code in {401, 403}


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(security_lab.router)
    db = AsyncMock()
    db.add = MagicMock()
    admin = SimpleNamespace(id="admin-1", email="admin@example.com", role="admin", is_superuser=True)

    async def override_db():
        yield db

    async def override_admin():
        return admin

    app.dependency_overrides[security_lab.get_db] = override_db
    app.dependency_overrides[security_lab.get_admin_user] = override_admin
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        yield test_client, db


@pytest.mark.asyncio
async def test_scenario_catalog_is_available_to_admin_while_lab_is_disabled(client):
    test_client, _ = client
    with patch("app.api.security_lab.settings.SECURITY_LAB_ENABLED", False):
        response = await test_client.get("/admin/security-lab/scenarios")

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert {item["id"] for item in response.json()["scenarios"]} == {
        "credential-stuffing-rate-limit",
        "refresh-token-replay",
        "risky-login-outcomes",
        "temporary-privileged-access",
        "pkce-code-replay",
    }


@pytest.mark.asyncio
async def test_disabled_lab_refuses_to_run_and_does_not_persist(client):
    test_client, db = client
    with patch("app.services.security_lab_service.settings.SECURITY_LAB_ENABLED", False):
        response = await test_client.post(
            "/admin/security-lab/scenarios/risky-login-outcomes/runs", json={"seed": 1}
        )

    assert response.status_code == 403
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_request_cannot_override_the_server_configured_target(client):
    test_client, db = client
    response = await test_client.post(
        "/admin/security-lab/scenarios/risky-login-outcomes/runs",
        json={"seed": 1, "base_url": "https://example.com"},
    )

    assert response.status_code == 422
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_successful_run_is_persisted_with_evidence(client):
    test_client, db = client

    async def refresh(run):
        run.id = "run-1"
        run.created_at = "2026-09-04T00:00:00Z"

    db.refresh.side_effect = refresh
    with patch.multiple(
        "app.services.security_lab_service.settings",
        SECURITY_LAB_ENABLED=True,
        SECURITY_LAB_BASE_URL="http://localhost:8000",
        SECURITY_LAB_ALLOWED_BASE_URLS=["http://localhost:8000"],
    ):
        response = await test_client.post(
            "/admin/security-lab/scenarios/pkce-code-replay/runs", json={"seed": 9}
        )

    assert response.status_code == 201
    assert response.json()["status"] == "passed"
    assert response.json()["evidence"]["passed"] is True
    persisted = db.add.call_args.args[0]
    assert persisted.requested_by == "admin-1"
    assert persisted.evidence_digest == response.json()["evidence_digest"]
    db.commit.assert_awaited_once()