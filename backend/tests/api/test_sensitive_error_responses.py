"""Regression tests for sensitive-data-safe API failure responses."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api import ai_simple
from app.services.ollama_ai_service import OllamaAIService


@pytest.mark.asyncio
async def test_simple_ai_error_does_not_return_exception_details(monkeypatch, caplog):
    canary = "password=highly-sensitive-value"
    monkeypatch.setattr(
        ai_simple.ollama,
        "check_health",
        AsyncMock(side_effect=RuntimeError(canary)),
    )

    with pytest.raises(HTTPException) as raised:
        await ai_simple.analyze_password(
            ai_simple.PasswordAnalysisRequest(password="input-secret", user_context={})
        )

    assert raised.value.detail == "Password analysis failed"
    assert canary not in str(raised.value.detail)
    assert canary not in caplog.text
    assert "RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_ollama_health_does_not_disclose_internal_endpoint():
    service = OllamaAIService(host="internal-model.service", port=11434)
    response = AsyncMock()
    response.status = 200
    response.__aenter__.return_value = response
    response.__aexit__.return_value = None
    session = MagicMock()
    session.get.return_value = response
    service.session = session

    result = await service.health_check()

    assert result["status"] == "healthy"
    assert "endpoint" not in result
    assert "internal-model.service" not in str(result)
