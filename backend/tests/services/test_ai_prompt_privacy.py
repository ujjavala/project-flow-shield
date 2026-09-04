from unittest.mock import AsyncMock

import pytest

from app.services.ollama_ai_service import OllamaAIService


@pytest.mark.asyncio
async def test_password_advice_never_sends_password_or_identity_to_model():
    service = OllamaAIService()
    service._make_request = AsyncMock(return_value=(
        '{"security_score":0.8,"strength_level":"strong",'
        '"personal_info_detected":false,"common_patterns":[],'
        '"recommendations":[],"explanation":"Strong composition"}'
    ))
    password = "CanarySecret-987!"
    identity = {"first_name": "CanaryName", "email": "canary@example.test"}

    await service.analyze_password_security(password, identity)

    prompt = service._make_request.await_args.args[0]
    assert password not in prompt
    assert identity["first_name"] not in prompt
    assert identity["email"] not in prompt


@pytest.mark.asyncio
async def test_fraud_advice_never_sends_direct_identifiers_to_model():
    service = OllamaAIService()
    service._make_request = AsyncMock(return_value=(
        '{"fraud_score":0.2,"risk_level":"low","risk_factors":[],'
        '"confidence":0.8,"explanation":"No elevated indicators"}'
    ))
    registration = {
        "email": "canary@example.test",
        "first_name": "CanaryName",
        "last_name": "CanarySurname",
        "ip_address": "203.0.113.99",
        "user_agent": "CanaryBrowser/1.0",
        "source": "web",
    }

    await service.detect_registration_fraud(registration)

    prompt = service._make_request.await_args.args[0]
    for sensitive_value in (
        registration["email"],
        registration["first_name"],
        registration["last_name"],
        registration["ip_address"],
        registration["user_agent"],
    ):
        assert sensitive_value not in prompt
