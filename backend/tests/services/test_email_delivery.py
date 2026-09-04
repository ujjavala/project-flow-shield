"""Tests for the development authentication-email sink."""

import json

import pytest

from app.config import settings
from app.services.email_delivery import EmailDeliveryError, EmailDeliveryService


@pytest.mark.asyncio
async def test_development_sink_writes_private_message_without_logging_token(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_DELIVERY_MODE", "development_file")
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(settings, "DEVELOPMENT_MAILBOX_PATH", str(tmp_path))

    await EmailDeliveryService().send_password_reset("person@example.com", "raw-secret-token")

    messages = list(tmp_path.glob("*.json"))
    assert len(messages) == 1
    message = json.loads(messages[0].read_text(encoding="utf-8"))
    assert message["to"] == "person@example.com"
    assert "raw-secret-token" in message["body"]
    assert "raw-secret-token" not in caplog.text
    assert "person@example.com" not in caplog.text
    assert messages[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_development_sink_is_rejected_in_production(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_DELIVERY_MODE", "development_file")
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "DEVELOPMENT_MAILBOX_PATH", str(tmp_path))

    service = EmailDeliveryService()
    with pytest.raises(EmailDeliveryError):
        await service.send_verification("person@example.com", "raw-secret-token")
