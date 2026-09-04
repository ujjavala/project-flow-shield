"""Security tests for email verification and password recovery."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.user import (
    EmailVerificationModel,
    PasswordResetConfirmModel,
    PasswordResetRequestModel,
    confirm_password_reset,
    request_password_reset,
    resend_verification,
    verify_email,
)
from app.utils.security import hash_one_time_token


@pytest.mark.asyncio
async def test_password_reset_stores_only_digest_and_delivers_raw_token():
    user = SimpleNamespace(
        id="user-1",
        email="person@example.com",
        is_active=True,
        password_reset_token=None,
        password_reset_expires=None,
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = result

    with patch("app.api.user.generate_reset_token", return_value="raw-reset-secret"), patch(
        "app.api.user.email_delivery.send_password_reset", new=AsyncMock()
    ) as send:
        response = await request_password_reset(PasswordResetRequestModel(email=user.email), db)

    assert response == {"message": "If the email exists, a password reset link has been sent."}
    assert user.password_reset_token == hash_one_time_token("raw-reset-secret")
    assert "raw-reset-secret" not in user.password_reset_token
    send.assert_awaited_once_with(user.email, "raw-reset-secret")
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_password_reset_response_does_not_reveal_missing_account():
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = result

    response = await request_password_reset(PasswordResetRequestModel(email="missing@example.com"), db)

    assert response == {"message": "If the email exists, a password reset link has been sent."}
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_password_reset_confirmation_uses_atomic_digest_redemption():
    result = MagicMock()
    result.scalar_one_or_none.return_value = "user-1"
    db = AsyncMock()
    db.execute.return_value = result

    response = await confirm_password_reset(
        PasswordResetConfirmModel(token="raw-reset-secret", new_password="NewPassword123!"),
        db,
    )

    statement = db.execute.await_args.args[0]
    compiled = statement.compile()
    assert hash_one_time_token("raw-reset-secret") in compiled.params.values()
    assert "raw-reset-secret" not in compiled.params.values()
    assert response["message"].startswith("Password has been reset successfully")
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_replayed_or_expired_reset_token_is_rejected():
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = result

    with pytest.raises(HTTPException) as raised:
        await confirm_password_reset(
            PasswordResetConfirmModel(token="invalid-secret", new_password="NewPassword123!"),
            db,
        )

    assert getattr(raised.value, "status_code", None) == 400
    assert getattr(raised.value, "detail", None) == "Invalid or expired reset token"
    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_email_verification_is_atomic_and_uses_digest():
    result = MagicMock()
    result.scalar_one_or_none.return_value = "user-1"
    db = AsyncMock()
    db.execute.return_value = result

    response = await verify_email(EmailVerificationModel(token="raw-verification-secret"), db)

    statement = db.execute.await_args.args[0]
    compiled = statement.compile()
    assert hash_one_time_token("raw-verification-secret") in compiled.params.values()
    assert response["message"].startswith("Email verified successfully")
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_resend_verification_rotates_digest_and_is_enumeration_safe():
    user = SimpleNamespace(
        email="person@example.com",
        is_active=True,
        is_verified=False,
        email_verification_token=None,
        email_verification_expires=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = result

    with patch("app.api.user.generate_verification_token", return_value="new-verification-secret"), patch(
        "app.api.user.email_delivery.send_verification", new=AsyncMock()
    ) as send:
        response = await resend_verification(PasswordResetRequestModel(email=user.email), db)

    assert "exists and is unverified" in response["message"]
    assert user.email_verification_token == hash_one_time_token("new-verification-secret")
    send.assert_awaited_once_with(user.email, "new-verification-secret")
