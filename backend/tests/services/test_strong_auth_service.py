"""Focused tests for MFA secrets, recovery codes, and challenge security."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest

from app.models.auth_security import AuthChallenge
from app.models.user import User
from app.services.strong_auth_service import (
    StrongAuthError,
    begin_passkey_registration,
    complete_passkey_registration,
    decrypt_totp_secret,
    encrypt_totp_secret,
    locked_challenge,
    verify_totp_or_recovery,
)
from app.services.session_service import utcnow
from app.utils.security import hash_one_time_token


def mfa_user(secret: str) -> User:
    return User(
        id="user-1", email="user@example.com", hashed_password="unused",
        is_active=True, is_verified=True, totp_enabled=True,
        totp_secret_encrypted=encrypt_totp_secret(secret),
    )


def test_totp_secret_is_encrypted_at_rest():
    secret = pyotp.random_base32()
    encrypted = encrypt_totp_secret(secret)
    assert encrypted != secret
    assert secret not in encrypted
    assert decrypt_totp_secret(encrypted) == secret


@pytest.mark.asyncio
async def test_valid_totp_is_accepted_without_persisting_the_code():
    secret = pyotp.random_base32()
    db = AsyncMock()
    method = await verify_totp_or_recovery(db, mfa_user(secret), pyotp.TOTP(secret).now())
    assert method == "totp"
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_recovery_code_is_consumed_atomically():
    secret = pyotp.random_base32()
    db = AsyncMock()
    consumed = MagicMock()
    consumed.scalar_one_or_none.return_value = "recovery-1"
    db.execute.return_value = consumed

    method = await verify_totp_or_recovery(db, mfa_user(secret), "single-use-recovery-code")

    assert method == "recovery_code"
    statement = db.execute.await_args.args[0]
    assert "used_at IS NULL" in str(statement)
    assert "single-use-recovery-code" not in str(statement)


@pytest.mark.asyncio
async def test_expired_challenge_is_rejected():
    challenge = AuthChallenge(
        id="challenge-1", user_id="user-1", purpose="totp_login", challenge=hash_one_time_token("secret"),
        expires_at=utcnow() - timedelta(seconds=1),
    )
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = challenge
    db.execute.return_value = result

    with pytest.raises(StrongAuthError, match="invalid or expired"):
        await locked_challenge(db, challenge.id, challenge.purpose)


@pytest.mark.asyncio
async def test_passkey_registration_challenge_is_bound_to_user_and_session():
    db = AsyncMock()
    db.add = MagicMock()
    existing = MagicMock()
    existing.scalars.return_value.all.return_value = []
    db.execute.return_value = existing
    user = User(id="user-1", email="user@example.com", hashed_password="unused")

    result = await begin_passkey_registration(db, user, "session-1")

    challenge = db.add.call_args.args[0]
    assert challenge.user_id == user.id
    assert challenge.session_id == "session-1"
    assert challenge.purpose == "passkey_register"
    assert result["challenge_id"] == challenge.id
    assert result["publicKey"]["authenticatorSelection"]["userVerification"] == "required"


@pytest.mark.asyncio
async def test_passkey_registration_consumes_challenge():
    db = AsyncMock()
    db.add = MagicMock()
    challenge = AuthChallenge(
        id="challenge-1", user_id="user-1", session_id="session-1",
        purpose="passkey_register", challenge="YWJj", expires_at=utcnow() + timedelta(minutes=1),
    )
    lookup = MagicMock()
    lookup.scalar_one_or_none.return_value = challenge
    db.execute.return_value = lookup
    verified = SimpleNamespace(
        credential_id=b"credential-id", credential_public_key=b"public-key", sign_count=0,
        aaguid="aaguid", credential_device_type=SimpleNamespace(value="single_device"),
        credential_backed_up=False,
    )
    user = User(id="user-1", email="user@example.com", hashed_password="unused")
    credential = {"id": "Y3JlZGVudGlhbC1pZA", "response": {"transports": ["internal"]}}

    with patch("app.services.strong_auth_service.verify_registration_response", return_value=verified):
        passkey = await complete_passkey_registration(
            db, user, "session-1", challenge.id, credential, "Laptop"
        )

    assert challenge.used_at is not None
    assert passkey.user_id == user.id
    assert passkey.public_key == b"public-key"
    db.commit.assert_awaited_once()
