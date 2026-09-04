"""Passkey and TOTP operations using vetted WebAuthn/TOTP libraries."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import timedelta

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import settings
from app.models.auth_security import AuthChallenge, PasskeyCredential, TOTPRecoveryCode
from app.models.user import User
from app.services.session_service import is_expired, utcnow
from app.utils.security import hash_one_time_token


class StrongAuthError(Exception):
    pass


def _fernet() -> Fernet:
    configured = settings.MFA_ENCRYPTION_KEY.strip()
    if configured:
        key = configured.encode("ascii")
    elif settings.ENVIRONMENT.lower() in {"development", "test"}:
        # Local-only deterministic key; production must inject a dedicated key.
        digest = hashlib.sha256(("flowshield-mfa:" + settings.JWT_SECRET_KEY).encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    else:
        raise RuntimeError("MFA_ENCRYPTION_KEY must be configured outside development")
    try:
        return Fernet(key)
    except (ValueError, InvalidToken) as exc:
        raise RuntimeError("MFA_ENCRYPTION_KEY must be a Fernet key") from exc


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(encrypted: str) -> str:
    try:
        return _fernet().decrypt(encrypted.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise StrongAuthError("MFA configuration is unavailable") from exc


def _challenge_ttl(seconds: int) -> int:
    return max(30, min(seconds, 600))


async def create_challenge(
    db: AsyncSession,
    *,
    purpose: str,
    challenge: str,
    user_id: str | None,
    session_id: str | None,
    ttl_seconds: int,
) -> AuthChallenge:
    now = utcnow()
    record = AuthChallenge(
        id=str(uuid.uuid4()),
        user_id=user_id,
        session_id=session_id,
        purpose=purpose,
        challenge=challenge,
        created_at=now,
        expires_at=now + timedelta(seconds=_challenge_ttl(ttl_seconds)),
    )
    db.add(record)
    await db.commit()
    return record


async def locked_challenge(
    db: AsyncSession,
    challenge_id: str,
    purpose: str,
    *,
    user_id: str | None = None,
    session_id: str | None = None,
) -> AuthChallenge:
    conditions = [
        AuthChallenge.id == challenge_id,
        AuthChallenge.purpose == purpose,
        AuthChallenge.used_at.is_(None),
    ]
    if user_id is not None:
        conditions.append(AuthChallenge.user_id == user_id)
    if session_id is not None:
        conditions.append(AuthChallenge.session_id == session_id)
    result = await db.execute(select(AuthChallenge).where(*conditions).with_for_update())
    challenge = result.scalar_one_or_none()
    if challenge is None or is_expired(challenge.expires_at):
        raise StrongAuthError("Challenge is invalid or expired")
    return challenge


async def begin_totp_setup(db: AsyncSession, user: User, session_id: str) -> dict:
    secret = pyotp.random_base32()
    user.totp_pending_secret_encrypted = encrypt_totp_secret(secret)
    setup_token = secrets.token_urlsafe(32)
    challenge = await create_challenge(
        db,
        purpose="totp_setup",
        challenge=hash_one_time_token(setup_token),
        user_id=user.id,
        session_id=session_id,
        ttl_seconds=settings.TOTP_SETUP_EXPIRE_SECONDS,
    )
    await db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.WEBAUTHN_RP_NAME)
    return {"challenge_id": challenge.id, "setup_token": setup_token, "secret": secret, "otpauth_uri": uri}


async def confirm_totp_setup(
    db: AsyncSession, user: User, session_id: str, challenge_id: str, setup_token: str, code: str
) -> list[str]:
    challenge = await locked_challenge(db, challenge_id, "totp_setup", user_id=user.id, session_id=session_id)
    if not secrets.compare_digest(challenge.challenge, hash_one_time_token(setup_token)):
        raise StrongAuthError("Challenge is invalid or expired")
    if not user.totp_pending_secret_encrypted:
        raise StrongAuthError("TOTP setup has not been started")
    secret = decrypt_totp_secret(user.totp_pending_secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise StrongAuthError("Invalid authentication code")

    recovery_codes = [secrets.token_urlsafe(16) for _ in range(10)]
    await db.execute(delete(TOTPRecoveryCode).where(TOTPRecoveryCode.user_id == user.id))
    for recovery_code in recovery_codes:
        db.add(TOTPRecoveryCode(user_id=user.id, code_hash=hash_one_time_token(recovery_code)))
    user.totp_secret_encrypted = user.totp_pending_secret_encrypted
    user.totp_pending_secret_encrypted = None
    user.totp_enabled = True
    challenge.used_at = utcnow()
    await db.commit()
    return recovery_codes


async def verify_totp_or_recovery(db: AsyncSession, user: User, code: str) -> str:
    if not user.totp_enabled or not user.totp_secret_encrypted:
        raise StrongAuthError("MFA is not enabled")
    secret = decrypt_totp_secret(user.totp_secret_encrypted)
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        return "totp"

    digest = hash_one_time_token(code)
    result = await db.execute(
        update(TOTPRecoveryCode)
        .where(
            TOTPRecoveryCode.user_id == user.id,
            TOTPRecoveryCode.code_hash == digest,
            TOTPRecoveryCode.used_at.is_(None),
        )
        .values(used_at=utcnow())
        .returning(TOTPRecoveryCode.id)
    )
    if result.scalar_one_or_none() is None:
        raise StrongAuthError("Invalid authentication code")
    return "recovery_code"


async def begin_passkey_registration(db: AsyncSession, user: User, session_id: str) -> dict:
    existing_result = await db.execute(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
    existing = existing_result.scalars().all()
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=user.id.encode("utf-8"),
        user_name=user.email,
        user_display_name=(" ".join(filter(None, (user.first_name, user.last_name))) or user.email),
        timeout=_challenge_ttl(settings.AUTH_CHALLENGE_EXPIRE_SECONDS) * 1000,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id)) for item in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    challenge = await create_challenge(
        db,
        purpose="passkey_register",
        challenge=bytes_to_base64url(options.challenge),
        user_id=user.id,
        session_id=session_id,
        ttl_seconds=settings.AUTH_CHALLENGE_EXPIRE_SECONDS,
    )
    return {"challenge_id": challenge.id, "publicKey": json.loads(options_to_json(options))}


async def complete_passkey_registration(
    db: AsyncSession,
    user: User,
    session_id: str,
    challenge_id: str,
    credential: dict,
    name: str,
) -> PasskeyCredential:
    challenge = await locked_challenge(
        db, challenge_id, "passkey_register", user_id=user.id, session_id=session_id
    )
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
            require_user_verification=True,
        )
    except Exception as exc:
        raise StrongAuthError("Passkey registration could not be verified") from exc

    credential_id = bytes_to_base64url(verified.credential_id)
    transports = credential.get("response", {}).get("transports")
    record = PasskeyCredential(
        id=str(uuid.uuid4()),
        user_id=user.id,
        credential_id=credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=(name or "Passkey")[:100],
        transports=transports,
        aaguid=verified.aaguid,
        device_type=verified.credential_device_type.value,
        backed_up=verified.credential_backed_up,
    )
    challenge.used_at = utcnow()
    db.add(record)
    await db.commit()
    return record


async def begin_passkey_authentication(db: AsyncSession, user: User) -> dict:
    result = await db.execute(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
    credentials = result.scalars().all()
    if not credentials:
        raise StrongAuthError("Passkey authentication is unavailable")
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        timeout=_challenge_ttl(settings.AUTH_CHALLENGE_EXPIRE_SECONDS) * 1000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id)) for item in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge = await create_challenge(
        db,
        purpose="passkey_authenticate",
        challenge=bytes_to_base64url(options.challenge),
        user_id=user.id,
        session_id=None,
        ttl_seconds=settings.AUTH_CHALLENGE_EXPIRE_SECONDS,
    )
    return {"challenge_id": challenge.id, "publicKey": json.loads(options_to_json(options))}


async def complete_passkey_authentication(
    db: AsyncSession, challenge_id: str, credential: dict
) -> tuple[User, PasskeyCredential]:
    challenge = await locked_challenge(db, challenge_id, "passkey_authenticate")
    credential_id = credential.get("id")
    result = await db.execute(
        select(PasskeyCredential).where(
            PasskeyCredential.credential_id == credential_id,
            PasskeyCredential.user_id == challenge.user_id,
        ).with_for_update()
    )
    stored = result.scalar_one_or_none()
    if stored is None:
        raise StrongAuthError("Passkey authentication could not be verified")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        raise StrongAuthError("Passkey authentication could not be verified") from exc

    if stored.sign_count and verified.new_sign_count and verified.new_sign_count <= stored.sign_count:
        raise StrongAuthError("Authenticator counter regression detected")
    stored.sign_count = verified.new_sign_count
    stored.last_used_at = utcnow()
    stored.device_type = verified.credential_device_type.value
    stored.backed_up = verified.credential_backed_up
    challenge.used_at = utcnow()
    user = await db.get(User, challenge.user_id)
    if user is None or not user.is_active or not user.is_verified:
        raise StrongAuthError("Passkey authentication could not be verified")
    await db.commit()
    return user, stored
