"""WebAuthn, TOTP MFA, and user-controlled session APIs."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.connection import get_db
from app.models.auth_security import AuthChallenge, AuthSession, PasskeyCredential, TOTPRecoveryCode
from app.models.user import User
from app.services.principal_service import AccessPrincipal
from app.services.principal_service import resolve_access_principal
from app.services.session_service import create_session_tokens, revoke_session, utcnow
from app.services.strong_auth_service import (
    StrongAuthError,
    begin_passkey_authentication,
    begin_passkey_registration,
    begin_totp_setup,
    complete_passkey_authentication,
    complete_passkey_registration,
    confirm_totp_setup,
    locked_challenge,
    verify_totp_or_recovery,
)
from app.utils.security import hash_one_time_token

router = APIRouter(prefix="/auth", tags=["strong-authentication"])
bearer = HTTPBearer(auto_error=False)


CurrentPrincipal = AccessPrincipal


async def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> CurrentPrincipal:
    return await resolve_access_principal(
        credentials.credentials if credentials else None,
        db,
    )


class PasskeyRegistrationComplete(BaseModel):
    challenge_id: str
    credential: dict[str, Any]
    name: str = Field(default="Passkey", min_length=1, max_length=100)


class PasskeyAuthenticationBegin(BaseModel):
    email: str


class PasskeyAuthenticationComplete(BaseModel):
    challenge_id: str
    credential: dict[str, Any]
    device_name: str | None = Field(default=None, max_length=100)


class TOTPSetupConfirm(BaseModel):
    challenge_id: str
    setup_token: str
    code: str = Field(min_length=6, max_length=32)


class TOTPLoginComplete(BaseModel):
    challenge_id: str
    challenge_token: str
    code: str = Field(min_length=6, max_length=64)
    device_name: str | None = Field(default=None, max_length=100)


class TOTPDisable(BaseModel):
    code: str = Field(min_length=6, max_length=64)


def _client_context(request: Request) -> tuple[str | None, str | None]:
    ip_address = request.client.host if request.client else None
    return ip_address, request.headers.get("user-agent")


def _token_response(tokens) -> dict:
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "session_id": tokens.session_id,
    }


@router.post("/passkeys/register/options")
async def passkey_registration_options(
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    return await begin_passkey_registration(db, principal.user, principal.session.id)


@router.post("/passkeys/register/verify")
async def passkey_registration_verify(
    request: PasskeyRegistrationComplete,
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    try:
        passkey = await complete_passkey_registration(
            db, principal.user, principal.session.id, request.challenge_id, request.credential, request.name
        )
    except StrongAuthError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"id": passkey.id, "name": passkey.name, "created_at": passkey.created_at}


@router.get("/passkeys")
async def list_passkeys(
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PasskeyCredential).where(PasskeyCredential.user_id == principal.user.id))
    return [
        {
            "id": item.id,
            "name": item.name,
            "created_at": item.created_at,
            "last_used_at": item.last_used_at,
            "device_type": item.device_type,
            "backed_up": item.backed_up,
        }
        for item in result.scalars().all()
    ]


@router.delete("/passkeys/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_passkey(
    passkey_id: str,
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        delete(PasskeyCredential)
        .where(PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == principal.user.id)
        .returning(PasskeyCredential.id)
    )
    if result.scalar_one_or_none() is None:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Passkey not found")
    await db.commit()


@router.post("/passkeys/authenticate/options")
async def passkey_authentication_options(
    request: PasskeyAuthenticationBegin,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == request.email, User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passkey authentication is unavailable")
    try:
        return await begin_passkey_authentication(db, user)
    except StrongAuthError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/passkeys/authenticate/verify")
async def passkey_authentication_verify(
    body: PasskeyAuthenticationComplete,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    try:
        user, _ = await complete_passkey_authentication(db, body.challenge_id, body.credential)
        ip_address, user_agent = _client_context(request)
        tokens = await create_session_tokens(
            db,
            user,
            authentication_method="passkey",
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=body.device_name,
            extra_claims={"amr": ["webauthn"]},
        )
    except StrongAuthError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return _token_response(tokens)


@router.post("/mfa/totp/setup")
async def totp_setup(
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if principal.user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="TOTP is already enabled")
    return await begin_totp_setup(db, principal.user, principal.session.id)


@router.post("/mfa/totp/confirm")
async def totp_confirm(
    body: TOTPSetupConfirm,
    response: Response,
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    try:
        recovery_codes = await confirm_totp_setup(
            db, principal.user, principal.session.id, body.challenge_id, body.setup_token, body.code
        )
    except StrongAuthError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {"enabled": True, "recovery_codes": recovery_codes}


@router.post("/mfa/totp/verify")
async def totp_verify_login(
    body: TOTPLoginComplete,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    try:
        challenge = await locked_challenge(db, body.challenge_id, "totp_login")
        if not secrets.compare_digest(challenge.challenge, hash_one_time_token(body.challenge_token)):
            raise StrongAuthError("Challenge is invalid or expired")
        user = await db.get(User, challenge.user_id)
        if user is None or not user.is_active:
            raise StrongAuthError("Authentication failed")
        method = await verify_totp_or_recovery(db, user, body.code)
        challenge.used_at = utcnow()
        await db.commit()
        ip_address, user_agent = _client_context(request)
        tokens = await create_session_tokens(
            db,
            user,
            authentication_method="password_mfa",
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=body.device_name,
            extra_claims={"amr": ["pwd", method]},
        )
    except StrongAuthError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return _token_response(tokens)


@router.post("/mfa/totp/disable")
async def totp_disable(
    body: TOTPDisable,
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    try:
        await verify_totp_or_recovery(db, principal.user, body.code)
    except StrongAuthError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    principal.user.totp_enabled = False
    principal.user.totp_secret_encrypted = None
    principal.user.totp_pending_secret_encrypted = None
    await db.execute(delete(TOTPRecoveryCode).where(TOTPRecoveryCode.user_id == principal.user.id))
    await db.commit()
    return {"enabled": False}


@router.get("/sessions")
async def list_sessions(
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuthSession)
        .where(AuthSession.user_id == principal.user.id, AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.last_seen_at.desc())
    )
    return [
        {
            "id": item.id,
            "device_name": item.device_name,
            "user_agent": item.user_agent,
            "ip_address": item.ip_address,
            "authentication_method": item.authentication_method,
            "created_at": item.created_at,
            "last_seen_at": item.last_seen_at,
            "expires_at": item.expires_at,
            "current": item.id == principal.session.id,
        }
        for item in result.scalars().all()
        if not is_expired(item.expires_at)
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_user_session(
    session_id: str,
    principal: CurrentPrincipal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
):
    if not await revoke_session(db, session_id, principal.user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
