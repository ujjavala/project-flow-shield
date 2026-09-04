"""Token-mediating backend-for-frontend endpoints.

Opaque browser session handles are HttpOnly. Access and refresh credentials are
stored only in Redis and are never returned to browser JavaScript.
"""

from __future__ import annotations

from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.connection import get_db
from app.models.user import User
from app.services.bff_session_service import (
    create_bff_session,
    delete_bff_session,
    get_bff_session,
    update_bff_tokens,
    valid_csrf,
)
from app.services.principal_service import resolve_access_principal
from app.services.risk_policy_service import (
    build_login_features,
    evaluate_and_persist,
    ollama_shadow_advisor,
)
from app.services.session_service import (
    InvalidRefreshToken,
    RefreshTokenReuseDetected,
    create_session_tokens,
    revoke_session,
    rotate_refresh_token,
)
from app.utils.admin_auth import _is_admin_user
from app.utils.security import verify_password

router = APIRouter(prefix="/bff", tags=["Backend for Frontend"])


class BFFLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)
    portal: Literal["user", "admin"] = "user"
    remember_me: bool = False


def _set_session_cookies(response: Response, session_id: str, csrf_token: str) -> None:
    max_age = settings.BFF_SESSION_EXPIRE_SECONDS
    response.set_cookie(
        "bff_session",
        session_id,
        max_age=max_age,
        httponly=True,
        secure=settings.BFF_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.BFF_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie("bff_session", path="/", secure=settings.BFF_COOKIE_SECURE, samesite="strict")
    response.delete_cookie("csrf_token", path="/", secure=settings.BFF_COOKIE_SECURE, samesite="strict")
    response.headers["Cache-Control"] = "no-store"


def _require_csrf(request: Request, session: dict) -> None:
    if not valid_csrf(
        session,
        request.cookies.get("csrf_token"),
        request.headers.get("X-CSRF-Token"),
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


@router.post("/login", response_model=None)
async def login(
    login_data: BFFLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active or not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is unavailable")

    is_admin = _is_admin_user(user)
    if login_data.portal == "admin" and not is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    if login_data.portal == "user" and is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Use the admin portal")
    if user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Complete MFA login before creating a browser session")

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    features = await build_login_features(db, user.id, client_ip, user_agent)
    risk = await evaluate_and_persist(
        db,
        correlation_id=f"bff-login-{uuid4()}",
        context="admin_password_login" if is_admin else "password_login",
        features=features,
        user_id=user.id,
        ai_advisor=ollama_shadow_advisor,
    )
    if risk.outcome != "allow":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Additional authentication is required")

    tokens = await create_session_tokens(
        db,
        user,
        authentication_method="admin" if is_admin else "password",
        ip_address=client_ip,
        user_agent=user_agent,
    )
    browser_session_id, csrf_token = await create_bff_session(
        user_id=user.id,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        session_id=tokens.session_id,
        is_admin=is_admin,
    )
    _set_session_cookies(response, browser_session_id, csrf_token)
    return {
        "authenticated": True,
        "user": {"id": user.id, "email": user.email, "role": user.role, "is_admin": is_admin},
    }


@router.get("/session-status")
async def session_status(request: Request, db: AsyncSession = Depends(get_db)):
    session = await get_bff_session(request.cookies.get("bff_session"))
    if session is None:
        return {"authenticated": False}
    try:
        principal = await resolve_access_principal(session["access_token"], db)
    except HTTPException:
        await delete_bff_session(request.cookies.get("bff_session"))
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": {"id": principal.user.id, "is_admin": _is_admin_user(principal.user)},
    }


@router.post("/refresh")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    browser_session_id = request.cookies.get("bff_session")
    session = await get_bff_session(browser_session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid")
    _require_csrf(request, session)
    try:
        tokens = await rotate_refresh_token(db, session["refresh_token"])
    except (InvalidRefreshToken, RefreshTokenReuseDetected) as exc:
        await delete_bff_session(browser_session_id)
        _clear_session_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid") from exc
    await update_bff_tokens(browser_session_id, tokens.access_token, tokens.refresh_token)
    response.headers["Cache-Control"] = "no-store"
    return {"refreshed": True}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    browser_session_id = request.cookies.get("bff_session")
    session = await get_bff_session(browser_session_id)
    if session is not None:
        _require_csrf(request, session)
        await revoke_session(db, session["auth_session_id"], session["user_id"])
    await delete_bff_session(browser_session_id)
    _clear_session_cookies(response)
    return {"authenticated": False}


@router.get("/me")
async def me(request: Request, db: AsyncSession = Depends(get_db)):
    session = await get_bff_session(request.cookies.get("bff_session"))
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid")
    principal = await resolve_access_principal(session["access_token"], db)
    user = principal.user
    return {"id": user.id, "email": user.email, "role": user.role, "is_admin": _is_admin_user(user)}
