"""Minimal OpenID Connect discovery, JWKS, and UserInfo endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.connection import get_db
from app.models.oauth import OAuth2AccessToken
from app.models.user import User
from app.services.oidc_service import OIDCConfigurationError, get_jwks
from app.utils.security import verify_token

router = APIRouter()
security = HTTPBearer(auto_error=False)

NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _issuer() -> str:
    return settings.OIDC_ISSUER.rstrip("/")


def _bearer_error() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "invalid_token", "error_description": "Access token is invalid"},
        headers={**NO_STORE_HEADERS, "WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def _expired(value: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= datetime.now(timezone.utc)


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    issuer = _issuer()
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth2/pkce/authorize",
        "token_endpoint": f"{issuer}/oauth2/pkce/token",
        "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
        "jwks_uri": f"{issuer}/oauth2/jwks",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "read", "write"],
        "claims_supported": [
            "iss", "aud", "sub", "iat", "exp", "auth_time", "nonce",
            "name", "given_name", "family_name", "preferred_username",
            "picture", "email", "email_verified",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }


@router.get("/oauth2/jwks")
async def jwks():
    try:
        content = get_jwks()
    except OIDCConfigurationError:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "temporarily_unavailable"},
            headers=NO_STORE_HEADERS,
        )
    return JSONResponse(content=content, headers={"Cache-Control": "public, max-age=300"})


@router.get("/oauth2/userinfo")
async def userinfo(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if credentials is None:
        return _bearer_error()

    token = credentials.credentials
    payload = verify_token(token)
    if not payload or payload.get("type") != "access":
        return _bearer_error()

    result = await db.execute(
        select(OAuth2AccessToken).where(
            OAuth2AccessToken.access_token == token,
            OAuth2AccessToken.is_revoked.is_(False),
        )
    )
    token_record = result.scalar_one_or_none()
    if (
        token_record is None
        or _expired(token_record.expires_at)
        or payload.get("sub") != token_record.user_id
        or payload.get("client_id") != token_record.client_id
        or "openid" not in (token_record.scope or "").split()
    ):
        return _bearer_error()

    user = await db.get(User, token_record.user_id)
    if user is None or not user.is_active:
        return _bearer_error()

    scopes = set((token_record.scope or "").split())
    claims: dict[str, object] = {"sub": user.id}
    if "email" in scopes:
        claims.update({"email": user.email, "email_verified": user.is_verified})
    if "profile" in scopes:
        claims.update({
            "name": " ".join(filter(None, (user.first_name, user.last_name))),
            "given_name": user.first_name,
            "family_name": user.last_name,
            "preferred_username": user.username,
            "picture": user.profile_picture,
        })
    return JSONResponse(content=claims, headers=NO_STORE_HEADERS)
