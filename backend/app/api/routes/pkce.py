"""OAuth 2.1 authorization-code endpoints with mandatory PKCE S256."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.models.oauth import OAuth2Client
from app.models.pkce import PKCERequest, PKCEResponse, PKCETokenRequest, PKCETokenResponse
from app.models.user import User
from app.services.pkce_service import (
    PKCEClientError,
    PKCEGrantError,
    get_registered_client,
    issue_authorization_code,
    redeem_authorization_code,
)
from app.services.principal_service import resolve_access_principal

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth2/pkce", tags=["PKCE OAuth2"])
security = HTTPBearer(auto_error=False)

NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


def _redirect_uri(uri: str, params: dict[str, str]) -> str:
    parsed = urlsplit(uri)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(params.items())
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _oauth_error(error: str, description: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers=NO_STORE_HEADERS,
    )


async def _current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    principal = await resolve_access_principal(
        credentials.credentials if credentials else None,
        db,
    )
    user = principal.user
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authenticated user")
    payload = principal.claims
    authenticated_at = payload.get("auth_time") or payload.get("iat")
    user._oidc_auth_time = datetime.fromtimestamp(authenticated_at, timezone.utc) if authenticated_at else datetime.now(timezone.utc)
    return user


async def _validate_redirect_target(
    db: AsyncSession,
    client_id: str,
    redirect_uri: str,
) -> Optional[OAuth2Client]:
    try:
        return await get_registered_client(db, client_id, redirect_uri)
    except PKCEClientError:
        return None


@router.get("/authorize", response_model=None)
async def pkce_authorize_get(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    code_challenge_method: str = "S256",
    scope: Optional[str] = "read write",
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    client = await _validate_redirect_target(db, client_id, redirect_uri)
    if client is None:
        return _oauth_error("invalid_client", "Unknown client or redirect URI", status.HTTP_400_BAD_REQUEST)

    if response_type != "code":
        params = {
            "error": "unsupported_response_type",
            "error_description": "Only the authorization code response type is supported",
            "state": state,
        }
        return RedirectResponse(_redirect_uri(redirect_uri, params), status_code=status.HTTP_302_FOUND)

    try:
        authorization_request = PKCERequest(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=request.query_params.get("nonce"),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
    except ValidationError:
        params = {
            "error": "invalid_request",
            "error_description": "A valid S256 challenge and state are required",
            "state": state,
        }
        return RedirectResponse(_redirect_uri(redirect_uri, params), status_code=status.HTTP_302_FOUND)

    if credentials is None:
        return RedirectResponse(
            f"/login?{urlencode({'return_to': str(request.url)})}",
            status_code=status.HTTP_302_FOUND,
        )

    try:
        user = await _current_user(credentials, db)
        code, _ = await issue_authorization_code(
            db, authorization_request, user.id, getattr(user, "_oidc_auth_time", None)
        )
    except HTTPException:
        return RedirectResponse(
            f"/login?{urlencode({'return_to': str(request.url)})}",
            status_code=status.HTTP_302_FOUND,
        )
    except PKCEClientError:
        params = {"error": "invalid_scope", "error_description": "Requested scope is not allowed", "state": state}
        return RedirectResponse(_redirect_uri(redirect_uri, params), status_code=status.HTTP_302_FOUND)

    params = {"code": code, "state": state}
    return RedirectResponse(_redirect_uri(redirect_uri, params), status_code=status.HTTP_302_FOUND)


@router.post("/authorize", response_model=PKCEResponse)
async def pkce_authorize_post(
    authorization_request: PKCERequest,
    current_user: User = Depends(_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        code, expires_in = await issue_authorization_code(
            db,
            authorization_request,
            current_user.id,
            getattr(current_user, "_oidc_auth_time", None),
        )
    except PKCEClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request", "error_description": str(exc)},
        ) from exc
    return PKCEResponse(code=code, state=authorization_request.state, expires_in=expires_in)


@router.post("/token", response_model=PKCETokenResponse)
async def pkce_token_exchange(
    token_request: PKCETokenRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        token_data = await redeem_authorization_code(db, token_request)
    except PKCEClientError:
        return _oauth_error("invalid_client", "Client authentication failed", status.HTTP_401_UNAUTHORIZED)
    except PKCEGrantError:
        return _oauth_error("invalid_grant", "Authorization grant is invalid", status.HTTP_400_BAD_REQUEST)
    except Exception:
        logger.exception("PKCE token exchange failed")
        return _oauth_error("server_error", "Token service unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)

    return JSONResponse(content=token_data, headers=NO_STORE_HEADERS)


@router.get("/client-config")
async def get_pkce_client_config(
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select

    result = await db.execute(
        select(OAuth2Client).where(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active.is_(True),
        )
    )
    client = result.scalar_one_or_none()
    if client is None:
        return _oauth_error("invalid_client", "Unknown client", status.HTTP_400_BAD_REQUEST)

    return {
        "client_id": client.client_id,
        "pkce_methods": ["S256"],
        "token_endpoint_auth_methods": ["client_secret_post"] if client.is_confidential else ["none"],
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "redirect_uris": client.redirect_uris,
        "scope": client.scope,
    }
