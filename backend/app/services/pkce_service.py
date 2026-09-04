"""Durable OAuth 2.1 authorization-code flow with PKCE S256."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.oauth import OAuth2AccessToken, OAuth2AuthorizationCode, OAuth2Client
from app.models.pkce import PKCERequest, PKCETokenRequest, PKCEUtils
from app.models.user import User
from app.services.oidc_service import issue_id_token
from app.services.session_service import create_session_tokens
from app.utils.security import hash_one_time_token, verify_password


class PKCEGrantError(Exception):
    """A non-descriptive OAuth invalid_grant failure."""


class PKCEClientError(Exception):
    """OAuth client authentication or registration failure."""


INVALID_GRANT_MESSAGE = "Authorization grant is invalid"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


async def get_registered_client(
    db: AsyncSession,
    client_id: str,
    redirect_uri: str,
) -> OAuth2Client:
    result = await db.execute(
        select(OAuth2Client).where(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active.is_(True),
        )
    )
    client = result.scalar_one_or_none()
    if client is None or not redirect_uri or urlsplit(redirect_uri).fragment:
        raise PKCEClientError("Unknown client or unregistered redirect URI")
    if not any(secrets.compare_digest(redirect_uri, registered) for registered in (client.redirect_uris or [])):
        raise PKCEClientError("Unknown client or unregistered redirect URI")
    if "authorization_code" not in (client.grant_types or []):
        raise PKCEClientError("Authorization code grant is not enabled")
    if "code" not in (client.response_types or []):
        raise PKCEClientError("Authorization code response is not enabled")
    return client


def validate_requested_scope(client: OAuth2Client, requested_scope: str | None) -> str:
    allowed = set((client.scope or "").split())
    requested = set((requested_scope or "").split())
    if not requested:
        requested = allowed
    if not requested.issubset(allowed):
        raise PKCEClientError("Requested scope is not allowed")
    return " ".join(sorted(requested))


async def issue_authorization_code(
    db: AsyncSession,
    request: PKCERequest,
    user_id: str,
    auth_time: datetime | None = None,
) -> tuple[str, int]:
    client = await get_registered_client(db, request.client_id, request.redirect_uri)
    scope = validate_requested_scope(client, request.scope)

    raw_code = PKCEUtils.generate_authorization_code()
    expires_in = min(settings.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES * 60, 600)
    record = OAuth2AuthorizationCode(
        id=str(uuid.uuid4()),
        code=_code_digest(raw_code),
        client_id=request.client_id,
        user_id=user_id,
        redirect_uri=request.redirect_uri,
        scope=scope,
        state=request.state,
        nonce=request.nonce if "openid" in scope.split() else None,
        auth_time=auth_time or _utcnow(),
        code_challenge=request.code_challenge,
        code_challenge_method="S256",
        expires_at=_utcnow() + timedelta(seconds=expires_in),
        is_used=False,
    )
    db.add(record)
    await db.commit()
    return raw_code, expires_in


def _authenticate_token_client(client: OAuth2Client, client_secret: str | None) -> None:
    if client.is_confidential:
        if not client_secret or not verify_password(client_secret, client.client_secret):
            raise PKCEClientError("Client authentication failed")
    elif client_secret:
        raise PKCEClientError("Public clients must not send a client secret")


async def redeem_authorization_code(
    db: AsyncSession,
    request: PKCETokenRequest,
) -> dict[str, object]:
    client = await get_registered_client(db, request.client_id, request.redirect_uri)
    _authenticate_token_client(client, request.client_secret)

    digest = _code_digest(request.code)
    result = await db.execute(
        select(OAuth2AuthorizationCode).where(
            OAuth2AuthorizationCode.code == digest,
            OAuth2AuthorizationCode.client_id == request.client_id,
            OAuth2AuthorizationCode.redirect_uri == request.redirect_uri,
            OAuth2AuthorizationCode.is_used.is_(False),
        )
    )
    grant = result.scalar_one_or_none()
    if grant is None or grant.expires_at <= _utcnow():
        raise PKCEGrantError(INVALID_GRANT_MESSAGE)

    if not PKCEUtils.authorization_code_is_redeemable(
        request.code_verifier,
        grant.code_challenge,
        grant.code_challenge_method,
        bool(getattr(grant, "is_used", False)),
    ):
        raise PKCEGrantError(INVALID_GRANT_MESSAGE)

    grant_auth_time = getattr(grant, "auth_time", None) or getattr(grant, "created_at", None) or _utcnow()
    if grant_auth_time.tzinfo is None:
        grant_auth_time = grant_auth_time.replace(tzinfo=timezone.utc)

    id_token = None
    if "openid" in (grant.scope or "").split():
        id_token = issue_id_token(
            subject=grant.user_id,
            audience=request.client_id,
            auth_time=grant_auth_time,
            nonce=grant.nonce,
        )

    consume_result = await db.execute(
        update(OAuth2AuthorizationCode)
        .where(
            OAuth2AuthorizationCode.id == grant.id,
            OAuth2AuthorizationCode.is_used.is_(False),
        )
        .values(is_used=True)
        .returning(OAuth2AuthorizationCode.id)
    )
    if consume_result.scalar_one_or_none() is None:
        await db.rollback()
        raise PKCEGrantError(INVALID_GRANT_MESSAGE)

    user = await db.get(User, grant.user_id)
    if user is None or not user.is_active:
        await db.rollback()
        raise PKCEGrantError(INVALID_GRANT_MESSAGE)
    issued = await create_session_tokens(
        db,
        user,
        authentication_method="pkce",
        extra_claims={
            "client_id": request.client_id,
            "scope": grant.scope,
            "auth_time": int(grant_auth_time.astimezone(timezone.utc).timestamp()),
            "jti": secrets.token_urlsafe(24),
        },
        commit=False,
    )
    access_token = issued.access_token
    refresh_token = issued.refresh_token
    access_expires = _utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_expires = _utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(OAuth2AccessToken(
        id=str(uuid.uuid4()),
        access_token=access_token,
        refresh_token_hash=hash_one_time_token(refresh_token),
        client_id=request.client_id,
        user_id=grant.user_id,
        scope=grant.scope,
        token_type="Bearer",
        expires_at=access_expires,
        refresh_token_expires_at=refresh_expires,
        is_revoked=False,
    ))
    await db.commit()

    token_response = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "scope": grant.scope,
    }
    if id_token is not None:
        token_response["id_token"] = id_token
    return token_response
