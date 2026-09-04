"""Redis-backed BFF sessions; bearer and refresh tokens never reach browser JavaScript."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from redis.asyncio import from_url

from app.config import settings

_SESSION_PREFIX = "bff:session:"
_SESSION_FIELDS = {
    "user_id",
    "access_token",
    "refresh_token",
    "auth_session_id",
    "is_admin",
    "csrf_digest",
}


def _key(session_id: str) -> str:
    return _SESSION_PREFIX + hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def new_session_id() -> str:
    return secrets.token_urlsafe(48)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _csrf_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _deserialize_session(value: str) -> dict[str, Any] | None:
    try:
        data = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or set(data) != _SESSION_FIELDS:
        return None
    if not all(isinstance(data[field], str) and data[field] for field in _SESSION_FIELDS - {"is_admin"}):
        return None
    if not isinstance(data["is_admin"], bool):
        return None
    digest = data["csrf_digest"]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return None
    return data


async def create_bff_session(
    *,
    user_id: str,
    access_token: str,
    refresh_token: str,
    session_id: str,
    is_admin: bool,
) -> tuple[str, str]:
    browser_session_id = new_session_id()
    csrf_token = new_csrf_token()
    data = {
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "auth_session_id": session_id,
        "is_admin": bool(is_admin),
        "csrf_digest": _csrf_digest(csrf_token),
    }
    redis = from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await redis.setex(
            _key(browser_session_id),
            settings.BFF_SESSION_EXPIRE_SECONDS,
            json.dumps(data, separators=(",", ":")),
        )
    finally:
        await redis.aclose()
    return browser_session_id, csrf_token


async def get_bff_session(session_id: str | None) -> dict[str, Any] | None:
    if not session_id:
        return None
    redis = from_url(settings.REDIS_URL, decode_responses=True)
    try:
        value = await redis.get(_key(session_id))
        if not value:
            return None
        data = _deserialize_session(value)
        if data is None:
            await redis.delete(_key(session_id))
            return None
        await redis.expire(_key(session_id), settings.BFF_SESSION_EXPIRE_SECONDS)
        return data
    finally:
        await redis.aclose()


async def update_bff_tokens(session_id: str, access_token: str, refresh_token: str) -> bool:
    data = await get_bff_session(session_id)
    if data is None:
        return False
    data["access_token"] = access_token
    data["refresh_token"] = refresh_token
    redis = from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await redis.setex(
            _key(session_id),
            settings.BFF_SESSION_EXPIRE_SECONDS,
            json.dumps(data, separators=(",", ":")),
        )
    finally:
        await redis.aclose()
    return True


async def delete_bff_session(session_id: str | None) -> None:
    if not session_id:
        return
    redis = from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await redis.delete(_key(session_id))
    finally:
        await redis.aclose()


def valid_csrf(session: dict[str, Any], cookie_token: str | None, header_token: str | None) -> bool:
    if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
        return False
    return hmac.compare_digest(session.get("csrf_digest", ""), _csrf_digest(header_token))
