"""OpenID Connect signing and public-key publication helpers."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from app.config import settings


class OIDCConfigurationError(RuntimeError):
    """OIDC signing configuration is missing or invalid."""


def _read_key(path_value: str, *, private: bool):
    if not path_value:
        raise OIDCConfigurationError("OIDC signing key configuration is incomplete")
    try:
        key_bytes = Path(path_value).read_bytes()
        if private:
            key = serialization.load_pem_private_key(key_bytes, password=None)
        else:
            key = serialization.load_pem_public_key(key_bytes)
    except (OSError, ValueError, TypeError) as exc:
        raise OIDCConfigurationError("OIDC signing key configuration is invalid") from exc

    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)) or key.key_size < 2048:
        raise OIDCConfigurationError("OIDC signing keys must be RSA keys of at least 2048 bits")
    return key


def _base64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _public_jwk(key: rsa.RSAPrivateKey | rsa.RSAPublicKey, kid: str) -> dict[str, str]:
    public_key = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": _base64url_uint(numbers.n),
        "e": _base64url_uint(numbers.e),
    }


def get_jwks() -> dict[str, list[dict[str, str]]]:
    """Publish the active key and retained public keys used during rotation."""
    if not settings.OIDC_ACTIVE_KEY_ID:
        raise OIDCConfigurationError("OIDC active key ID is not configured")

    keys_by_id: dict[str, dict[str, str]] = {}
    active_key = _read_key(settings.OIDC_SIGNING_KEY_PATH, private=True)
    keys_by_id[settings.OIDC_ACTIVE_KEY_ID] = _public_jwk(active_key, settings.OIDC_ACTIVE_KEY_ID)

    for kid, public_key_path in settings.OIDC_PUBLIC_KEY_PATHS.items():
        if not kid:
            raise OIDCConfigurationError("OIDC public key ID is invalid")
        keys_by_id[kid] = _public_jwk(_read_key(public_key_path, private=False), kid)
    return {"keys": list(keys_by_id.values())}


def issue_id_token(
    *,
    subject: str,
    audience: str,
    auth_time: datetime,
    nonce: str | None,
) -> str:
    """Issue a short-lived, asymmetrically signed OIDC ID token."""
    if not settings.OIDC_ACTIVE_KEY_ID or not settings.OIDC_ISSUER:
        raise OIDCConfigurationError("OIDC issuer or active key ID is not configured")

    private_key = _read_key(settings.OIDC_SIGNING_KEY_PATH, private=True)
    now = datetime.now(timezone.utc)
    if auth_time.tzinfo is None:
        auth_time = auth_time.replace(tzinfo=timezone.utc)
    claims: dict[str, object] = {
        "iss": settings.OIDC_ISSUER.rstrip("/"),
        "aud": audience,
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.OIDC_ID_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "auth_time": int(auth_time.astimezone(timezone.utc).timestamp()),
    }
    if nonce is not None:
        claims["nonce"] = nonce

    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": settings.OIDC_ACTIVE_KEY_ID, "typ": "JWT"},
    )
