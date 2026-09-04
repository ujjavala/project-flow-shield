"""Focused tests for OIDC signing, claims, and key rotation metadata."""

from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from app.config import settings
from app.services.oidc_service import get_jwks, issue_id_token


def _write_key_pair(directory, name: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = directory / f"{name}-private.pem"
    public_path = directory / f"{name}-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


def test_id_token_has_standard_claims_and_active_kid(tmp_path, monkeypatch):
    private_path, public_path = _write_key_pair(tmp_path, "active")
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_PATH", str(private_path))
    monkeypatch.setattr(settings, "OIDC_ACTIVE_KEY_ID", "key-2026-09")
    monkeypatch.setattr(settings, "OIDC_ID_TOKEN_EXPIRE_MINUTES", 5)

    auth_time = datetime(2026, 9, 4, 1, 2, 3, tzinfo=timezone.utc)
    token = issue_id_token(
        subject="user-123",
        audience="client-123",
        auth_time=auth_time,
        nonce="request-nonce",
    )

    headers = jwt.get_unverified_header(token)
    claims = jwt.decode(
        token,
        public_path.read_text(),
        algorithms=["RS256"],
        audience="client-123",
        issuer="https://issuer.example",
    )
    assert headers["kid"] == "key-2026-09"
    assert claims["sub"] == "user-123"
    assert claims["aud"] == "client-123"
    assert claims["auth_time"] == int(auth_time.timestamp())
    assert claims["nonce"] == "request-nonce"
    assert claims["exp"] - claims["iat"] == 300


def test_jwks_publishes_active_and_previous_rotation_keys(tmp_path, monkeypatch):
    active_private, _ = _write_key_pair(tmp_path, "active")
    _, previous_public = _write_key_pair(tmp_path, "previous")
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_PATH", str(active_private))
    monkeypatch.setattr(settings, "OIDC_ACTIVE_KEY_ID", "active-key")
    monkeypatch.setattr(settings, "OIDC_PUBLIC_KEY_PATHS", {"previous-key": str(previous_public)})

    keys = get_jwks()["keys"]

    assert {key["kid"] for key in keys} == {"active-key", "previous-key"}
    assert all(key["kty"] == "RSA" and key["alg"] == "RS256" for key in keys)
    assert all("d" not in key for key in keys)
