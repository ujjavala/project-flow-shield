"""Durable models for MFA, passkeys, sessions, and rotating refresh tokens."""

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text
from sqlalchemy.sql import func

from app.database.base import Base


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_name = Column(String(100), nullable=True)
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    authentication_method = Column(String(32), nullable=False, default="password")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    session_id = Column(String, ForeignKey("auth_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    purpose = Column(String(40), nullable=False, index=True)
    challenge = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used_at = Column(DateTime(timezone=True), nullable=True, index=True)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = Column(String(1024), unique=True, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    name = Column(String(100), nullable=False, default="Passkey")
    transports = Column(JSON, nullable=True)
    aaguid = Column(String(64), nullable=True)
    device_type = Column(String(32), nullable=True)
    backed_up = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)


class TOTPRecoveryCode(Base):
    __tablename__ = "totp_recovery_codes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True, index=True)
