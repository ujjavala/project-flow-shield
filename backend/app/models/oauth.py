from sqlalchemy import Column, String, Boolean, DateTime, Text, JSON
from app.database.base import Base
from sqlalchemy.sql import func
import uuid

class OAuth2Client(Base):
    __tablename__ = "oauth2_clients"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = Column(String(255), unique=True, nullable=False, index=True)
    client_secret = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    
    # Client configuration
    grant_types = Column(JSON, default=["authorization_code", "refresh_token"])
    response_types = Column(JSON, default=["code"])
    redirect_uris = Column(JSON, nullable=False)
    scope = Column(String(255), default="read write")
    
    # Client metadata
    logo_uri = Column(String(255), nullable=True)
    homepage_uri = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_confidential = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<OAuth2Client(client_id={self.client_id}, name={self.client_name})>"

class OAuth2AuthorizationCode(Base):
    __tablename__ = "oauth2_authorization_codes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    code = Column(String(255), unique=True, nullable=False, index=True)
    client_id = Column(String(255), nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    
    # Authorization details
    redirect_uri = Column(String(255), nullable=False)
    scope = Column(String(255), nullable=True)
    state = Column(String(255), nullable=True)
    
    # Code challenge for PKCE
    code_challenge = Column(String(255), nullable=True)
    code_challenge_method = Column(String(10), nullable=True)
    
    # Status and expiry
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<OAuth2AuthorizationCode(code={self.code[:8]}..., client_id={self.client_id})>"

class OAuth2AccessToken(Base):
    __tablename__ = "oauth2_access_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    access_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), nullable=True, index=True)
    client_id = Column(String(255), nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    
    # Token details
    scope = Column(String(255), nullable=True)
    token_type = Column(String(50), default="Bearer")
    
    # Expiry
    expires_at = Column(DateTime(timezone=True), nullable=False)
    refresh_token_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Status
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<OAuth2AccessToken(token={self.access_token[:8]}..., client_id={self.client_id})>"