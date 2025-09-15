"""
PKCE (Proof Key for Code Exchange) Models
OAuth 2.1 standard implementation for enhanced security
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
import secrets
import hashlib
import base64


class PKCERequest(BaseModel):
    """PKCE authorization request"""
    client_id: str
    redirect_uri: str
    scope: Optional[str] = "read write"
    state: Optional[str] = None
    code_challenge: str = Field(..., min_length=43, max_length=128)
    code_challenge_method: str = Field(default="S256", pattern="^(S256|plain)$")
    response_type: str = Field(default="code", pattern="^code$")


class PKCETokenRequest(BaseModel):
    """PKCE token exchange request"""
    grant_type: str = Field(default="authorization_code", pattern="^authorization_code$")
    code: str
    redirect_uri: str
    client_id: str
    code_verifier: str = Field(..., min_length=43, max_length=128)


class PKCEAuthorizationCode(BaseModel):
    """PKCE Authorization Code storage model"""
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: Optional[str]
    state: Optional[str]
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime
    is_used: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class PKCEUtils:
    """PKCE utility functions for OAuth 2.1 compliance"""
    
    @staticmethod
    def generate_code_verifier() -> str:
        """
        Generate a cryptographically random code verifier
        RFC 7636 Section 4.1: 43-128 characters, URL-safe
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    @staticmethod
    def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
        """
        Generate code challenge from verifier
        RFC 7636 Section 4.2: S256 method (SHA256)
        """
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
            return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        elif method == "plain":
            # Plain method not recommended for production
            return code_verifier
        else:
            raise ValueError(f"Unsupported code challenge method: {method}")
    
    @staticmethod
    def verify_code_challenge(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
        """
        Verify code verifier against stored challenge
        Critical security check for PKCE flow
        """
        try:
            expected_challenge = PKCEUtils.generate_code_challenge(code_verifier, method)
            return secrets.compare_digest(expected_challenge, code_challenge)
        except Exception:
            return False
    
    @staticmethod
    def generate_authorization_code() -> str:
        """Generate secure authorization code"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def is_code_expired(expires_at: datetime) -> bool:
        """Check if authorization code has expired"""
        return datetime.utcnow() > expires_at
    
    @staticmethod
    def create_authorization_code(
        client_id: str,
        user_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        expires_in_minutes: int = 10
    ) -> PKCEAuthorizationCode:
        """
        Create a new PKCE authorization code
        RFC 6749 Section 4.1.2: Short lifetime (10 minutes max)
        """
        code = PKCEUtils.generate_authorization_code()
        expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        
        return PKCEAuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at
        )


class PKCEResponse(BaseModel):
    """PKCE authorization response"""
    code: str
    state: Optional[str] = None
    expires_in: int = 600  # 10 minutes


class PKCETokenResponse(BaseModel):
    """PKCE token response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class PKCEError(BaseModel):
    """PKCE error response"""
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
    state: Optional[str] = None


# PKCE Error Types (RFC 6749 Section 5.2)
class PKCEErrorTypes:
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    
    # PKCE-specific errors (RFC 7636)
    INVALID_CODE_CHALLENGE_METHOD = "invalid_request"
    INVALID_CODE_VERIFIER = "invalid_grant"