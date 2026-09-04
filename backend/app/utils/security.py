from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher
from jwt import InvalidTokenError, decode, encode
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import secrets
import hashlib
from app.config import settings

# New passwords use Argon2id; bcrypt remains available to verify seeded and
# existing credentials until they are upgraded after a successful login.
password_hash = PasswordHash((Argon2Hasher(), BcryptHasher()))

def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return password_hash.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        return password_hash.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "access"
    })
    
    encoded_jwt = encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt

def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "refresh"
    })
    
    encoded_jwt = encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token and return payload"""
    try:
        payload = decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except InvalidTokenError:
        return None

def generate_state() -> str:
    """Generate secure random state for OAuth2"""
    return secrets.token_urlsafe(32)

def generate_client_secret() -> str:
    """Generate secure client secret"""
    return secrets.token_urlsafe(64)

def generate_authorization_code() -> str:
    """Generate OAuth2 authorization code"""
    return secrets.token_urlsafe(32)

def generate_token() -> str:
    """Generate generic secure token"""
    return secrets.token_urlsafe(32)

def generate_verification_token() -> str:
    """Generate a secure email verification token"""
    return secrets.token_urlsafe(32)

def generate_reset_token() -> str:
    """Generate a secure password reset token"""
    return secrets.token_urlsafe(32)

def hash_one_time_token(token: str) -> str:
    """Return a deterministic digest suitable for storing a random one-time token."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()

def generate_access_token_string() -> str:
    """Generate a secure access token string"""
    return secrets.token_urlsafe(48)

def generate_refresh_token_string() -> str:
    """Generate a secure refresh token string"""
    return secrets.token_urlsafe(48)

def is_strong_password(password: str) -> bool:
    """Check if password meets strength requirements"""
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    return has_upper and has_lower and has_digit and has_special