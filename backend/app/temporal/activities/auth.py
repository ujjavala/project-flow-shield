from temporalio import activity
from datetime import datetime, timedelta
import secrets
import logging

from app.config import settings

logger = logging.getLogger(__name__)

class AuthActivities:
    
    @activity.defn(name="generate_verification_token")
    async def generate_verification_token(self) -> dict:
        """Generate email verification token"""
        try:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS)
            
            return {
                "token": token,
                "expires_at": expires_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to generate verification token: {e}")
            raise
    
    @activity.defn(name="generate_password_reset_token")
    async def generate_password_reset_token(self) -> dict:
        """Generate password reset token"""
        try:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=settings.PASSWORD_RESET_EXPIRE_HOURS)
            
            return {
                "token": token,
                "expires_at": expires_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to generate password reset token: {e}")
            raise
    
    @activity.defn(name="validate_password_reset_token")
    async def validate_password_reset_token(self, token: str) -> bool:
        """Validate password reset token"""
        try:
            from app.database.connection import AsyncSessionLocal
            from app.models.user import User
            from sqlalchemy import select
            
            async with AsyncSessionLocal() as session:
                # Find user by reset token
                result = await session.execute(
                    select(User).where(User.password_reset_token == token)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    return False
                
                # Check token expiry
                if user.password_reset_expires and user.password_reset_expires < datetime.utcnow():
                    return False
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to validate password reset token: {e}")
            return False
    
    @activity.defn(name="generate_oauth_authorization_code")
    async def generate_oauth_authorization_code(self, client_id: str, user_id: str, redirect_uri: str, scope: str = None, state: str = None) -> dict:
        """Generate OAuth2 authorization code"""
        try:
            from app.database.connection import AsyncSessionLocal
            from app.models.oauth import OAuth2AuthorizationCode
            
            code = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(minutes=settings.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES)
            
            async with AsyncSessionLocal() as session:
                auth_code = OAuth2AuthorizationCode(
                    code=code,
                    client_id=client_id,
                    user_id=user_id,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    state=state,
                    expires_at=expires_at
                )
                
                session.add(auth_code)
                await session.commit()
                
                logger.info(f"OAuth2 authorization code generated for client {client_id}, user {user_id}")
                
                return {
                    "code": code,
                    "expires_at": expires_at.isoformat(),
                    "state": state
                }
                
        except Exception as e:
            logger.error(f"Failed to generate OAuth2 authorization code: {e}")
            raise
    
    @activity.defn(name="exchange_authorization_code")
    async def exchange_authorization_code(self, code: str, client_id: str, redirect_uri: str) -> dict:
        """Exchange authorization code for access token"""
        try:
            from app.database.connection import AsyncSessionLocal
            from app.models.oauth import OAuth2AuthorizationCode, OAuth2AccessToken
            from app.utils.security import create_access_token, create_refresh_token
            from sqlalchemy import select
            
            async with AsyncSessionLocal() as session:
                # Find authorization code
                result = await session.execute(
                    select(OAuth2AuthorizationCode).where(
                        OAuth2AuthorizationCode.code == code,
                        OAuth2AuthorizationCode.client_id == client_id,
                        OAuth2AuthorizationCode.redirect_uri == redirect_uri,
                        OAuth2AuthorizationCode.is_used == False
                    )
                )
                auth_code = result.scalar_one_or_none()
                
                if not auth_code:
                    raise ValueError("Invalid authorization code")
                
                # Check expiry
                if auth_code.expires_at < datetime.utcnow():
                    raise ValueError("Authorization code has expired")
                
                # Mark code as used
                auth_code.is_used = True
                
                # Generate tokens
                access_token = create_access_token({"sub": auth_code.user_id, "client_id": client_id})
                refresh_token = create_refresh_token({"sub": auth_code.user_id, "client_id": client_id})
                
                access_token_expires = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
                refresh_token_expires = datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
                
                # Store access token
                oauth_token = OAuth2AccessToken(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    client_id=client_id,
                    user_id=auth_code.user_id,
                    scope=auth_code.scope,
                    expires_at=access_token_expires,
                    refresh_token_expires_at=refresh_token_expires
                )
                
                session.add(oauth_token)
                await session.commit()
                
                logger.info(f"Authorization code exchanged for access token: client {client_id}, user {auth_code.user_id}")
                
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    "scope": auth_code.scope
                }
                
        except Exception as e:
            logger.error(f"Failed to exchange authorization code: {e}")
            raise
    
    @activity.defn(name="revoke_access_token")
    async def revoke_access_token(self, token: str) -> bool:
        """Revoke access token"""
        try:
            from app.database.connection import AsyncSessionLocal
            from app.models.oauth import OAuth2AccessToken
            from sqlalchemy import select
            
            async with AsyncSessionLocal() as session:
                # Find access token
                result = await session.execute(
                    select(OAuth2AccessToken).where(OAuth2AccessToken.access_token == token)
                )
                oauth_token = result.scalar_one_or_none()
                
                if oauth_token:
                    oauth_token.is_revoked = True
                    await session.commit()
                    logger.info(f"Access token revoked: {token[:8]}...")
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"Failed to revoke access token: {e}")
            return False