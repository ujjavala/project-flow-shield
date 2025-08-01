from temporalio import activity
from dataclasses import dataclass
from typing import Optional
import logging
from datetime import datetime

from app.database.connection import AsyncSessionLocal
from app.models.user import User
from app.utils.security import hash_password
from sqlalchemy import select

logger = logging.getLogger(__name__)

@dataclass
class UserCreateData:
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None

@dataclass
class UserUpdateData:
    user_id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    is_verified: Optional[bool] = None
    is_active: Optional[bool] = None

class UserActivities:
    
    @activity.defn(name="create_user")
    async def create_user(self, user_data: UserCreateData, verification_token: str) -> dict:
        """Create a new user in the database"""
        try:
            async with AsyncSessionLocal() as session:
                # Check if user already exists
                existing_user = await session.execute(
                    select(User).where(User.email == user_data.email)
                )
                if existing_user.scalar_one_or_none():
                    raise ValueError(f"User with email {user_data.email} already exists")
                
                # Create new user
                hashed_password = hash_password(user_data.password)
                
                new_user = User(
                    email=user_data.email,
                    username=user_data.username,
                    hashed_password=hashed_password,
                    first_name=user_data.first_name,
                    last_name=user_data.last_name,
                    email_verification_token=verification_token,
                    is_verified=False,
                    is_active=True
                )
                
                session.add(new_user)
                await session.commit()
                await session.refresh(new_user)
                
                logger.info(f"User created successfully: {user_data.email}")
                
                return {
                    "user_id": new_user.id,
                    "email": new_user.email,
                    "username": new_user.username,
                    "first_name": new_user.first_name,
                    "last_name": new_user.last_name,
                    "created_at": new_user.created_at.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to create user {user_data.email}: {e}")
            raise
    
    @activity.defn(name="update_user")
    async def update_user(self, update_data: UserUpdateData) -> dict:
        """Update user information"""
        try:
            async with AsyncSessionLocal() as session:
                # Get user
                user = await session.get(User, update_data.user_id)
                if not user:
                    raise ValueError(f"User with ID {update_data.user_id} not found")
                
                # Update fields
                if update_data.email is not None:
                    user.email = update_data.email
                if update_data.first_name is not None:
                    user.first_name = update_data.first_name
                if update_data.last_name is not None:
                    user.last_name = update_data.last_name
                if update_data.username is not None:
                    user.username = update_data.username
                if update_data.is_verified is not None:
                    user.is_verified = update_data.is_verified
                if update_data.is_active is not None:
                    user.is_active = update_data.is_active
                
                user.updated_at = datetime.utcnow()
                
                await session.commit()
                await session.refresh(user)
                
                logger.info(f"User updated successfully: {user.email}")
                
                return {
                    "user_id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "is_verified": user.is_verified,
                    "is_active": user.is_active,
                    "updated_at": user.updated_at.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to update user {update_data.user_id}: {e}")
            raise
    
    @activity.defn(name="verify_user_email")
    async def verify_user_email(self, verification_token: str) -> dict:
        """Verify user email using verification token"""
        try:
            async with AsyncSessionLocal() as session:
                # Find user by verification token
                result = await session.execute(
                    select(User).where(User.email_verification_token == verification_token)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    raise ValueError("Invalid verification token")
                
                if user.is_verified:
                    raise ValueError("Email already verified")
                
                # Check token expiry if set
                if user.email_verification_expires and user.email_verification_expires < datetime.utcnow():
                    raise ValueError("Verification token has expired")
                
                # Verify user
                user.is_verified = True
                user.email_verification_token = None
                user.email_verification_expires = None
                user.updated_at = datetime.utcnow()
                
                await session.commit()
                await session.refresh(user)
                
                logger.info(f"User email verified successfully: {user.email}")
                
                return {
                    "user_id": user.id,
                    "email": user.email,
                    "is_verified": user.is_verified,
                    "verified_at": user.updated_at.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to verify email with token {verification_token}: {e}")
            raise
    
    @activity.defn(name="set_password_reset_token")
    async def set_password_reset_token(self, email: str, reset_token: str, expires_at: datetime) -> bool:
        """Set password reset token for user"""
        try:
            async with AsyncSessionLocal() as session:
                # Find user by email
                result = await session.execute(
                    select(User).where(User.email == email)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    raise ValueError(f"User with email {email} not found")
                
                # Set reset token
                user.password_reset_token = reset_token
                user.password_reset_expires = expires_at
                user.updated_at = datetime.utcnow()
                
                await session.commit()
                
                logger.info(f"Password reset token set for user: {email}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to set password reset token for {email}: {e}")
            raise
    
    @activity.defn(name="reset_user_password")
    async def reset_user_password(self, reset_token: str, new_password: str) -> dict:
        """Reset user password using reset token"""
        try:
            async with AsyncSessionLocal() as session:
                # Find user by reset token
                result = await session.execute(
                    select(User).where(User.password_reset_token == reset_token)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    raise ValueError("Invalid password reset token")
                
                # Check token expiry
                if user.password_reset_expires and user.password_reset_expires < datetime.utcnow():
                    raise ValueError("Password reset token has expired")
                
                # Reset password
                user.hashed_password = hash_password(new_password)
                user.password_reset_token = None
                user.password_reset_expires = None
                user.updated_at = datetime.utcnow()
                
                await session.commit()
                await session.refresh(user)
                
                logger.info(f"Password reset successfully for user: {user.email}")
                
                return {
                    "user_id": user.id,
                    "email": user.email,
                    "password_reset_at": user.updated_at.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to reset password with token {reset_token}: {e}")
            raise