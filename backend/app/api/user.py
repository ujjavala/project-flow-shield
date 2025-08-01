from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import logging

from app.database.connection import get_db
from app.models.user import User, RefreshToken
from app.utils.security import verify_password, create_access_token, create_refresh_token, verify_token
from app.temporal.client import get_temporal_client
from app.temporal.workflows.user_registration import UserRegistrationWorkflow, RegistrationRequest, EmailVerificationWorkflow
from app.temporal.workflows.password_reset import PasswordResetWorkflow, PasswordResetRequest, PasswordResetConfirmationWorkflow, PasswordResetConfirmation

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models
class UserRegister(BaseModel):
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class PasswordResetRequestModel(BaseModel):
    email: str

class PasswordResetConfirmModel(BaseModel):
    token: str
    new_password: str

class EmailVerificationModel(BaseModel):
    token: str

class RefreshTokenModel(BaseModel):
    refresh_token: str

@router.post("/register", response_model=dict)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user"""
    try:
        # Check if user already exists
        result = await db.execute(select(User).where(User.email == user_data.email))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        
        # Start user registration workflow
        temporal_client = await get_temporal_client()
        
        registration_request = RegistrationRequest(
            email=user_data.email,
            password=user_data.password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            username=user_data.username
        )
        
        workflow_result = await temporal_client.execute_workflow(
            UserRegistrationWorkflow.run,
            registration_request,
            id=f"user-registration-{user_data.email}-{datetime.utcnow().timestamp()}",
            task_queue="oauth2-task-queue"
        )
        
        if not workflow_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=workflow_result["message"]
            )
        
        return {
            "message": workflow_result["message"],
            "user_id": workflow_result["user_id"],
            "email": workflow_result["email"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=TokenResponse)
async def login(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """User login"""
    try:
        # Find user
        result = await db.execute(select(User).where(User.email == user_data.email))
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified. Please check your email and verify your account."
            )
        
        # Create tokens
        access_token = create_access_token({"sub": user.id, "email": user.email})
        refresh_token = create_refresh_token({"sub": user.id})
        
        # Store refresh token
        refresh_token_record = RefreshToken(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        )
        db.add(refresh_token_record)
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        await db.commit()
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: RefreshTokenModel,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token"""
    try:
        # Verify refresh token
        payload = verify_token(token_data.refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user_id = payload.get("sub")
        
        # Check if refresh token exists and is not revoked
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token == token_data.refresh_token,
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False
            )
        )
        refresh_token_record = result.scalar_one_or_none()
        
        if not refresh_token_record or refresh_token_record.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired or revoked"
            )
        
        # Get user
        user = await db.get(User, user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new access token
        access_token = create_access_token({"sub": user.id, "email": user.email})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=token_data.refresh_token,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/password-reset/request")
async def request_password_reset(request_data: PasswordResetRequestModel):
    """Request password reset"""
    try:
        temporal_client = await get_temporal_client()
        
        reset_request = PasswordResetRequest(email=request_data.email)
        
        workflow_result = await temporal_client.execute_workflow(
            PasswordResetWorkflow.run,
            reset_request,
            id=f"password-reset-{request_data.email}-{datetime.utcnow().timestamp()}",
            task_queue="oauth2-task-queue"
        )
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent."}
        
    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        return {"message": "If the email exists, a password reset link has been sent."}

@router.post("/password-reset/confirm")
async def confirm_password_reset(reset_data: PasswordResetConfirmModel):
    """Confirm password reset"""
    try:
        temporal_client = await get_temporal_client()
        
        reset_confirmation = PasswordResetConfirmation(
            reset_token=reset_data.token,
            new_password=reset_data.new_password
        )
        
        workflow_result = await temporal_client.execute_workflow(
            PasswordResetConfirmationWorkflow.run,
            reset_confirmation,
            id=f"password-reset-confirm-{reset_data.token}-{datetime.utcnow().timestamp()}",
            task_queue="oauth2-task-queue"
        )
        
        if not workflow_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=workflow_result["message"]
            )
        
        return {"message": workflow_result["message"]}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirmation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )

@router.post("/verify-email")
async def verify_email(verification_data: EmailVerificationModel):
    """Verify email address"""
    try:
        temporal_client = await get_temporal_client()
        
        workflow_result = await temporal_client.execute_workflow(
            EmailVerificationWorkflow.run,
            verification_data.token,
            id=f"email-verification-{verification_data.token}-{datetime.utcnow().timestamp()}",
            task_queue="oauth2-task-queue"
        )
        
        if not workflow_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=workflow_result["message"]
            )
        
        return {"message": workflow_result["message"]}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email verification failed"
        )

@router.post("/logout")
async def logout(
    token_data: RefreshTokenModel,
    db: AsyncSession = Depends(get_db)
):
    """User logout - revoke refresh token"""
    try:
        # Revoke refresh token
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token == token_data.refresh_token)
        )
        refresh_token_record = result.scalar_one_or_none()
        
        if refresh_token_record:
            refresh_token_record.is_revoked = True
            await db.commit()
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )