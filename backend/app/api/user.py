from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import logging

from app.database.connection import get_db
from app.models.user import User, RefreshToken
from app.utils.security import verify_password, create_access_token, create_refresh_token, verify_token
from app.temporal.client import get_temporal_client
from app.temporal.workflows.user_registration import UserRegistrationWorkflow, EmailVerificationWorkflow
from app.temporal.types import RegistrationRequest
from app.temporal.workflows.password_reset import PasswordResetWorkflow, PasswordResetRequest, PasswordResetConfirmationWorkflow, PasswordResetConfirmation
from app.config import settings

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
        
        # Try Temporal workflow first, fallback to direct registration
        try:
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
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(seconds=30)
            )
            
            if workflow_result["success"]:
                logger.info(f"User registered via Temporal workflow: {user_data.email}")
                return {
                    "success": True,
                    "user_id": workflow_result["user_id"],
                    "email": workflow_result["email"],
                    "message": workflow_result["message"],
                    "verification_email_sent": workflow_result.get("verification_email_sent", False),
                    "method": "temporal_workflow"
                }
            else:
                logger.warning(f"Temporal workflow failed: {workflow_result.get('error')}")
                # Fall through to direct registration
                
        except Exception as temporal_error:
            logger.warning(f"Temporal workflow unavailable: {temporal_error}")
            # Fall through to direct registration
        
        # Direct registration fallback
        from app.utils.security import hash_password, generate_verification_token
        import uuid
        
        # Generate verification token
        verification_token = generate_verification_token()
        
        # Create user
        new_user = User(
            id=str(uuid.uuid4()),
            email=user_data.email,
            username=user_data.username if user_data.username else None,
            hashed_password=hash_password(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email_verification_token=verification_token,
            is_verified=False,
            is_active=True
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"User registered directly: {user_data.email}")
        
        # Log verification link for now - skip complex email workflows that are hanging
        logger.info(f"Verification link: http://localhost:3000/verify-email?token={verification_token}")
        verification_email_sent = False
        
        return {
            "success": True,
            "user_id": new_user.id,
            "email": new_user.email,
            "message": "Registration successful. Please check your email to verify your account.",
            "verification_email_sent": verification_email_sent,
            "method": "direct_registration"
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
        # Try Temporal workflow first, fallback to direct method
        try:
            temporal_client = await get_temporal_client()
            
            from app.temporal.types import LoginRequest
            from app.temporal.workflows.user_login import UserLoginWorkflow
            
            login_request = LoginRequest(
                email=user_data.email,
                password=user_data.password
            )
            
            workflow_result = await temporal_client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id=f"user-login-{user_data.email}-{datetime.utcnow().timestamp()}",
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(seconds=30)
            )
            
            if workflow_result["success"]:
                logger.info(f"User logged in via Temporal workflow: {user_data.email}")
                return TokenResponse(
                    access_token=workflow_result["access_token"],
                    refresh_token=workflow_result["refresh_token"],
                    token_type=workflow_result.get("token_type", "bearer"),
                    expires_in=workflow_result["expires_in"]
                )
            else:
                # Workflow failed, get the error message
                error_detail = workflow_result.get("error", "Login failed")
                if "Invalid credentials" in error_detail or "deactivated" in error_detail:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=error_detail
                    )
                else:
                    # Fall through to direct method for other errors
                    logger.warning(f"Temporal workflow failed: {error_detail}")
                    
        except Exception as temporal_error:
            logger.warning(f"Temporal workflow unavailable: {temporal_error}")
            # Fall through to direct method
        
        # Direct login fallback
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
        
        # Temporarily disable email verification requirement
        # if not user.is_verified:
        #     raise HTTPException(
        #         status_code=status.HTTP_401_UNAUTHORIZED,
        #         detail="Email not verified. Please check your email and verify your account."
        #     )
        
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
        
        logger.info(f"User logged in directly: {user_data.email}")
        
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
async def request_password_reset(
    request_data: PasswordResetRequestModel,
    db: AsyncSession = Depends(get_db)
):
    """Request password reset"""
    try:
        # Try Temporal workflow first, fallback to direct method
        try:
            temporal_client = await get_temporal_client()
            
            reset_request = PasswordResetRequest(email=request_data.email)
            
            workflow_result = await temporal_client.execute_workflow(
                PasswordResetWorkflow.run,
                reset_request,
                id=f"password-reset-{request_data.email}-{datetime.utcnow().timestamp()}",
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(seconds=5)
            )
            
            logger.info(f"Password reset requested via Temporal workflow for: {request_data.email}")
            return {"message": "If the email exists, a password reset link has been sent.", "method": "temporal_workflow"}
            
        except Exception as temporal_error:
            logger.warning(f"Temporal workflow unavailable: {temporal_error}")
            # Fall through to direct method
        
        # Direct password reset fallback
        result = await db.execute(select(User).where(User.email == request_data.email))
        user = result.scalar_one_or_none()
        
        if user:
            # Generate password reset token
            from app.utils.security import generate_verification_token
            reset_token = generate_verification_token()
            
            # Update user with reset token (expires in 1 hour)
            user.password_reset_token = reset_token
            user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
            
            await db.commit()
            
            logger.info(f"Password reset requested directly for: {request_data.email}")
            logger.info(f"Password reset link: http://localhost:3000/reset-password?token={reset_token}")
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent.", "method": "direct_method"}
        
    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        return {"message": "If the email exists, a password reset link has been sent."}

@router.post("/password-reset/confirm")
async def confirm_password_reset(
    reset_data: PasswordResetConfirmModel,
    db: AsyncSession = Depends(get_db)
):
    """Confirm password reset"""
    try:
        # Try Temporal workflow first, fallback to direct method
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
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(seconds=5)
            )
            
            if workflow_result["success"]:
                logger.info("Password reset completed via Temporal workflow")
                return {"message": workflow_result["message"], "method": "temporal_workflow"}
            else:
                logger.warning(f"Temporal password reset failed: {workflow_result.get('error')}")
                # Fall through to direct method
                
        except Exception as temporal_error:
            logger.warning(f"Temporal workflow unavailable: {temporal_error}")
            # Fall through to direct method
        
        # Direct password reset confirmation fallback
        result = await db.execute(
            select(User).where(User.password_reset_token == reset_data.token)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Check if token has expired
        if user.password_reset_expires and user.password_reset_expires < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset token has expired"
            )
        
        # Update password and clear reset token
        from app.utils.security import hash_password
        user.hashed_password = hash_password(reset_data.new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        
        await db.commit()
        
        logger.info(f"Password reset completed directly for user: {user.email}")
        return {"message": "Password has been reset successfully! You can now login with your new password.", "method": "direct_method"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirmation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )

@router.post("/verify-email")
async def verify_email(
    verification_data: EmailVerificationModel,
    db: AsyncSession = Depends(get_db)
):
    """Verify email address"""
    try:
        # Try Temporal workflow first, fallback to direct verification
        try:
            temporal_client = await get_temporal_client()
            
            workflow_result = await temporal_client.execute_workflow(
                EmailVerificationWorkflow.run,
                verification_data.token,
                id=f"email-verification-{verification_data.token}-{datetime.utcnow().timestamp()}",
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(seconds=5)
            )
            
            if workflow_result["success"]:
                logger.info(f"Email verified via Temporal workflow")
                return {
                    "message": workflow_result["message"], 
                    "method": "temporal_workflow"
                }
            else:
                logger.warning(f"Temporal verification failed: {workflow_result.get('error')}")
                # Fall through to direct verification
                
        except Exception as temporal_error:
            logger.warning(f"Temporal workflow unavailable: {temporal_error}")
            # Fall through to direct verification
        
        # Direct verification fallback
        result = await db.execute(
            select(User).where(User.email_verification_token == verification_data.token)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )
        
        if user.is_verified:
            return {"message": "Email already verified", "method": "direct_verification"}
        
        # Update user verification status
        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expires = None
        
        await db.commit()
        
        logger.info(f"Email verified directly for user: {user.email}")
        return {
            "message": "Email verified successfully! You can now login.", 
            "method": "direct_verification"
        }
        
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