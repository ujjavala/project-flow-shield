from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta, timezone
import logging
import uuid

from app.database.connection import get_db
from app.models.auth_security import AuthChallenge
from app.models.user import User, RefreshToken
from app.services.session_service import (
    InvalidRefreshToken,
    RefreshTokenReuseDetected,
    create_session_tokens,
    revoke_session,
    rotate_refresh_token,
)
from app.utils.security import (
    verify_password,
    generate_verification_token,
    generate_reset_token,
    hash_one_time_token,
    hash_password,
)
from app.config import settings
from app.services.email_delivery import email_delivery, EmailDeliveryError
from app.services.risk_policy_service import (
    RiskPolicyError,
    build_login_features,
    evaluate_and_persist,
    ollama_shadow_advisor,
    source_ip_is_blocked,
)

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
    session_id: Optional[str] = None
    risk_decision_id: Optional[str] = None
    risk_outcome: Optional[str] = None

class PasswordResetRequestModel(BaseModel):
    email: str

class PasswordResetConfirmModel(BaseModel):
    token: str
    new_password: str

class EmailVerificationModel(BaseModel):
    token: str

class RefreshTokenModel(BaseModel):
    refresh_token: str


async def _evaluate_login_risk(db: AsyncSession, user: User, request: Request):
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    try:
        features = await build_login_features(db, user.id, ip_address, user_agent)
        return await evaluate_and_persist(
            db,
            correlation_id=f"login-{uuid.uuid4()}",
            context="password_login",
            features=features,
            user_id=user.id,
            ai_advisor=ollama_shadow_advisor,
        )
    except RiskPolicyError as exc:
        logger.exception("Risk policy evaluation failed for user id %s", user.id)
        if settings.RISK_POLICY_FAIL_CLOSED or source_ip_is_blocked(ip_address):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication risk could not be safely evaluated",
            ) from exc
        return None


def _enforce_login_risk(risk_decision, user: User) -> None:
    if risk_decision is None:
        return
    if risk_decision.outcome == "deny":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication denied by security policy",
        )
    if risk_decision.outcome == "review":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication requires security review",
        )
    if risk_decision.outcome == "step_up" and not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Additional authentication is required but is not configured",
        )


def _validate_password_login_user(user: User) -> None:
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated",
        )
    if (hasattr(user, "role") and user.role in ["admin", "moderator"]) or user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin users must use admin login endpoint: /admin/auth/login",
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your email and verify your account.",
        )

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
        
        import uuid

        # One-time secrets stay in the API process and are persisted only as hashes.
        verification_token = generate_verification_token()
        new_user = User(
            id=str(uuid.uuid4()),
            email=user_data.email,
            username=user_data.username if user_data.username else None,
            hashed_password=hash_password(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email_verification_token=hash_one_time_token(verification_token),
            email_verification_expires=datetime.now(timezone.utc) + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
            is_verified=False,
            is_active=True
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        logger.info("User registered: %s", user_data.email)

        verification_email_sent = True
        try:
            await email_delivery.send_verification(new_user.email, verification_token)
        except (EmailDeliveryError, OSError):
            verification_email_sent = False
            logger.exception("Verification email delivery failed for %s", new_user.email)
        
        return {
            "success": True,
            "user_id": new_user.id,
            "email": new_user.email,
            "message": "Registration successful. Please check your email to verify your account.",
            "verification_email_sent": verification_email_sent,
            "method": "database"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=None)
async def login(
    user_data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """User login"""
    try:
        result = await db.execute(select(User).where(User.email == user_data.email))
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        _validate_password_login_user(user)

        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        risk_decision = await _evaluate_login_risk(db, user, request)
        _enforce_login_risk(risk_decision, user)
        
        if user.totp_enabled:
            import secrets

            challenge_token = secrets.token_urlsafe(32)
            challenge = AuthChallenge(
                id=str(uuid.uuid4()),
                user_id=user.id,
                purpose="totp_login",
                challenge=hash_one_time_token(challenge_token),
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(
                    seconds=min(settings.AUTH_CHALLENGE_EXPIRE_SECONDS, 600)
                ),
            )
            db.add(challenge)
            await db.commit()
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "mfa_required": True,
                    "challenge_id": challenge.id,
                    "challenge_token": challenge_token,
                    "expires_in": min(settings.AUTH_CHALLENGE_EXPIRE_SECONDS, 600),
                    "risk_decision_id": risk_decision.id if risk_decision else None,
                    "risk_outcome": risk_decision.outcome if risk_decision else "allow",
                },
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        user.last_login = datetime.now(timezone.utc)
        tokens = await create_session_tokens(
            db,
            user,
            authentication_method="password",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        logger.info(f"User logged in directly: {user_data.email}")
        
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            session_id=tokens.session_id,
            risk_decision_id=risk_decision.id if risk_decision else None,
            risk_outcome=risk_decision.outcome if risk_decision else "allow",
        )
        
    except HTTPException:
        raise
    except Exception:
        logger.exception("Login failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: RefreshTokenModel,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Atomically rotate a refresh token; replay revokes its entire family."""
    try:
        tokens = await rotate_refresh_token(db, token_data.refresh_token)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            session_id=tokens.session_id,
        )
    except RefreshTokenReuseDetected as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected; session revoked",
        ) from exc
    except InvalidRefreshToken as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc
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
        result = await db.execute(select(User).where(User.email == request_data.email))
        user = result.scalar_one_or_none()
        
        if user and user.is_active:
            reset_token = generate_reset_token()
            user.password_reset_token = hash_one_time_token(reset_token)
            user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=settings.PASSWORD_RESET_EXPIRE_HOURS)
            
            await db.commit()

            try:
                await email_delivery.send_password_reset(user.email, reset_token)
            except (EmailDeliveryError, OSError):
                logger.exception("Password reset email delivery failed for %s", user.email)
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent."}
        
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
        now = datetime.now(timezone.utc)
        token_digest = hash_one_time_token(reset_data.token)
        result = await db.execute(
            update(User)
            .where(
                User.password_reset_token == token_digest,
                User.password_reset_expires.is_not(None),
                User.password_reset_expires >= now,
                User.is_active.is_(True),
            )
            .values(
                hashed_password=hash_password(reset_data.new_password),
                password_reset_token=None,
                password_reset_expires=None,
            )
            .returning(User.id)
        )
        user_id = result.scalar_one_or_none()
        if user_id is None:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        await db.commit()

        logger.info("Password reset completed for user id %s", user_id)
        return {"message": "Password has been reset successfully. You can now log in with your new password."}
        
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
        now = datetime.now(timezone.utc)
        token_digest = hash_one_time_token(verification_data.token)
        result = await db.execute(
            update(User)
            .where(
                User.email_verification_token == token_digest,
                User.email_verification_expires.is_not(None),
                User.email_verification_expires >= now,
                User.is_active.is_(True),
            )
            .values(
                is_verified=True,
                email_verification_token=None,
                email_verification_expires=None,
            )
            .returning(User.id)
        )
        user_id = result.scalar_one_or_none()
        if user_id is None:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )
        await db.commit()

        logger.info("Email verified for user id %s", user_id)
        return {
            "message": "Email verified successfully. You can now log in."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email verification failed"
        )


@router.post("/resend-verification")
async def resend_verification(
    request_data: PasswordResetRequestModel,
    db: AsyncSession = Depends(get_db),
):
    """Rotate and redeliver a verification token without revealing account state."""
    generic_response = {"message": "If the account exists and is unverified, a verification email has been sent."}
    try:
        result = await db.execute(select(User).where(User.email == request_data.email))
        user = result.scalar_one_or_none()
        if user is None or not user.is_active or user.is_verified:
            return generic_response

        verification_token = generate_verification_token()
        user.email_verification_token = hash_one_time_token(verification_token)
        user.email_verification_expires = datetime.now(timezone.utc) + timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
        )
        await db.commit()

        try:
            await email_delivery.send_verification(user.email, verification_token)
        except (EmailDeliveryError, OSError):
            logger.exception("Verification email redelivery failed for %s", user.email)
        return generic_response
    except Exception:
        logger.exception("Verification email request failed")
        return generic_response

@router.post("/logout")
async def logout(
    token_data: RefreshTokenModel,
    db: AsyncSession = Depends(get_db)
):
    """User logout - revoke refresh token"""
    try:
        token_digest = hash_one_time_token(token_data.refresh_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_digest)
        )
        refresh_token_record = result.scalar_one_or_none()
        
        if refresh_token_record:
            await revoke_session(db, refresh_token_record.session_id, refresh_token_record.user_id)
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )