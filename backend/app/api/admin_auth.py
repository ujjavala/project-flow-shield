"""
Admin Authentication API
Separate login/authentication endpoints for admin users
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.connection import get_db
from app.models.user import User, RefreshToken
from app.models.auth_security import AuthChallenge
from app.services.session_service import (
    InvalidRefreshToken,
    RefreshTokenReuseDetected,
    create_session_tokens,
    revoke_session,
    rotate_refresh_token,
)
from app.utils.security import hash_one_time_token, verify_password, verify_token
from app.utils.admin_auth import (
    create_admin_session_log,
    ADMIN_SECURITY_HEADERS,
    AdminPermissionChecker,
    _is_admin_user,
    get_admin_user
)
from app.config import settings

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/admin/auth", tags=["Admin Authentication"])

# Request/Response Models
class AdminLoginRequest(BaseModel):
    email: str = Field(..., description="Admin email address")
    password: str = Field(..., description="Admin password")
    remember_me: Optional[bool] = Field(default=False, description="Remember admin session")

class AdminLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    admin_role: str
    permissions: Dict[str, bool]
    session_info: Dict[str, Any]

class AdminPasswordChangeRequest(BaseModel):
    current_password: str = Field(..., description="Current admin password")
    new_password: str = Field(..., description="New admin password")
    force_logout_other_sessions: Optional[bool] = Field(default=True, description="Force logout of other admin sessions")

@router.post("/login", response_model=None)
async def admin_login(
    login_data: AdminLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Admin-specific login endpoint with enhanced security"""

    try:
        # Add admin security headers
        for header, value in ADMIN_SECURITY_HEADERS.items():
            response.headers[header] = value

        # Get user from database
        result = await db.execute(select(User).where(User.email == login_data.email))
        user = result.scalar_one_or_none()

        if not user or not verify_password(login_data.password, user.hashed_password):
            # Log failed admin login attempt
            logger.warning("Admin login failed reason=invalid_credentials")
            await _log_admin_security_event("admin_login_failed", {
                "reason": "invalid_credentials",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials"
            )

        if not user.is_active:
            logger.warning("Admin login failed user_id=%s reason=account_inactive", user.id)
            await _log_admin_security_event("admin_login_failed", {
                "user_id": user.id,
                "reason": "account_inactive",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin account is inactive"
            )

        # Check if user has admin privileges
        if not _is_admin_user(user):
            logger.warning("Admin login failed user_id=%s reason=insufficient_privileges", user.id)
            await _log_admin_security_event("admin_login_failed", {
                "user_id": user.id,
                "reason": "insufficient_privileges",
                "user_role": user.role,
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )

        # Check email verification for admin accounts
        if not user.is_verified:
            logger.warning("Admin login failed user_id=%s reason=email_not_verified", user.id)
            await _log_admin_security_event("admin_login_failed", {
                "user_id": user.id,
                "reason": "email_not_verified",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin email verification required"
            )

        if user.totp_enabled:
            import secrets
            import uuid

            challenge_token = secrets.token_urlsafe(32)
            challenge = AuthChallenge(
                id=str(uuid.uuid4()), user_id=user.id, purpose="totp_login",
                challenge=hash_one_time_token(challenge_token),
                created_at=datetime.now().astimezone(),
                expires_at=datetime.now().astimezone() + timedelta(seconds=min(settings.AUTH_CHALLENGE_EXPIRE_SECONDS, 600)),
            )
            db.add(challenge)
            await db.commit()
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={"mfa_required": True, "challenge_id": challenge.id, "challenge_token": challenge_token,
                         "expires_in": min(settings.AUTH_CHALLENGE_EXPIRE_SECONDS, 600)},
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        admin_token_expire = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        if login_data.remember_me:
            admin_token_expire *= 2  # Extended session for remember me
        user.last_login = datetime.now().astimezone()
        tokens = await create_session_tokens(
            db,
            user,
            authentication_method="admin",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        # Get admin permissions
        permissions = _get_admin_permissions(user)

        # Create session info
        session_info = {
            "login_time": datetime.now().isoformat(),
            "session_type": "admin",
            "remember_me": login_data.remember_me,
            "expires_in_minutes": admin_token_expire
        }

        # Log successful admin login
        logger.info("Admin login succeeded user_id=%s role=%s", user.id, user.role)
        await create_admin_session_log(user, "admin_login_success", {
            "remember_me": login_data.remember_me,
            "permissions": permissions,
            "session_info": session_info
        })

        return AdminLoginResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=admin_token_expire * 60,
            admin_role=user.role,
            permissions=permissions,
            session_info=session_info
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Admin login failed unexpectedly exception_type=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin login failed"
        )

class AdminLogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="Admin refresh token")
    logout_all_sessions: Optional[bool] = Field(default=False, description="Logout from all admin sessions")

@router.post("/logout")
async def admin_logout(
    request: AdminLogoutRequest,
    db: AsyncSession = Depends(get_db)
):
    """Admin logout with option to terminate all sessions"""

    try:
        if request.logout_all_sessions:
            # Find user from refresh token
            result = await db.execute(
                select(RefreshToken).where(RefreshToken.token_hash == hash_one_time_token(request.refresh_token))
            )
            refresh_token_record = result.scalar_one_or_none()

            if refresh_token_record:
                # Revoke all refresh tokens for this admin user
                all_tokens_result = await db.execute(
                    select(RefreshToken).where(RefreshToken.user_id == refresh_token_record.user_id)
                )
                all_tokens = all_tokens_result.scalars().all()

                for token in all_tokens:
                    await revoke_session(db, token.session_id, token.user_id)

                # Get admin user for logging
                admin_user = await db.get(User, refresh_token_record.user_id)
                if admin_user:
                    logger.info("Admin logout-all succeeded user_id=%s", admin_user.id)
                    await create_admin_session_log(admin_user, "admin_logout_all_sessions")

            await db.commit()

            return {
                "message": "Logged out from all admin sessions",
                "sessions_terminated": len(all_tokens) if 'all_tokens' in locals() else 0,
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Revoke single refresh token
            result = await db.execute(
                select(RefreshToken).where(RefreshToken.token_hash == hash_one_time_token(request.refresh_token))
            )
            refresh_token_record = result.scalar_one_or_none()

            if refresh_token_record:
                await revoke_session(db, refresh_token_record.session_id, refresh_token_record.user_id)

                # Get admin user for logging
                admin_user = await db.get(User, refresh_token_record.user_id)
                if admin_user:
                    logger.info("Admin logout succeeded user_id=%s", admin_user.id)
                    await create_admin_session_log(admin_user, "admin_logout_single_session")

            await db.commit()

            return {
                "message": "Admin logged out successfully",
                "timestamp": datetime.now().isoformat()
            }

    except Exception as exc:
        logger.error("Admin logout failed exception_type=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin logout failed"
        )

class AdminRefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Admin refresh token")

@router.post("/refresh")
async def admin_refresh_token(
    request: AdminRefreshRequest,
    db: AsyncSession = Depends(get_db)
):
    """Refresh admin access token"""

    try:
        tokens = await rotate_refresh_token(db, request.refresh_token)
        payload = verify_token(tokens.access_token)
        admin_user = await db.get(User, payload["sub"] if payload else None)
        if admin_user is None or not _is_admin_user(admin_user):
            if admin_user is not None:
                await revoke_session(db, tokens.session_id, admin_user.id)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

        # Log token refresh
        await create_admin_session_log(admin_user, "admin_token_refresh")

        return {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "admin_role": admin_user.role
        }

    except (InvalidRefreshToken, RefreshTokenReuseDetected) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin refresh token") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Admin token refresh failed exception_type=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin token refresh failed"
        )

@router.get("/session-info")
async def get_admin_session_info(
    admin_user = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current admin session information"""

    try:
        # Get active sessions count
        active_sessions_result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == admin_user.id,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.utcnow()
            )
        )
        active_sessions = len(active_sessions_result.scalars().all())

        permissions = _get_admin_permissions(admin_user)

        session_info = {
            "admin_id": admin_user.id,
            "admin_email": admin_user.email,
            "admin_role": admin_user.role,
            "is_superuser": admin_user.is_superuser,
            "last_login": admin_user.last_login.isoformat() if admin_user.last_login else None,
            "active_sessions": active_sessions,
            "permissions": permissions,
            "session_type": "admin",
            "current_time": datetime.now().isoformat()
        }

        return session_info

    except Exception as exc:
        logger.error("Failed to get admin session info exception_type=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve admin session information"
        )

@router.get("/health")
async def admin_auth_health():
    """Health check for admin authentication service"""

    return {
        "status": "healthy",
        "service": "admin_authentication",
        "timestamp": datetime.now().isoformat(),
        "features": {
            "admin_login": True,
            "session_management": True,
            "role_based_access": True,
            "audit_logging": True
        }
    }

# Helper functions

def _get_admin_permissions(admin_user: User) -> Dict[str, bool]:
    """Get admin permissions based on role"""

    checker = AdminPermissionChecker()

    return {
        "can_manage_users": checker.can_manage_users(admin_user),
        "can_view_system_logs": checker.can_view_system_logs(admin_user),
        "can_modify_security_settings": checker.can_modify_security_settings(admin_user),
        "can_access_rate_limiting": checker.can_access_rate_limiting(admin_user),
        "can_manage_workflows": checker.can_manage_workflows(admin_user),
        "can_export_data": checker.can_export_data(admin_user)
    }

async def _log_admin_security_event(event_type: str, details: Dict[str, Any]):
    """Log admin security events"""

    try:
        security_log = {
            "event_type": event_type,
            "timestamp": datetime.now().isoformat(),
            "details": {
                key: value
                for key, value in details.items()
                if key in {"reason", "user_id", "user_role", "timestamp"}
            },
            "source": "admin_auth"
        }

        # TODO: Store in security audit table
        logger.warning("ADMIN_SECURITY_EVENT: %s", security_log)

    except Exception as exc:
        logger.error("Failed to log admin security event exception_type=%s", type(exc).__name__)