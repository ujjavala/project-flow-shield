"""
Admin Authentication API
Separate login/authentication endpoints for admin users
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.connection import get_db
from app.models.user import User, RefreshToken
from app.utils.security import verify_password, create_access_token, create_refresh_token
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

@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(
    login_data: AdminLoginRequest,
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
            logger.warning(f"Failed admin login attempt for: {login_data.email}")
            await _log_admin_security_event("admin_login_failed", {
                "email": login_data.email,
                "reason": "invalid_credentials",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials"
            )

        if not user.is_active:
            logger.warning(f"Inactive admin account login attempt: {login_data.email}")
            await _log_admin_security_event("admin_login_failed", {
                "email": login_data.email,
                "reason": "account_inactive",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin account is inactive"
            )

        # Check if user has admin privileges
        if not _is_admin_user(user):
            logger.warning(f"Non-admin user attempted admin login: {login_data.email}")
            await _log_admin_security_event("admin_login_failed", {
                "email": login_data.email,
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
            logger.warning(f"Unverified admin account login attempt: {login_data.email}")
            await _log_admin_security_event("admin_login_failed", {
                "email": login_data.email,
                "reason": "email_not_verified",
                "timestamp": datetime.now().isoformat()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin email verification required"
            )

        # Create admin tokens with enhanced payload
        token_payload = {
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "is_admin": True,
            "session_type": "admin"
        }

        # Adjust token expiration for admin sessions
        admin_token_expire = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        if login_data.remember_me:
            admin_token_expire *= 2  # Extended session for remember me

        access_token = create_access_token(token_payload, expires_delta=timedelta(minutes=admin_token_expire))
        refresh_token = create_refresh_token({"sub": user.id, "is_admin": True})

        # Store refresh token with admin flag
        refresh_token_record = RefreshToken(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        )
        db.add(refresh_token_record)

        # Update last login
        user.last_login = datetime.utcnow()
        await db.commit()

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
        logger.info(f"Admin user logged in successfully: {user.email} (role: {user.role})")
        await create_admin_session_log(user, "admin_login_success", {
            "remember_me": login_data.remember_me,
            "permissions": permissions,
            "session_info": session_info
        })

        return AdminLoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=admin_token_expire * 60,
            admin_role=user.role,
            permissions=permissions,
            session_info=session_info
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin login failed: {e}")
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
                select(RefreshToken).where(RefreshToken.token == request.refresh_token)
            )
            refresh_token_record = result.scalar_one_or_none()

            if refresh_token_record:
                # Revoke all refresh tokens for this admin user
                all_tokens_result = await db.execute(
                    select(RefreshToken).where(RefreshToken.user_id == refresh_token_record.user_id)
                )
                all_tokens = all_tokens_result.scalars().all()

                for token in all_tokens:
                    token.is_revoked = True

                # Get admin user for logging
                admin_user = await db.get(User, refresh_token_record.user_id)
                if admin_user:
                    logger.info(f"Admin user logged out from all sessions: {admin_user.email}")
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
                select(RefreshToken).where(RefreshToken.token == request.refresh_token)
            )
            refresh_token_record = result.scalar_one_or_none()

            if refresh_token_record:
                refresh_token_record.is_revoked = True

                # Get admin user for logging
                admin_user = await db.get(User, refresh_token_record.user_id)
                if admin_user:
                    logger.info(f"Admin user logged out: {admin_user.email}")
                    await create_admin_session_log(admin_user, "admin_logout_single_session")

            await db.commit()

            return {
                "message": "Admin logged out successfully",
                "timestamp": datetime.now().isoformat()
            }

    except Exception as e:
        logger.error(f"Admin logout failed: {e}")
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
        from app.utils.security import verify_token

        # Verify refresh token
        payload = verify_token(request.refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin refresh token"
            )

        user_id = payload.get("sub")
        is_admin = payload.get("is_admin", False)

        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin refresh token required"
            )

        # Check if refresh token exists and is not revoked
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token == request.refresh_token,
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False
            )
        )
        refresh_token_record = result.scalar_one_or_none()

        if not refresh_token_record or refresh_token_record.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin refresh token expired or revoked"
            )

        # Get admin user
        admin_user = await db.get(User, user_id)
        if not admin_user or not admin_user.is_active or not _is_admin_user(admin_user):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin user not found or inactive"
            )

        # Create new admin access token
        token_payload = {
            "sub": admin_user.id,
            "email": admin_user.email,
            "role": admin_user.role,
            "is_admin": True,
            "session_type": "admin"
        }

        access_token = create_access_token(token_payload)

        # Log token refresh
        await create_admin_session_log(admin_user, "admin_token_refresh")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "admin_role": admin_user.role
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin token refresh failed: {e}")
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

    except Exception as e:
        logger.error(f"Failed to get admin session info: {e}")
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
            "details": details,
            "source": "admin_auth"
        }

        # TODO: Store in security audit table
        logger.warning(f"ADMIN_SECURITY_EVENT: {security_log}")

    except Exception as e:
        logger.error(f"Failed to log admin security event: {e}")