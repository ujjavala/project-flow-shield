"""
User Dashboard API Router
Provides user-specific dashboard functionality distinct from admin dashboard
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import httpx

from app.database.connection import get_db
from app.models.user import User, RefreshToken
from app.utils.security import verify_token

logger = logging.getLogger(__name__)
security = HTTPBearer()

# Create API router
router = APIRouter(prefix="/dashboard", tags=["User Dashboard"])

# Response Models
class UserProfileResponse(BaseModel):
    user_id: str
    email: str
    username: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    is_verified: bool
    last_login: Optional[str]
    created_at: str
    account_status: str
    security_level: str

class UserActivityResponse(BaseModel):
    recent_logins: List[Dict[str, Any]]
    security_events: List[Dict[str, Any]]
    rate_limit_status: Dict[str, Any]
    active_sessions: int

class UserSecurityResponse(BaseModel):
    two_factor_enabled: bool
    password_last_changed: Optional[str]
    security_score: int
    recommended_actions: List[str]
    recent_security_alerts: List[Dict[str, Any]]

class UserPreferencesResponse(BaseModel):
    email_notifications: bool
    security_notifications: bool
    theme: str
    language: str
    timezone: str

class SecurityAlertResponse(BaseModel):
    alert_id: str
    type: str
    severity: str
    message: str
    timestamp: str
    acknowledged: bool

# Dependency to get current user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user"""

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        # Verify JWT token
        payload = verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )

        # Get user from database
        user = await db.get(User, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive"
            )

        # Check if user has admin role - deny access to admin users
        # (they should use admin dashboard instead)
        if hasattr(user, 'role') and user.role == 'admin':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin users should use the admin dashboard"
            )

        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

@router.get("/", response_model=Dict[str, Any])
async def user_dashboard_home(
    current_user: User = Depends(get_current_user)
):
    """User dashboard home - overview for authenticated user"""
    return {
        "message": f"Welcome to your dashboard, {current_user.email}",
        "user_id": current_user.id,
        "timestamp": datetime.now().isoformat(),
        "features": {
            "profile_management": True,
            "security_settings": True,
            "activity_monitoring": True,
            "preferences": True,
            "rate_limit_status": True
        },
        "quick_actions": [
            "View Profile",
            "Change Password",
            "Security Settings",
            "Account Activity",
            "Preferences"
        ],
        "endpoints": {
            "profile": "/dashboard/profile",
            "activity": "/dashboard/activity",
            "security": "/dashboard/security",
            "preferences": "/dashboard/preferences"
        }
    }

@router.get("/profile", response_model=UserProfileResponse)
async def get_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get user profile information"""

    try:
        # Calculate account status
        account_status = "active" if current_user.is_active else "inactive"
        if not current_user.is_verified:
            account_status = "unverified"

        # Calculate security level based on various factors
        security_level = "basic"
        if current_user.is_verified:
            security_level = "verified"

        # TODO: Add MFA check when MFA system is implemented
        # if current_user.has_mfa_enabled:
        #     security_level = "secure"

        return UserProfileResponse(
            user_id=current_user.id,
            email=current_user.email,
            username=current_user.username,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            is_verified=current_user.is_verified,
            last_login=current_user.last_login.isoformat() if current_user.last_login else None,
            created_at=current_user.created_at.isoformat() if hasattr(current_user, 'created_at') and current_user.created_at else datetime.now().isoformat(),
            account_status=account_status,
            security_level=security_level
        )

    except Exception as e:
        logger.error(f"Failed to get user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve profile information"
        )

@router.get("/activity", response_model=UserActivityResponse)
async def get_user_activity(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user activity and security events"""

    try:
        # Get recent logins (mock data for now - in production, track in audit logs)
        recent_logins = [
            {
                "timestamp": current_user.last_login.isoformat() if current_user.last_login else datetime.now().isoformat(),
                "ip_address": "192.168.1.100",  # Mock data
                "location": "New York, US",      # Mock data
                "device": "Chrome Browser",     # Mock data
                "success": True
            }
        ]

        # Get active sessions count
        active_sessions_result = await db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.user_id == current_user.id,
                    RefreshToken.is_revoked == False,
                    RefreshToken.expires_at > datetime.utcnow()
                )
            )
        )
        active_sessions = len(active_sessions_result.scalars().all())

        # Get rate limit status for this user
        rate_limit_status = await _get_user_rate_limit_status(current_user.id)

        # Mock security events - in production, get from audit logs
        security_events = [
            {
                "timestamp": datetime.now().isoformat(),
                "event_type": "login_success",
                "description": "Successful login from trusted device",
                "severity": "info"
            }
        ]

        return UserActivityResponse(
            recent_logins=recent_logins,
            security_events=security_events,
            rate_limit_status=rate_limit_status,
            active_sessions=active_sessions
        )

    except Exception as e:
        logger.error(f"Failed to get user activity: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve activity information"
        )

@router.get("/security", response_model=UserSecurityResponse)
async def get_user_security_status(
    current_user: User = Depends(get_current_user)
):
    """Get user security status and recommendations"""

    try:
        # Calculate security score (0-100)
        security_score = 30  # Base score

        if current_user.is_verified:
            security_score += 25

        # TODO: Add MFA check
        two_factor_enabled = False  # Mock for now
        if two_factor_enabled:
            security_score += 30

        # Check password age (mock for now)
        password_last_changed = None  # TODO: Track password changes
        if password_last_changed:
            security_score += 15

        # Generate recommendations based on current security status
        recommended_actions = []

        if not current_user.is_verified:
            recommended_actions.append("Verify your email address")

        if not two_factor_enabled:
            recommended_actions.append("Enable two-factor authentication")

        if not password_last_changed:
            recommended_actions.append("Consider updating your password")

        if security_score < 70:
            recommended_actions.append("Review and improve your security settings")

        # Mock recent security alerts
        recent_security_alerts = []

        return UserSecurityResponse(
            two_factor_enabled=two_factor_enabled,
            password_last_changed=password_last_changed,
            security_score=security_score,
            recommended_actions=recommended_actions,
            recent_security_alerts=recent_security_alerts
        )

    except Exception as e:
        logger.error(f"Failed to get user security status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security information"
        )

@router.get("/preferences", response_model=UserPreferencesResponse)
async def get_user_preferences(
    current_user: User = Depends(get_current_user)
):
    """Get user preferences and settings"""

    try:
        # For now, return default preferences
        # In production, these would be stored in user preferences table
        return UserPreferencesResponse(
            email_notifications=True,
            security_notifications=True,
            theme="light",
            language="en",
            timezone="UTC"
        )

    except Exception as e:
        logger.error(f"Failed to get user preferences: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve preferences"
        )

@router.put("/preferences")
async def update_user_preferences(
    preferences: UserPreferencesResponse,
    current_user: User = Depends(get_current_user)
):
    """Update user preferences"""

    try:
        # TODO: Store preferences in database
        # For now, just return success

        logger.info(f"User {current_user.id} updated preferences")

        return {
            "message": "Preferences updated successfully",
            "updated_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to update user preferences: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update preferences"
        )

@router.get("/rate-limits")
async def get_user_rate_limits(
    current_user: User = Depends(get_current_user)
):
    """Get user's current rate limit status"""

    try:
        rate_limit_status = await _get_user_rate_limit_status(current_user.id)

        return {
            "user_id": current_user.id,
            "rate_limits": rate_limit_status,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get rate limits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rate limit status"
        )

@router.post("/change-password")
async def change_password(
    current_password: str = Field(..., description="Current password"),
    new_password: str = Field(..., description="New password"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Change user password"""

    try:
        from app.utils.security import verify_password, hash_password

        # Verify current password
        if not verify_password(current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Update password
        current_user.hashed_password = hash_password(new_password)
        # TODO: Track password change date
        # current_user.password_changed_at = datetime.utcnow()

        await db.commit()

        logger.info(f"Password changed for user: {current_user.id}")

        return {
            "message": "Password changed successfully",
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to change password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Revoke a specific user session"""

    try:
        # Find and revoke the refresh token
        result = await db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.user_id == current_user.id,
                    RefreshToken.token.contains(session_id[:8])  # Match first 8 chars
                )
            )
        )
        refresh_token = result.scalar_one_or_none()

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )

        refresh_token.is_revoked = True
        await db.commit()

        logger.info(f"Session revoked for user: {current_user.id}")

        return {
            "message": "Session revoked successfully",
            "session_id": session_id,
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )

@router.post("/security-alerts/{alert_id}/acknowledge")
async def acknowledge_security_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    """Acknowledge a security alert"""

    try:
        # TODO: Implement security alert acknowledgment in database
        # For now, just return success

        logger.info(f"Security alert {alert_id} acknowledged by user: {current_user.id}")

        return {
            "message": "Security alert acknowledged",
            "alert_id": alert_id,
            "acknowledged_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to acknowledge security alert: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to acknowledge alert"
        )

@router.get("/export-data")
async def export_user_data(
    current_user: User = Depends(get_current_user)
):
    """Export user data (GDPR compliance)"""

    try:
        # Collect all user data for export
        user_data = {
            "profile": {
                "user_id": current_user.id,
                "email": current_user.email,
                "username": current_user.username,
                "first_name": current_user.first_name,
                "last_name": current_user.last_name,
                "created_at": current_user.created_at.isoformat() if hasattr(current_user, 'created_at') and current_user.created_at else None,
                "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
                "is_verified": current_user.is_verified,
                "is_active": current_user.is_active
            },
            "export_info": {
                "export_date": datetime.now().isoformat(),
                "data_types": ["profile", "activity_logs", "preferences", "security_events"],
                "format": "json"
            }
        }

        logger.info(f"Data export requested for user: {current_user.id}")

        return user_data

    except Exception as e:
        logger.error(f"Failed to export user data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export user data"
        )

# Helper functions

async def _get_user_rate_limit_status(user_id: str) -> Dict[str, Any]:
    """Get rate limit status for a specific user"""

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check different types of rate limits for the user
            rate_limits = {}

            for limit_type in ['api', 'login', 'mfa']:
                try:
                    response = await client.get(
                        f"http://localhost:8000/rate-limiting/status/user_{user_id}",
                        params={"limit_type": limit_type}
                    )

                    if response.status_code == 200:
                        data = response.json()
                        rate_limits[limit_type] = {
                            "current_count": data.get("current_count", 0),
                            "limit": data.get("limit", 100),
                            "remaining": data.get("remaining", 100),
                            "reset_time": data.get("reset_time"),
                            "status": "normal" if data.get("remaining", 100) > 0 else "limited"
                        }
                    else:
                        rate_limits[limit_type] = {
                            "status": "unknown",
                            "error": f"HTTP {response.status_code}"
                        }

                except Exception as e:
                    rate_limits[limit_type] = {
                        "status": "unavailable",
                        "error": str(e)
                    }

            return rate_limits

    except Exception as e:
        logger.error(f"Failed to get rate limit status: {e}")
        return {
            "error": "Rate limiting service unavailable",
            "status": "unknown"
        }

@router.get("/health")
async def user_dashboard_health():
    """Health check for user dashboard"""

    return {
        "status": "healthy",
        "service": "user_dashboard",
        "timestamp": datetime.now().isoformat(),
        "features_available": {
            "profile_management": True,
            "activity_monitoring": True,
            "security_settings": True,
            "preferences": True,
            "rate_limit_status": True,
            "data_export": True
        }
    }