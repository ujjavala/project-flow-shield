"""
Admin Authentication Utilities
Provides secure admin authentication and authorization functions
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.models.user import User
from app.utils.security import verify_token

logger = logging.getLogger(__name__)
admin_security = HTTPBearer()

class AdminAuthenticationError(Exception):
    """Custom exception for admin authentication errors"""
    pass

class InsufficientPermissionsError(Exception):
    """Custom exception for insufficient admin permissions"""
    pass

async def get_admin_user(
    credentials: HTTPAuthorizationCredentials = Depends(admin_security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated admin user
    Raises HTTPException if not authenticated or not an admin
    """

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        # Verify JWT token
        payload = verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired admin token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin token payload",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Get user from database
        user = await db.get(User, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin user not found",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin account is inactive",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Check admin role
        if not _is_admin_user(user):
            logger.warning(f"Non-admin user {user.email} attempted to access admin functionality")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required. Access denied."
            )

        # Log admin access
        logger.info(f"Admin user {user.email} (role: {user.role}) authenticated successfully")

        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )

async def get_super_admin_user(
    credentials: HTTPAuthorizationCredentials = Depends(admin_security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated super admin user
    Raises HTTPException if not authenticated or not a super admin
    """

    # First verify they're an admin
    admin_user = await get_admin_user(credentials, db)

    # Check for super admin privileges
    if not admin_user.is_superuser:
        logger.warning(f"Admin user {admin_user.email} attempted to access super admin functionality")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin privileges required. Access denied."
        )

    logger.info(f"Super admin user {admin_user.email} authenticated successfully")
    return admin_user

def require_admin_role(required_role: str = "admin"):
    """
    Decorator factory for requiring specific admin roles
    Usage: @require_admin_role("admin") or @require_admin_role("moderator")
    """

    async def verify_admin_role(
        credentials: HTTPAuthorizationCredentials = Depends(admin_security),
        db: AsyncSession = Depends(get_db)
    ) -> User:

        # Get authenticated admin user
        admin_user = await get_admin_user(credentials, db)

        # Check specific role requirement
        if not _has_required_role(admin_user, required_role):
            logger.warning(f"Admin user {admin_user.email} (role: {admin_user.role}) "
                         f"attempted to access {required_role}-only functionality")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required. Current role: '{admin_user.role}'"
            )

        return admin_user

    return verify_admin_role

def _is_admin_user(user: User) -> bool:
    """Check if user has admin privileges"""
    return (
        user.role in ['admin', 'moderator'] or
        user.is_superuser
    )

def _has_required_role(user: User, required_role: str) -> bool:
    """Check if user has the required role or higher"""

    # Role hierarchy: user < moderator < admin < superuser
    role_hierarchy = {
        'user': 0,
        'moderator': 1,
        'admin': 2,
        'superuser': 3
    }

    # Super admin bypass
    if user.is_superuser:
        return True

    user_role_level = role_hierarchy.get(user.role, 0)
    required_role_level = role_hierarchy.get(required_role, 0)

    return user_role_level >= required_role_level

async def create_admin_session_log(admin_user: User, action: str, details: Optional[dict] = None):
    """Log admin actions for audit purposes"""

    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'admin_user_id': admin_user.id,
            'admin_email': admin_user.email,
            'admin_role': admin_user.role,
            'action': action,
            'details': details or {},
            'session_type': 'admin'
        }

        # TODO: Store in proper audit log table
        # For now, just log to application logs
        logger.info(f"ADMIN_AUDIT: {log_entry}")

    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")

def validate_admin_api_key(api_key: str) -> bool:
    """
    Validate admin API key for programmatic access
    TODO: Implement proper API key management
    """

    # For demonstration - in production, use proper API key management
    ADMIN_API_KEYS = {
        'admin_key_001': {'role': 'admin', 'name': 'System Admin'},
        'super_key_001': {'role': 'superuser', 'name': 'Super Admin'}
    }

    return api_key in ADMIN_API_KEYS

class AdminPermissionChecker:
    """Utility class for checking admin permissions"""

    @staticmethod
    def can_manage_users(admin_user: User) -> bool:
        """Check if admin can manage users"""
        return admin_user.role in ['admin'] or admin_user.is_superuser

    @staticmethod
    def can_view_system_logs(admin_user: User) -> bool:
        """Check if admin can view system logs"""
        return admin_user.role in ['admin', 'moderator'] or admin_user.is_superuser

    @staticmethod
    def can_modify_security_settings(admin_user: User) -> bool:
        """Check if admin can modify security settings"""
        return admin_user.role in ['admin'] or admin_user.is_superuser

    @staticmethod
    def can_access_rate_limiting(admin_user: User) -> bool:
        """Check if admin can access rate limiting controls"""
        return admin_user.role in ['admin'] or admin_user.is_superuser

    @staticmethod
    def can_manage_workflows(admin_user: User) -> bool:
        """Check if admin can manage Temporal workflows"""
        return admin_user.role in ['admin'] or admin_user.is_superuser

    @staticmethod
    def can_export_data(admin_user: User) -> bool:
        """Check if admin can export sensitive data"""
        return admin_user.is_superuser  # Only super admins

# Admin authentication middleware for direct use
async def require_admin_auth():
    """Simple admin authentication check"""

    def admin_required(
        credentials: HTTPAuthorizationCredentials = Depends(admin_security),
        db: AsyncSession = Depends(get_db)
    ):
        return get_admin_user(credentials, db)

    return admin_required

# Rate limiting bypass for admin users
async def is_admin_request(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(admin_security),
    db: AsyncSession = Depends(get_db)
) -> bool:
    """Check if request is from an admin user (for rate limiting bypass)"""

    if not credentials:
        return False

    try:
        admin_user = await get_admin_user(credentials, db)
        return admin_user is not None
    except Exception:
        return False

# Security headers for admin endpoints
ADMIN_SECURITY_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Admin-Session": "protected"
}