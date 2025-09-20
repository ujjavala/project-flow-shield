"""
IAM Decorators and Middleware
Role-based access control decorators with scope and permission support
"""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from functools import wraps
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.models.user import User
from app.utils.security import verify_token
from app.services.iam_service import get_iam_service

logger = logging.getLogger(__name__)
security = HTTPBearer()

# ===== AUTHENTICATION DECORATORS =====

class IAMContext:
    """Context object for IAM operations"""

    def __init__(
        self,
        user: User,
        db: AsyncSession,
        request: Optional[Request] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        self.user = user
        self.db = db
        self.request = request
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.iam_service = get_iam_service(db)

async def get_iam_context(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> IAMContext:
    """Get authenticated user context for IAM operations"""

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        # Verify JWT token
        payload = verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Get user from database
        user = await db.get(User, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Extract request context
        ip_address = None
        user_agent = None

        return IAMContext(
            user=user,
            db=db,
            request=None,
            ip_address=ip_address,
            user_agent=user_agent
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"IAM context creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )

# ===== PERMISSION DECORATORS =====

def require_permission(
    permission_name: str,
    resource_type: Optional[str] = None,
    resource_id_param: Optional[str] = None,
    scope_id_param: Optional[str] = None,
    use_temporal: bool = True
):
    """
    Decorator to require specific permission for endpoint access

    Args:
        permission_name: Name of the required permission
        resource_type: Type of resource being accessed
        resource_id_param: Parameter name containing resource ID
        scope_id_param: Parameter name containing scope ID
        use_temporal: Whether to use Temporal workflows for evaluation
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context from dependencies
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                # Try to get context from kwargs
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found. Ensure endpoint uses IAMContext dependency."
                )

            # Extract resource and scope IDs from parameters
            resource_id = None
            if resource_id_param and resource_id_param in kwargs:
                resource_id = kwargs[resource_id_param]

            scope_id = None
            if scope_id_param and scope_id_param in kwargs:
                scope_id = kwargs[scope_id_param]

            # Evaluate permission
            permission_result = await iam_context.iam_service.evaluate_user_permission(
                user_id=iam_context.user.id,
                permission_name=permission_name,
                resource_type=resource_type,
                resource_id=resource_id,
                scope_id=scope_id,
                context={
                    'ip_address': iam_context.ip_address,
                    'user_agent': iam_context.user_agent,
                    'endpoint': func.__name__
                },
                use_temporal=use_temporal
            )

            if not permission_result.get('access_granted', False):
                logger.warning(
                    f"Permission denied for user {iam_context.user.id}: "
                    f"permission={permission_name}, reason={permission_result.get('reason', 'unknown')}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission_result.get('reason', 'insufficient_permissions')}"
                )

            # Add permission result to kwargs for endpoint use if needed
            kwargs['_permission_result'] = permission_result

            return await func(*args, **kwargs)

        return wrapper
    return decorator

def require_any_permission(
    permission_names: List[str],
    resource_type: Optional[str] = None,
    resource_id_param: Optional[str] = None,
    scope_id_param: Optional[str] = None,
    use_temporal: bool = True
):
    """
    Decorator to require ANY of the specified permissions for endpoint access
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found"
                )

            # Extract resource and scope IDs
            resource_id = kwargs.get(resource_id_param) if resource_id_param else None
            scope_id = kwargs.get(scope_id_param) if scope_id_param else None

            # Check each permission until one grants access
            granted_permissions = []
            for permission_name in permission_names:
                permission_result = await iam_context.iam_service.evaluate_user_permission(
                    user_id=iam_context.user.id,
                    permission_name=permission_name,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    scope_id=scope_id,
                    context={
                        'ip_address': iam_context.ip_address,
                        'user_agent': iam_context.user_agent,
                        'endpoint': func.__name__
                    },
                    use_temporal=use_temporal
                )

                if permission_result.get('access_granted', False):
                    granted_permissions.append(permission_name)

            if not granted_permissions:
                logger.warning(
                    f"Permission denied for user {iam_context.user.id}: "
                    f"permissions={permission_names}, none granted"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: requires any of {permission_names}"
                )

            kwargs['_granted_permissions'] = granted_permissions
            return await func(*args, **kwargs)

        return wrapper
    return decorator

def require_all_permissions(
    permission_names: List[str],
    resource_type: Optional[str] = None,
    resource_id_param: Optional[str] = None,
    scope_id_param: Optional[str] = None,
    use_temporal: bool = True
):
    """
    Decorator to require ALL of the specified permissions for endpoint access
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found"
                )

            # Extract resource and scope IDs
            resource_id = kwargs.get(resource_id_param) if resource_id_param else None
            scope_id = kwargs.get(scope_id_param) if scope_id_param else None

            # Check all permissions
            denied_permissions = []
            granted_permissions = []

            for permission_name in permission_names:
                permission_result = await iam_context.iam_service.evaluate_user_permission(
                    user_id=iam_context.user.id,
                    permission_name=permission_name,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    scope_id=scope_id,
                    context={
                        'ip_address': iam_context.ip_address,
                        'user_agent': iam_context.user_agent,
                        'endpoint': func.__name__
                    },
                    use_temporal=use_temporal
                )

                if permission_result.get('access_granted', False):
                    granted_permissions.append(permission_name)
                else:
                    denied_permissions.append(permission_name)

            if denied_permissions:
                logger.warning(
                    f"Permission denied for user {iam_context.user.id}: "
                    f"missing permissions={denied_permissions}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: missing required permissions {denied_permissions}"
                )

            kwargs['_granted_permissions'] = granted_permissions
            return await func(*args, **kwargs)

        return wrapper
    return decorator

# ===== ROLE DECORATORS =====

def require_role(
    role_name: str,
    scope_id_param: Optional[str] = None
):
    """
    Decorator to require specific role for endpoint access
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found"
                )

            # Check if user has the required role
            user_roles = getattr(iam_context.user, 'iam_roles', [])
            has_role = any(
                role.name == role_name and role.is_active
                for role in user_roles
            )

            if not has_role:
                logger.warning(
                    f"Role denied for user {iam_context.user.id}: "
                    f"required_role={role_name}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role required: {role_name}"
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator

def require_any_role(role_names: List[str]):
    """
    Decorator to require ANY of the specified roles for endpoint access
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found"
                )

            # Check if user has any of the required roles
            user_roles = getattr(iam_context.user, 'iam_roles', [])
            user_role_names = {role.name for role in user_roles if role.is_active}

            has_any_role = bool(set(role_names) & user_role_names)

            if not has_any_role:
                logger.warning(
                    f"Role denied for user {iam_context.user.id}: "
                    f"required_roles={role_names}, user_roles={list(user_role_names)}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"One of these roles required: {role_names}"
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator

# ===== SCOPE DECORATORS =====

def require_scope_access(
    scope_id_param: str,
    action: Optional[str] = None
):
    """
    Decorator to require access to specific scope
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract IAM context
            iam_context = None
            for arg in args:
                if isinstance(arg, IAMContext):
                    iam_context = arg
                    break

            if not iam_context:
                for key, value in kwargs.items():
                    if isinstance(value, IAMContext):
                        iam_context = value
                        break

            if not iam_context:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="IAM context not found"
                )

            # Get scope ID from parameters
            scope_id = kwargs.get(scope_id_param)
            if not scope_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Scope ID parameter '{scope_id_param}' is required"
                )

            # Check scope access
            accessible_scopes = await iam_context.iam_service.get_user_accessible_scopes(
                user_id=iam_context.user.id,
                action=action
            )

            scope_ids = {scope['id'] for scope in accessible_scopes}

            if scope_id not in scope_ids:
                logger.warning(
                    f"Scope access denied for user {iam_context.user.id}: "
                    f"scope_id={scope_id}, accessible_scopes={list(scope_ids)}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied to scope: {scope_id}"
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator

# ===== CONVENIENCE DECORATORS =====

def require_admin():
    """Convenience decorator for admin access"""
    return require_any_role(['admin', 'super_admin'])

def require_user_or_admin():
    """Convenience decorator for user or admin access"""
    return require_any_role(['user', 'admin', 'super_admin', 'moderator'])

def require_system_admin():
    """Convenience decorator for system admin access"""
    return require_permission('system.admin')

# ===== UTILITY FUNCTIONS =====

def get_user_permissions_summary(iam_context: IAMContext) -> Dict[str, Any]:
    """Get a summary of user's permissions for debugging/display"""

    user_roles = getattr(iam_context.user, 'iam_roles', [])
    active_roles = [role for role in user_roles if role.is_active]

    permissions = set()
    for role in active_roles:
        for permission in role.permissions:
            if permission.is_active:
                permissions.add(permission.name)

    return {
        'user_id': iam_context.user.id,
        'email': iam_context.user.email,
        'active_roles': [role.name for role in active_roles],
        'permissions': list(permissions),
        'is_admin': any(role.name in ['admin', 'super_admin'] for role in active_roles)
    }

def create_permission_check_function(
    permission_name: str,
    resource_type: Optional[str] = None,
    use_temporal: bool = True
):
    """Create a function that checks a specific permission"""

    async def check_permission(
        iam_context: IAMContext,
        resource_id: Optional[str] = None,
        scope_id: Optional[str] = None
    ) -> bool:
        """Check if user has the specified permission"""

        result = await iam_context.iam_service.evaluate_user_permission(
            user_id=iam_context.user.id,
            permission_name=permission_name,
            resource_type=resource_type,
            resource_id=resource_id,
            scope_id=scope_id,
            use_temporal=use_temporal
        )

        return result.get('access_granted', False)

    return check_permission