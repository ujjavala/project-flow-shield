"""
IAM Management API
Comprehensive role and permission management endpoints with scope support
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload

from app.database.connection import get_db
from app.models.user import User
from app.models.iam import (
    IAMRole, IAMPermission, IAMScope, IAMResource,
    IAMRoleRequest, IAMOperationEffect, IAMSession, IAMAuditLog,
    user_roles_table, role_permissions_table
)
from app.utils.iam_decorators import (
    get_iam_context, IAMContext, require_permission,
    require_any_permission, require_admin
)
from app.services.iam_service import get_iam_service
from app.config import settings
from app.temporal.client import get_temporal_client
from app.temporal.privileged_access_types import ApprovalDecision, PrivilegedAccessRequest
from app.temporal.workflows.privileged_access import PrivilegedAccessWorkflow

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/iam", tags=["IAM Management"])


def _internal_error(operation: str, exc: Exception) -> HTTPException:
    logger.error("IAM operation failed operation=%s exception_type=%s", operation, type(exc).__name__)
    return HTTPException(status_code=500, detail="IAM service operation failed")

# ===== REQUEST/RESPONSE MODELS =====

class CreateRoleRequest(BaseModel):
    name: str = Field(..., description="Unique role name")
    display_name: str = Field(..., description="Human-readable role name")
    description: Optional[str] = Field(None, description="Role description")
    scope: str = Field(default='global', description="Role scope")
    priority: int = Field(default=0, description="Role priority")
    is_system_role: bool = Field(default=False, description="Is system role")

class CreatePermissionRequest(BaseModel):
    name: str = Field(..., description="Unique permission name")
    display_name: str = Field(..., description="Human-readable permission name")
    description: Optional[str] = Field(None, description="Permission description")
    category: str = Field(..., description="Permission category")
    resource_type: Optional[str] = Field(None, description="Resource type")
    action: str = Field(..., description="Action type")
    risk_level: str = Field(default='low', description="Risk level")
    scope_types: Optional[List[str]] = Field(None, description="Applicable scope types")

class CreateScopeRequest(BaseModel):
    name: str = Field(..., description="Unique scope name")
    display_name: str = Field(..., description="Human-readable scope name")
    description: Optional[str] = Field(None, description="Scope description")
    scope_type: str = Field(..., description="Scope type")
    parent_scope_id: Optional[str] = Field(None, description="Parent scope ID")
    is_inheritable: bool = Field(default=True, description="Can inherit permissions")

class AssignRoleRequest(BaseModel):
    role_id: str = Field(..., description="Role ID")
    scope_id: Optional[str] = Field(None, description="Scope ID")
    expires_at: Optional[str] = Field(None, description="Expiration date (ISO format)")
    justification: Optional[str] = Field(None, description="Assignment justification")


class PrivilegedAccessCreateRequest(BaseModel):
    role_id: str
    scope_id: Optional[str] = None
    duration_seconds: int = Field(ge=60, le=2_592_000)
    justification: str = Field(min_length=10, max_length=2000)


class PrivilegedAccessDecisionRequest(BaseModel):
    approved: bool
    reason: Optional[str] = Field(default=None, max_length=1000)

class UpdateRolePermissionsRequest(BaseModel):
    role_id: str = Field(..., description="Role ID")
    permission_ids: List[str] = Field(..., description="List of permission IDs")
    action: str = Field(..., description="add or remove")

class RoleResponse(BaseModel):
    id: str
    name: str
    display_name: str
    description: Optional[str]
    scope: str
    priority: int
    is_active: bool
    is_system_role: bool
    created_at: str
    permissions_count: int

class PermissionResponse(BaseModel):
    id: str
    name: str
    display_name: str
    description: Optional[str]
    category: str
    resource_type: Optional[str]
    action: str
    risk_level: str
    is_active: bool
    created_at: str

class ScopeResponse(BaseModel):
    id: str
    name: str
    display_name: str
    description: Optional[str]
    scope_type: str
    parent_scope_id: Optional[str]
    hierarchy_path: Optional[str]
    level: int
    is_active: bool
    created_at: str

class UserRoleResponse(BaseModel):
    user_id: str
    email: str
    roles: List[Dict[str, Any]]
    scopes: List[Dict[str, Any]]
    permissions_summary: Dict[str, Any]


async def _require_scope_access(iam_context: IAMContext, scope_id: Optional[str]) -> None:
    """Reject cross-scope IAM mutations unless the actor is a superuser."""
    if iam_context.user.is_superuser:
        return
    if not scope_id or scope_id == "global":
        raise HTTPException(status_code=403, detail="Global IAM changes require a superuser")
    accessible = await iam_context.iam_service.get_user_accessible_scopes(iam_context.user.id)
    if scope_id not in {scope["id"] for scope in accessible}:
        raise HTTPException(status_code=403, detail="IAM change is outside the actor's accessible scopes")


def _require_role_grant_access(iam_context: IAMContext, role: IAMRole) -> None:
    """Prevent privilege escalation through grants at or above the actor's level."""
    if iam_context.user.is_superuser:
        return
    actor_roles = [actor_role for actor_role in getattr(iam_context.user, "iam_roles", []) if actor_role.is_active]
    actor_max_priority = max((actor_role.priority for actor_role in actor_roles), default=-1)
    if role.priority >= actor_max_priority:
        raise HTTPException(status_code=403, detail="Cannot grant a role at or above your privilege level")

# ===== ROLE MANAGEMENT ENDPOINTS =====

@router.get("/roles", response_model=List[RoleResponse])
@require_permission("iam.roles.read")
async def list_roles(
    iam_context: IAMContext = Depends(get_iam_context),
    skip: int = Query(0, description="Number of roles to skip"),
    limit: int = Query(100, description="Number of roles to return"),
    scope: Optional[str] = Query(None, description="Filter by scope"),
    active_only: bool = Query(True, description="Return only active roles")
):
    """List all roles with optional filtering"""

    try:
        db = iam_context.db

        # Build query
        query = select(IAMRole).options(
            selectinload(IAMRole.permissions)
        ).offset(skip).limit(limit)

        if active_only:
            query = query.where(IAMRole.is_active == True)

        if scope:
            query = query.where(IAMRole.scope == scope)

        result = await db.execute(query)
        roles = result.scalars().all()

        # Convert to response format
        role_responses = []
        for role in roles:
            role_responses.append(RoleResponse(
                id=role.id,
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                scope=role.scope,
                priority=role.priority,
                is_active=role.is_active,
                is_system_role=role.is_system_role,
                created_at=role.created_at.isoformat() if role.created_at else '',
                permissions_count=len(role.permissions) if role.permissions else 0
            ))

        return role_responses

    except Exception as exc:
        raise _internal_error("list_roles", exc) from exc

@router.post("/roles", response_model=RoleResponse)
@require_permission("iam.roles.create")
async def create_role(
    request: CreateRoleRequest,
    iam_context: IAMContext = Depends(get_iam_context)
):
    """Create a new role"""

    try:
        db = iam_context.db

        await _require_scope_access(iam_context, request.scope)
        if request.is_system_role and not iam_context.user.is_superuser:
            raise HTTPException(status_code=403, detail="Only a superuser can create system roles")

        # Check if role name already exists
        existing_query = select(IAMRole).where(IAMRole.name == request.name)
        existing_result = await db.execute(existing_query)
        if existing_result.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail=f"Role with name '{request.name}' already exists"
            )

        # Create the role
        new_role = IAMRole(
            name=request.name,
            display_name=request.display_name,
            description=request.description,
            scope=request.scope,
            priority=request.priority,
            is_system_role=request.is_system_role,
            created_by=iam_context.user.id
        )

        db.add(new_role)
        await db.commit()
        await db.refresh(new_role)

        # Log the creation
        audit_log = IAMAuditLog(
            actor_id=iam_context.user.id,
            action='role_created',
            target_type='role',
            target_id=new_role.id,
            result='success',
            details={
                'role_name': request.name,
                'scope': request.scope,
                'priority': request.priority
            },
            ip_address=iam_context.ip_address,
            user_agent=iam_context.user_agent
        )

        db.add(audit_log)
        await db.commit()

        return RoleResponse(
            id=new_role.id,
            name=new_role.name,
            display_name=new_role.display_name,
            description=new_role.description,
            scope=new_role.scope,
            priority=new_role.priority,
            is_active=new_role.is_active,
            is_system_role=new_role.is_system_role,
            created_at=new_role.created_at.isoformat(),
            permissions_count=0
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("create_role", exc) from exc

@router.get("/roles/{role_id}", response_model=Dict[str, Any])
@require_permission("iam.roles.read")
async def get_role_details(
    role_id: str,
    iam_context: IAMContext = Depends(get_iam_context)
):
    """Get detailed information about a specific role"""

    try:
        db = iam_context.db

        # Get role with permissions and users
        role_query = select(IAMRole).options(
            selectinload(IAMRole.permissions),
            selectinload(IAMRole.users)
        ).where(IAMRole.id == role_id)

        result = await db.execute(role_query)
        role = result.scalar_one_or_none()

        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Format permissions
        permissions = []
        if role.permissions:
            for permission in role.permissions:
                permissions.append({
                    'id': permission.id,
                    'name': permission.name,
                    'display_name': permission.display_name,
                    'category': permission.category,
                    'action': permission.action,
                    'risk_level': permission.risk_level,
                    'is_active': permission.is_active
                })

        # Format users
        users = []
        if role.users:
            for user in role.users:
                users.append({
                    'id': user.id,
                    'email': user.email,
                    'is_active': user.is_active
                })

        return {
            'role': {
                'id': role.id,
                'name': role.name,
                'display_name': role.display_name,
                'description': role.description,
                'scope': role.scope,
                'priority': role.priority,
                'is_active': role.is_active,
                'is_system_role': role.is_system_role,
                'created_at': role.created_at.isoformat() if role.created_at else '',
                'updated_at': role.updated_at.isoformat() if role.updated_at else ''
            },
            'permissions': permissions,
            'users': users,
            'stats': {
                'permission_count': len(permissions),
                'user_count': len(users)
            }
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("get_role_details", exc) from exc

# ===== PERMISSION MANAGEMENT ENDPOINTS =====

@router.get("/permissions", response_model=List[PermissionResponse])
@require_permission("iam.permissions.read")
async def list_permissions(
    iam_context: IAMContext = Depends(get_iam_context),
    skip: int = Query(0, description="Number of permissions to skip"),
    limit: int = Query(100, description="Number of permissions to return"),
    category: Optional[str] = Query(None, description="Filter by category"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    active_only: bool = Query(True, description="Return only active permissions")
):
    """List all permissions with optional filtering"""

    try:
        db = iam_context.db

        # Build query
        query = select(IAMPermission).offset(skip).limit(limit)

        if active_only:
            query = query.where(IAMPermission.is_active == True)

        if category:
            query = query.where(IAMPermission.category == category)

        if risk_level:
            query = query.where(IAMPermission.risk_level == risk_level)

        result = await db.execute(query)
        permissions = result.scalars().all()

        # Convert to response format
        permission_responses = []
        for permission in permissions:
            permission_responses.append(PermissionResponse(
                id=permission.id,
                name=permission.name,
                display_name=permission.display_name,
                description=permission.description,
                category=permission.category,
                resource_type=permission.resource_type,
                action=permission.action,
                risk_level=permission.risk_level,
                is_active=permission.is_active,
                created_at=permission.created_at.isoformat() if permission.created_at else ''
            ))

        return permission_responses

    except Exception as exc:
        raise _internal_error("list_permissions", exc) from exc

@router.post("/permissions", response_model=PermissionResponse)
@require_permission("iam.permissions.create")
async def create_permission(
    request: CreatePermissionRequest,
    iam_context: IAMContext = Depends(get_iam_context)
):
    """Create a new permission"""

    try:
        db = iam_context.db

        if not iam_context.user.is_superuser:
            raise HTTPException(status_code=403, detail="Only a superuser can define permissions")

        # Check if permission name already exists
        existing_query = select(IAMPermission).where(IAMPermission.name == request.name)
        existing_result = await db.execute(existing_query)
        if existing_result.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail=f"Permission with name '{request.name}' already exists"
            )

        # Create the permission
        new_permission = IAMPermission(
            name=request.name,
            display_name=request.display_name,
            description=request.description,
            category=request.category,
            resource_type=request.resource_type,
            action=request.action,
            risk_level=request.risk_level,
            scope_types=request.scope_types,
            created_by=iam_context.user.id
        )

        db.add(new_permission)
        await db.commit()
        await db.refresh(new_permission)

        # Log the creation
        audit_log = IAMAuditLog(
            actor_id=iam_context.user.id,
            action='permission_created',
            target_type='permission',
            target_id=new_permission.id,
            result='success',
            details={
                'permission_name': request.name,
                'category': request.category,
                'action': request.action,
                'risk_level': request.risk_level
            },
            ip_address=iam_context.ip_address,
            user_agent=iam_context.user_agent
        )

        db.add(audit_log)
        await db.commit()

        return PermissionResponse(
            id=new_permission.id,
            name=new_permission.name,
            display_name=new_permission.display_name,
            description=new_permission.description,
            category=new_permission.category,
            resource_type=new_permission.resource_type,
            action=new_permission.action,
            risk_level=new_permission.risk_level,
            is_active=new_permission.is_active,
            created_at=new_permission.created_at.isoformat()
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("create_permission", exc) from exc

# ===== USER ROLE MANAGEMENT ENDPOINTS =====

@router.post("/users/{user_id}/privileged-access", status_code=status.HTTP_202_ACCEPTED)
@require_permission("iam.users.assign_roles")
async def request_privileged_access(
    user_id: str,
    request: PrivilegedAccessCreateRequest,
    iam_context: IAMContext = Depends(get_iam_context),
):
    """Start an approval-gated, automatically expiring role assignment."""
    await _require_scope_access(iam_context, request.scope_id)
    role = await iam_context.db.get(IAMRole, request.role_id)
    target = await iam_context.db.get(User, user_id)
    if role is None or not role.is_active or target is None or not target.is_active:
        raise HTTPException(status_code=404, detail="Active user or role not found")
    _require_role_grant_access(iam_context, role)

    request_id = str(uuid.uuid4())
    workflow_id = f"privileged-access/{request_id}"
    record = IAMRoleRequest(
        id=request_id,
        requester_id=iam_context.user.id,
        target_user_id=user_id,
        role_id=request.role_id,
        scope_id=request.scope_id,
        workflow_id=workflow_id,
        request_type="assign",
        justification=request.justification,
        duration_seconds=request.duration_seconds,
        status="pending",
    )
    iam_context.db.add(record)
    await iam_context.db.commit()

    temporal_request = PrivilegedAccessRequest(
        request_id=request_id,
        requester_id=iam_context.user.id,
        target_user_id=user_id,
        role_id=request.role_id,
        scope_id=request.scope_id,
        duration_seconds=request.duration_seconds,
        approval_timeout_seconds=settings.PRIVILEGED_ACCESS_APPROVAL_TIMEOUT_SECONDS,
    )
    try:
        client = await get_temporal_client()
        await client.start_workflow(
            PrivilegedAccessWorkflow.run,
            temporal_request,
            id=workflow_id,
            task_queue=settings.TEMPORAL_IDENTITY_OPS_TASK_QUEUE,
        )
    except Exception:
        record.status = "dispatch_failed"
        await iam_context.db.commit()
        logger.exception("Failed to dispatch privileged access request %s", request_id)
        raise HTTPException(status_code=503, detail="Identity operations service unavailable")

    return {"request_id": request_id, "workflow_id": workflow_id, "status": "pending"}


@router.post("/privileged-access/{request_id}/decision", status_code=status.HTTP_202_ACCEPTED)
@require_permission("iam.users.assign_roles")
async def decide_privileged_access(
    request_id: str,
    decision: PrivilegedAccessDecisionRequest,
    iam_context: IAMContext = Depends(get_iam_context),
):
    """Signal a human approval decision; self-approval is prohibited."""
    record = await iam_context.db.get(IAMRoleRequest, request_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Privileged access request not found")
    if record.status != "pending":
        raise HTTPException(status_code=409, detail="Request is no longer pending")
    if record.requester_id == iam_context.user.id:
        raise HTTPException(status_code=403, detail="Requesters cannot approve their own access")
    await _require_scope_access(iam_context, record.scope_id)
    role = await iam_context.db.get(IAMRole, record.role_id)
    if role is None or not role.is_active:
        raise HTTPException(status_code=404, detail="Active role not found")
    _require_role_grant_access(iam_context, role)
    if not decision.approved and not decision.reason:
        raise HTTPException(status_code=422, detail="A denial reason is required")

    record.denial_reason = None if decision.approved else decision.reason
    await iam_context.db.commit()

    client = await get_temporal_client()
    handle = client.get_workflow_handle(record.workflow_id)
    await handle.signal(
        PrivilegedAccessWorkflow.decide,
        ApprovalDecision(
            approved=decision.approved,
            approver_id=iam_context.user.id,
        ),
    )
    return {"request_id": request_id, "decision": "approved" if decision.approved else "denied"}


@router.get("/privileged-access/{request_id}")
@require_permission("user.read")
async def get_privileged_access_request(
    request_id: str,
    iam_context: IAMContext = Depends(get_iam_context),
):
    """Return durable request state and immutable effect references."""
    record = await iam_context.db.get(IAMRoleRequest, request_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Privileged access request not found")
    await _require_scope_access(iam_context, record.scope_id)
    effects = await iam_context.db.execute(
        select(IAMOperationEffect).where(IAMOperationEffect.request_id == request_id)
    )
    return {
        "request_id": record.id,
        "workflow_id": record.workflow_id,
        "requester_id": record.requester_id,
        "target_user_id": record.target_user_id,
        "role_id": record.role_id,
        "scope_id": record.scope_id,
        "status": record.status,
        "approved_by": record.approved_by,
        "effects": [
            {
                "effect_id": effect.effect_id,
                "type": effect.effect_type,
                "details": effect.details,
                "created_at": effect.created_at,
            }
            for effect in effects.scalars().all()
        ],
    }

@router.post("/users/{user_id}/roles")
@require_permission("iam.users.assign_roles")
async def assign_role_to_user(
    user_id: str,
    request: AssignRoleRequest,
    iam_context: IAMContext = Depends(get_iam_context),
):
    """Assign a role after server-side scope and privilege validation."""

    try:
        iam_service = get_iam_service(iam_context.db)

        await _require_scope_access(iam_context, request.scope_id)
        role = await iam_context.db.get(IAMRole, request.role_id)
        if role is None or not role.is_active:
            raise HTTPException(status_code=404, detail="Role not found")
        _require_role_grant_access(iam_context, role)

        expires_at = None
        if request.expires_at:
            expires_at = datetime.fromisoformat(request.expires_at)

        result = await iam_service.assign_role_to_user(
            user_id=user_id,
            role_id=request.role_id,
            scope_id=request.scope_id,
            granted_by=iam_context.user.id,
            expires_at=expires_at,
            use_temporal=False,
        )

        return {
            'message': 'Role assigned',
            'result': result,
            'user_id': user_id,
            'role_id': request.role_id,
            'scope_id': request.scope_id,
            'assigned_by': iam_context.user.id,
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("assign_role_to_user", exc) from exc

@router.get("/users/{user_id}/roles", response_model=UserRoleResponse)
@require_any_permission(["iam.users.read", "iam.users.read_own"])
async def get_user_roles(
    user_id: str,
    iam_context: IAMContext = Depends(get_iam_context)
):
    """Get all roles and permissions for a specific user"""

    try:
        db = iam_context.db

        # Check if user can access this information
        if (user_id != iam_context.user.id and
            'iam.users.read' not in iam_context.user.get_effective_permissions()):
            raise HTTPException(
                status_code=403,
                detail="Can only view your own roles or need admin permission"
            )

        # Get user with roles, scopes, and permissions
        user_query = select(User).options(
            selectinload(User.iam_roles).selectinload(IAMRole.permissions),
            selectinload(User.scopes)
        ).where(User.id == user_id)

        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Format roles
        roles = []
        all_permissions = set()

        if hasattr(user, 'iam_roles'):
            for role in user.iam_roles:
                role_permissions = []
                if role.permissions:
                    for permission in role.permissions:
                        if permission.is_active:
                            role_permissions.append(permission.name)
                            all_permissions.add(permission.name)

                roles.append({
                    'id': role.id,
                    'name': role.name,
                    'display_name': role.display_name,
                    'scope': role.scope,
                    'priority': role.priority,
                    'is_active': role.is_active,
                    'permissions': role_permissions
                })

        # Format scopes
        scopes = []
        if hasattr(user, 'scopes'):
            for scope in user.scopes:
                scopes.append({
                    'id': scope.id,
                    'name': scope.name,
                    'display_name': scope.display_name,
                    'scope_type': scope.scope_type,
                    'level': scope.level
                })

        # Create permissions summary
        permissions_by_category = {}
        for role in user.iam_roles if hasattr(user, 'iam_roles') else []:
            for permission in role.permissions if role.permissions else []:
                if permission.is_active:
                    category = permission.category
                    if category not in permissions_by_category:
                        permissions_by_category[category] = []
                    permissions_by_category[category].append(permission.name)

        permissions_summary = {
            'total_permissions': len(all_permissions),
            'permissions_by_category': permissions_by_category,
            'high_risk_permissions': len([
                p for role in (user.iam_roles if hasattr(user, 'iam_roles') else [])
                for p in role.permissions if role.permissions and p.risk_level == 'high'
            ])
        }

        return UserRoleResponse(
            user_id=user.id,
            email=user.email,
            roles=roles,
            scopes=scopes,
            permissions_summary=permissions_summary
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("get_user_roles", exc) from exc

# ===== PERMISSION CHECK ENDPOINTS =====

@router.post("/check-permission")
@require_any_permission(["iam.permissions.check", "iam.permissions.check_own"])
async def check_user_permission(
    user_id: str = Query(..., description="User ID to check"),
    permission_name: str = Query(..., description="Permission to check"),
    resource_type: Optional[str] = Query(None, description="Resource type"),
    resource_id: Optional[str] = Query(None, description="Resource ID"),
    scope_id: Optional[str] = Query(None, description="Scope ID"),
    iam_context: IAMContext = Depends(get_iam_context),
):
    """Check if a user has a specific permission"""

    try:
        # Check if user can check permissions for others
        if user_id != iam_context.user.id:
            checker_result = await iam_context.iam_service.evaluate_user_permission(
                user_id=iam_context.user.id,
                permission_name="iam.permissions.check",
                use_temporal=False,
            )
            if not checker_result.get("access_granted"):
                raise HTTPException(
                    status_code=403,
                    detail="Can only check your own permissions or need admin permission",
                )

        if scope_id:
            await _require_scope_access(iam_context, scope_id)

        # Use IAM service to check permission
        iam_service = get_iam_service(iam_context.db)

        result = await iam_service.evaluate_user_permission(
            user_id=user_id,
            permission_name=permission_name,
            resource_type=resource_type,
            resource_id=resource_id,
            scope_id=scope_id,
            context={
                'checker_user_id': iam_context.user.id,
                'ip_address': iam_context.ip_address,
                'user_agent': iam_context.user_agent
            },
            use_temporal=False,
        )

        return {
            'user_id': user_id,
            'permission_name': permission_name,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'scope_id': scope_id,
            'result': result,
            'checked_by': iam_context.user.id,
            'checked_at': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise _internal_error("check_user_permission", exc) from exc

# ===== AUDIT AND REPORTING ENDPOINTS =====

@router.get("/audit/roles")
@require_permission("iam.audit.read")
async def get_role_audit_log(
    iam_context: IAMContext = Depends(get_iam_context),
    role_id: Optional[str] = Query(None, description="Filter by role ID"),
    action: Optional[str] = Query(None, description="Filter by action"),
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    limit: int = Query(100, description="Number of records to return")
):
    """Get audit log for role-related activities"""

    try:
        db = iam_context.db

        # Build query
        query = select(IAMAuditLog).where(
            IAMAuditLog.target_type.in_(['role', 'user_role', 'role_permission'])
        ).order_by(IAMAuditLog.timestamp.desc()).limit(limit)

        if role_id:
            query = query.where(IAMAuditLog.target_id.contains(role_id))

        if action:
            query = query.where(IAMAuditLog.action == action)

        if start_date:
            start_dt = datetime.fromisoformat(start_date)
            query = query.where(IAMAuditLog.timestamp >= start_dt)

        if end_date:
            end_dt = datetime.fromisoformat(end_date)
            query = query.where(IAMAuditLog.timestamp <= end_dt)

        result = await db.execute(query)
        audit_logs = result.scalars().all()

        # Format response
        formatted_logs = []
        for log in audit_logs:
            formatted_logs.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'actor_id': log.actor_id,
                'action': log.action,
                'target_type': log.target_type,
                'target_id': log.target_id,
                'result': log.result,
                'details': log.details,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent
            })

        return {
            'audit_logs': formatted_logs,
            'total_records': len(formatted_logs),
            'filters': {
                'role_id': role_id,
                'action': action,
                'start_date': start_date,
                'end_date': end_date
            },
            'generated_at': datetime.now().isoformat()
        }

    except Exception as exc:
        raise _internal_error("get_role_audit_log", exc) from exc

# ===== HEALTH CHECK =====

@router.get("/health")
async def iam_health_check():
    """Health check for IAM management system"""

    return {
        'status': 'healthy',
        'service': 'iam_management',
        'timestamp': datetime.now().isoformat(),
        'features': {
            'role_management': True,
            'permission_management': True,
            'scope_management': True,
            'temporal_workflows': True,
            'audit_logging': True
        }
    }