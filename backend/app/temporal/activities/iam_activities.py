"""
IAM Temporal Activities
Implementation of IAM-related activities for Temporal workflows
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from temporalio import activity
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload

from app.database.connection import get_db_session
from app.models.user import User
from app.models.iam import (
    IAMRole, IAMPermission, IAMScope, IAMResource, IAMPolicy,
    IAMSession, IAMAuditLog, IAMAccessEvaluation, IAMContextualRole,
    IAMRoleRequest, user_roles_table, role_permissions_table,
    user_scopes_table, role_scope_table
)
from app.temporal.workflows.iam_workflows import (
    RoleAssignmentRequest, PermissionEvaluationRequest,
    AccessReviewRequest, RoleProvisioningRequest
)

logger = logging.getLogger(__name__)

# ===== ROLE ASSIGNMENT ACTIVITIES =====

@activity.defn
async def validate_role_assignment(request: RoleAssignmentRequest) -> Dict[str, Any]:
    """Validate a role assignment request"""

    try:
        async with get_db_session() as db:
            # Check if user exists
            user = await db.get(User, request.user_id)
            if not user:
                return {'valid': False, 'error': f'User {request.user_id} not found'}

            if not user.is_active:
                return {'valid': False, 'error': f'User {request.user_id} is inactive'}

            # Check if role exists
            role = await db.get(IAMRole, request.role_id)
            if not role:
                return {'valid': False, 'error': f'Role {request.role_id} not found'}

            if not role.is_active:
                return {'valid': False, 'error': f'Role {request.role_id} is inactive'}

            # Check scope if provided
            if request.scope_id:
                scope = await db.get(IAMScope, request.scope_id)
                if not scope:
                    return {'valid': False, 'error': f'Scope {request.scope_id} not found'}

                if not scope.is_active:
                    return {'valid': False, 'error': f'Scope {request.scope_id} is inactive'}

            # Check if assignment already exists
            existing_query = select(user_roles_table).where(
                and_(
                    user_roles_table.c.user_id == request.user_id,
                    user_roles_table.c.role_id == request.role_id,
                    user_roles_table.c.is_active == True
                )
            )

            result = await db.execute(existing_query)
            existing = result.first()

            if existing:
                return {'valid': False, 'error': 'Role assignment already exists'}

            return {'valid': True, 'message': 'Role assignment request is valid'}

    except Exception as e:
        logger.error(f"Role assignment validation failed: {e}")
        return {'valid': False, 'error': f'Validation error: {str(e)}'}

@activity.defn
async def check_approval_requirements(request: RoleAssignmentRequest) -> Dict[str, Any]:
    """Check if approval is required for role assignment"""

    try:
        async with get_db_session() as db:
            # Get role information
            role = await db.get(IAMRole, request.role_id)
            if not role:
                return {'required': False, 'error': 'Role not found'}

            # High-priority roles require approval
            requires_approval = role.priority > 5

            # System roles require approval
            if role.is_system_role:
                requires_approval = True

            # Check if role has high-risk permissions
            if role.permissions:
                for permission in role.permissions:
                    if permission.risk_level in ['high', 'critical']:
                        requires_approval = True
                        break

            return {
                'required': requires_approval,
                'reason': 'high_risk_role' if requires_approval else 'standard_role',
                'role_priority': role.priority,
                'is_system_role': role.is_system_role
            }

    except Exception as e:
        logger.error(f"Approval requirement check failed: {e}")
        return {'required': True, 'error': str(e)}  # Default to requiring approval on errors

@activity.defn
async def request_role_assignment_approval(data: Dict[str, Any]) -> Dict[str, Any]:
    """Request approval for role assignment"""

    # For now, simulate approval - in production this would integrate with approval system
    request = data['assignment_request']
    approval_info = data['approval_info']

    try:
        async with get_db_session() as db:
            # Create role request record
            role_request = IAMRoleRequest(
                requester_id=request.granted_by or request.user_id,
                target_user_id=request.user_id,
                role_id=request.role_id,
                request_type='assign',
                justification=request.justification,
                status='pending'
            )

            db.add(role_request)
            await db.commit()

            # For demo purposes, auto-approve after a short delay
            # In production, this would wait for actual approval
            await asyncio.sleep(1)  # Simulate approval process

            role_request.status = 'approved'
            role_request.approved_by = 'system'  # Would be actual approver
            role_request.approved_at = datetime.now()

            await db.commit()

            return {
                'approved': True,
                'status': 'approved',
                'approval_id': role_request.id,
                'approved_by': 'system',
                'approved_at': datetime.now().isoformat()
            }

    except Exception as e:
        logger.error(f"Role assignment approval failed: {e}")
        return {
            'approved': False,
            'status': 'error',
            'error': str(e)
        }

@activity.defn
async def execute_role_assignment(request: RoleAssignmentRequest) -> Dict[str, Any]:
    """Execute the actual role assignment"""

    try:
        async with get_db_session() as db:
            # Create the role assignment
            expires_at = None
            if request.expires_at:
                expires_at = datetime.fromisoformat(request.expires_at)

            assignment_data = {
                'user_id': request.user_id,
                'role_id': request.role_id,
                'granted_at': datetime.now(),
                'granted_by': request.granted_by,
                'expires_at': expires_at,
                'is_active': True
            }

            await db.execute(user_roles_table.insert().values(**assignment_data))

            # If scoped assignment, create scope mapping
            if request.scope_id:
                scope_data = {
                    'role_id': request.role_id,
                    'scope_id': request.scope_id,
                    'user_id': request.user_id,
                    'granted_at': datetime.now(),
                    'granted_by': request.granted_by,
                    'is_active': True
                }

                await db.execute(role_scope_table.insert().values(**scope_data))

            await db.commit()

            # Create audit log
            audit_log = IAMAuditLog(
                actor_id=request.granted_by,
                action='role_assigned',
                target_type='user_role',
                target_id=f"{request.user_id}:{request.role_id}",
                result='success',
                details={
                    'role_id': request.role_id,
                    'scope_id': request.scope_id,
                    'assignment_type': request.assignment_type,
                    'expires_at': request.expires_at
                }
            )

            db.add(audit_log)
            await db.commit()

            return {
                'success': True,
                'assignment_id': f"{request.user_id}:{request.role_id}",
                'user_id': request.user_id,
                'role_id': request.role_id,
                'scope_id': request.scope_id,
                'assigned_at': datetime.now().isoformat()
            }

    except Exception as e:
        logger.error(f"Role assignment execution failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'user_id': request.user_id,
            'role_id': request.role_id
        }

@activity.defn
async def invalidate_user_permission_cache(data: Dict[str, str]) -> Dict[str, Any]:
    """Invalidate user permission cache"""

    try:
        async with get_db_session() as db:
            user_id = data['user_id']

            # Mark all cached evaluations for this user as expired
            await db.execute(
                IAMAccessEvaluation.__table__.update()
                .where(IAMAccessEvaluation.user_id == user_id)
                .values(expires_at=datetime.now() - timedelta(seconds=1))
            )

            await db.commit()

            return {'success': True, 'user_id': user_id}

    except Exception as e:
        logger.error(f"Failed to invalidate permission cache: {e}")
        return {'success': False, 'error': str(e)}

# ===== PERMISSION EVALUATION ACTIVITIES =====

@activity.defn
async def check_permission_cache(data: Dict[str, str]) -> Dict[str, Any]:
    """Check permission cache"""

    try:
        async with get_db_session() as db:
            cache_key = data['cache_key']

            cached_query = select(IAMAccessEvaluation).where(
                and_(
                    IAMAccessEvaluation.cache_key == cache_key,
                    IAMAccessEvaluation.expires_at > datetime.now()
                )
            ).order_by(IAMAccessEvaluation.evaluated_at.desc()).limit(1)

            result = await db.execute(cached_query)
            cached_eval = result.scalar_one_or_none()

            if cached_eval:
                return {
                    'found': True,
                    'result': {
                        'access_granted': cached_eval.access_granted,
                        'reason': cached_eval.evaluation_reason,
                        'user_id': cached_eval.user_id,
                        'permission': f"{cached_eval.resource_type}:{cached_eval.action}",
                        'applied_roles': cached_eval.applied_roles or [],
                        'evaluated_at': cached_eval.evaluated_at.isoformat(),
                        'cached': True
                    }
                }

            return {'found': False}

    except Exception as e:
        logger.error(f"Permission cache check failed: {e}")
        return {'found': False, 'error': str(e)}

@activity.defn
async def evaluate_direct_permissions(request: PermissionEvaluationRequest) -> Dict[str, Any]:
    """Evaluate user's direct permissions"""

    try:
        async with get_db_session() as db:
            # For this implementation, users don't have direct permissions
            # All permissions come through roles
            # This could be extended to support direct user permissions

            return {
                'has_permission': False,
                'permissions': [],
                'evaluation_method': 'direct',
                'reason': 'no_direct_permissions_model'
            }

    except Exception as e:
        logger.error(f"Direct permission evaluation failed: {e}")
        return {
            'has_permission': False,
            'permissions': [],
            'evaluation_method': 'direct',
            'reason': f'evaluation_error: {str(e)}'
        }

@activity.defn
async def evaluate_role_permissions(request: PermissionEvaluationRequest) -> Dict[str, Any]:
    """Evaluate role-based permissions"""

    try:
        async with get_db_session() as db:
            # Get user with roles and their permissions
            user_query = select(User).options(
                selectinload(User.iam_roles).selectinload(IAMRole.permissions)
            ).where(User.id == request.user_id)

            result = await db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                return {
                    'has_permission': False,
                    'matching_roles': [],
                    'evaluation_method': 'roles',
                    'reason': 'user_not_found'
                }

            matching_roles = []
            matching_permissions = []

            # Check each role for the requested permission
            for role in user.iam_roles:
                if not role.is_active:
                    continue

                for permission in role.permissions:
                    if (permission.name == request.permission_name and
                        permission.is_active):

                        # Check scope compatibility
                        if await _is_permission_scope_compatible(
                            permission, request.scope_id, db
                        ):
                            matching_roles.append({
                                'role_id': role.id,
                                'role_name': role.name,
                                'permission_id': permission.id,
                                'permission_name': permission.name
                            })
                            matching_permissions.append(permission.name)

            has_permission = len(matching_roles) > 0

            return {
                'has_permission': has_permission,
                'matching_roles': matching_roles,
                'matching_permissions': list(set(matching_permissions)),
                'evaluation_method': 'roles',
                'reason': 'role_based_grant' if has_permission else 'no_matching_roles'
            }

    except Exception as e:
        logger.error(f"Role permission evaluation failed: {e}")
        return {
            'has_permission': False,
            'matching_roles': [],
            'evaluation_method': 'roles',
            'reason': f'evaluation_error: {str(e)}'
        }

@activity.defn
async def evaluate_scope_permissions(request: PermissionEvaluationRequest) -> Dict[str, Any]:
    """Evaluate scope-based permissions"""

    try:
        async with get_db_session() as db:
            if not request.scope_id:
                return {
                    'has_permission': True,  # No scope restriction
                    'applicable_scopes': [],
                    'evaluation_method': 'scope',
                    'reason': 'no_scope_restriction'
                }

            # Check if user has access to the requested scope
            scope_query = select(user_scopes_table).where(
                and_(
                    user_scopes_table.c.user_id == request.user_id,
                    user_scopes_table.c.scope_id == request.scope_id,
                    user_scopes_table.c.is_active == True
                )
            )

            result = await db.execute(scope_query)
            scope_access = result.first()

            if scope_access:
                return {
                    'has_permission': True,
                    'applicable_scopes': [request.scope_id],
                    'evaluation_method': 'scope',
                    'reason': 'user_has_scope_access'
                }

            # Check for inherited scope access
            scope = await db.get(IAMScope, request.scope_id)
            if scope and scope.parent_scope_id:
                parent_access_query = select(user_scopes_table).where(
                    and_(
                        user_scopes_table.c.user_id == request.user_id,
                        user_scopes_table.c.scope_id == scope.parent_scope_id,
                        user_scopes_table.c.is_active == True
                    )
                )

                parent_result = await db.execute(parent_access_query)
                if parent_result.first():
                    return {
                        'has_permission': True,
                        'applicable_scopes': [scope.parent_scope_id, request.scope_id],
                        'evaluation_method': 'scope',
                        'reason': 'inherited_scope_access'
                    }

            return {
                'has_permission': False,
                'applicable_scopes': [],
                'evaluation_method': 'scope',
                'reason': 'no_scope_access'
            }

    except Exception as e:
        logger.error(f"Scope permission evaluation failed: {e}")
        return {
            'has_permission': False,
            'applicable_scopes': [],
            'evaluation_method': 'scope',
            'reason': f'evaluation_error: {str(e)}'
        }

@activity.defn
async def check_resource_ownership(request: PermissionEvaluationRequest) -> Dict[str, Any]:
    """Check resource ownership"""

    try:
        if not request.resource_id or not request.resource_type:
            return {
                'is_owner': False,
                'reason': 'no_resource_specified'
            }

        async with get_db_session() as db:
            # Check if resource exists and user owns it
            resource_query = select(IAMResource).where(
                and_(
                    IAMResource.resource_type == request.resource_type,
                    IAMResource.resource_id == request.resource_id,
                    IAMResource.owner_id == request.user_id
                )
            )

            result = await db.execute(resource_query)
            resource = result.scalar_one_or_none()

            return {
                'is_owner': resource is not None,
                'resource_id': request.resource_id,
                'resource_type': request.resource_type,
                'reason': 'owns_resource' if resource else 'not_owner'
            }

    except Exception as e:
        logger.error(f"Resource ownership check failed: {e}")
        return {
            'is_owner': False,
            'reason': f'check_error: {str(e)}'
        }

@activity.defn
async def make_final_access_decision(data: Dict[str, Any]) -> Dict[str, Any]:
    """Make final access decision"""

    try:
        eval_request = data['eval_request']
        results = data['evaluation_results']

        # Extract results from different evaluation methods
        direct = results.get('direct', {})
        roles = results.get('roles', {})
        scopes = results.get('scopes', {})
        ownership = results.get('ownership', {})
        policies = results.get('policies', {})

        # Decision logic: Grant if any positive result
        access_granted = False
        reasons = []
        applied_roles = []

        # Check role-based permissions
        if roles.get('has_permission', False):
            access_granted = True
            reasons.append(roles.get('reason', 'role_based'))
            applied_roles.extend([r['role_name'] for r in roles.get('matching_roles', [])])

        # Check resource ownership
        if ownership.get('is_owner', False):
            access_granted = True
            reasons.append('resource_owner')
            applied_roles.append('resource_owner')

        # Check scope permissions
        if not scopes.get('has_permission', True):  # Default true if no scope
            access_granted = False
            reasons = ['scope_access_denied']

        # Apply policy decisions (if any deny policies, override)
        if policies.get('has_deny_policies', False):
            access_granted = False
            reasons = ['denied_by_policy']

        final_reason = '; '.join(reasons) if reasons else 'no_access_granted'

        return {
            'access_granted': access_granted,
            'reason': final_reason,
            'user_id': eval_request['user_id'],
            'permission': eval_request['permission_name'],
            'applied_roles': applied_roles,
            'evaluation_details': {
                'direct_permissions': direct,
                'role_permissions': roles,
                'scope_permissions': scopes,
                'resource_ownership': ownership,
                'policy_evaluation': policies
            },
            'evaluated_at': datetime.now().isoformat(),
            'cache_result': True
        }

    except Exception as e:
        logger.error(f"Final access decision failed: {e}")
        return {
            'access_granted': False,
            'reason': f'decision_error: {str(e)}',
            'user_id': data.get('eval_request', {}).get('user_id', 'unknown'),
            'permission': data.get('eval_request', {}).get('permission_name', 'unknown'),
            'evaluated_at': datetime.now().isoformat(),
            'cache_result': False
        }

# ===== HELPER FUNCTIONS =====

async def _is_permission_scope_compatible(
    permission: IAMPermission,
    scope_id: Optional[str],
    db: AsyncSession
) -> bool:
    """Check if permission is compatible with the requested scope"""

    if not permission.is_scope_aware:
        return True

    if not scope_id:
        return True

    # Check if permission's scope types include the current scope type
    if permission.scope_types:
        scope = await db.get(IAMScope, scope_id)
        if scope and scope.scope_type not in permission.scope_types:
            return False

    return True

# ===== NOTIFICATION AND LOGGING ACTIVITIES =====

@activity.defn
async def send_role_assignment_notification(data: Dict[str, Any]) -> Dict[str, Any]:
    """Send notification about role assignment"""

    # For demo purposes, just log the notification
    # In production, this would send emails, Slack messages, etc.

    request = data['assignment_request']
    result = data['assignment_result']

    logger.info(
        f"NOTIFICATION: Role {request['role_id']} assigned to user {request['user_id']} "
        f"in scope {request.get('scope_id', 'global')} by {request.get('granted_by', 'system')}"
    )

    return {
        'notification_sent': True,
        'method': 'logged',
        'timestamp': datetime.now().isoformat()
    }

@activity.defn
async def log_access_decision(data: Dict[str, Any]) -> Dict[str, Any]:
    """Log access decision for audit"""

    try:
        async with get_db_session() as db:
            eval_request = data['eval_request']
            decision = data['decision']

            audit_log = IAMAuditLog(
                actor_id=eval_request['user_id'],
                action='permission_evaluated',
                target_type='permission',
                target_id=eval_request['permission_name'],
                resource_type=eval_request.get('resource_type'),
                resource_id=eval_request.get('resource_id'),
                result='success',
                details={
                    'access_granted': decision['access_granted'],
                    'reason': decision['reason'],
                    'applied_roles': decision.get('applied_roles', []),
                    'scope_id': eval_request.get('scope_id')
                }
            )

            db.add(audit_log)
            await db.commit()

            return {'logged': True}

    except Exception as e:
        logger.error(f"Failed to log access decision: {e}")
        return {'logged': False, 'error': str(e)}