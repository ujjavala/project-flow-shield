"""
IAM Service Layer
Provides comprehensive Identity and Access Management services with Temporal workflow integration
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
import hashlib
import json

from app.models.user import User
from app.models.iam import (
    IAMRole, IAMPermission, IAMScope, IAMResource, IAMPolicy,
    IAMSession, IAMAuditLog, IAMAccessEvaluation, IAMContextualRole,
    IAMRoleRequest, user_roles_table, role_permissions_table,
    user_scopes_table, role_scope_table
)

logger = logging.getLogger(__name__)

class IAMService:
    """Comprehensive IAM Service with Temporal workflow integration"""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ===== ROLE MANAGEMENT =====

    async def assign_role_to_user(
        self,
        user_id: str,
        role_id: str,
        scope_id: Optional[str] = None,
        granted_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        use_temporal: bool = True
    ) -> Dict[str, Any]:
        """
        Assign a role to a user, optionally within a specific scope
        Uses Temporal workflow for complex assignments
        """
        try:
            if use_temporal:
                # Use Temporal workflow for role assignment
                from app.temporal.client import get_temporal_client
                from app.temporal.workflows.iam_workflows import IAMRoleAssignmentWorkflow

                client = await get_temporal_client()

                workflow_input = {
                    'user_id': user_id,
                    'role_id': role_id,
                    'scope_id': scope_id,
                    'granted_by': granted_by,
                    'expires_at': expires_at.isoformat() if expires_at else None,
                    'assignment_type': 'direct'
                }

                result = await client.execute_workflow(
                    IAMRoleAssignmentWorkflow.assign_role,
                    workflow_input,
                    id=f"role-assignment-{user_id}-{role_id}-{datetime.now().timestamp()}",
                    task_queue="iam-workflows"
                )

                return result
            else:
                # Direct assignment without workflow
                return await self._assign_role_direct(user_id, role_id, scope_id, granted_by, expires_at)

        except Exception as e:
            logger.error(f"Failed to assign role {role_id} to user {user_id}: {e}")
            await self._log_iam_audit(
                actor_id=granted_by,
                action='role_assignment_failed',
                target_type='user_role',
                target_id=f"{user_id}:{role_id}",
                result='failure',
                error_message=str(e)
            )
            raise

    async def _assign_role_direct(
        self,
        user_id: str,
        role_id: str,
        scope_id: Optional[str] = None,
        granted_by: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Direct role assignment without Temporal workflow"""

        # Verify user exists
        user = await self.db.get(User, user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Verify role exists
        role = await self.db.get(IAMRole, role_id)
        if not role:
            raise ValueError(f"Role {role_id} not found")

        # Verify scope if provided
        if scope_id:
            scope = await self.db.get(IAMScope, scope_id)
            if not scope:
                raise ValueError(f"Scope {scope_id} not found")

        # Check if assignment already exists
        existing_query = select(user_roles_table).where(
            and_(
                user_roles_table.c.user_id == user_id,
                user_roles_table.c.role_id == role_id
            )
        )
        existing = await self.db.execute(existing_query)
        if existing.first():
            return {'status': 'already_assigned', 'user_id': user_id, 'role_id': role_id}

        # Create the assignment
        assignment_data = {
            'user_id': user_id,
            'role_id': role_id,
            'granted_at': datetime.now(),
            'granted_by': granted_by,
            'expires_at': expires_at,
            'is_active': True
        }

        await self.db.execute(user_roles_table.insert().values(**assignment_data))

        # If this is a scoped role, create the scope assignment
        if scope_id:
            scope_assignment_data = {
                'role_id': role_id,
                'scope_id': scope_id,
                'user_id': user_id,
                'granted_at': datetime.now(),
                'granted_by': granted_by,
                'is_active': True
            }
            await self.db.execute(role_scope_table.insert().values(**scope_assignment_data))

        await self.db.commit()

        # Log the assignment
        await self._log_iam_audit(
            actor_id=granted_by,
            action='role_assigned',
            target_type='user_role',
            target_id=f"{user_id}:{role_id}",
            result='success',
            details={'scope_id': scope_id, 'expires_at': expires_at}
        )

        return {
            'status': 'assigned',
            'user_id': user_id,
            'role_id': role_id,
            'scope_id': scope_id,
            'assigned_at': datetime.now().isoformat()
        }

    # ===== PERMISSION EVALUATION =====

    async def evaluate_user_permission(
        self,
        user_id: str,
        permission_name: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        scope_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        use_temporal: bool = True
    ) -> Dict[str, Any]:
        """
        Evaluate whether a user has a specific permission
        Uses Temporal workflow for complex evaluations with caching
        """

        # Generate cache key for this evaluation
        cache_key = self._generate_permission_cache_key(
            user_id, permission_name, resource_type, resource_id, scope_id
        )

        # Check cache first
        cached_result = await self._get_cached_permission_evaluation(cache_key)
        if cached_result:
            return cached_result

        try:
            if use_temporal:
                # Use Temporal workflow for permission evaluation
                from app.temporal.client import get_temporal_client
                from app.temporal.workflows.iam_workflows import IAMPermissionEvaluationWorkflow

                client = await get_temporal_client()

                workflow_input = {
                    'user_id': user_id,
                    'permission_name': permission_name,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'scope_id': scope_id,
                    'context': context or {},
                    'cache_key': cache_key
                }

                result = await client.execute_workflow(
                    IAMPermissionEvaluationWorkflow.evaluate_permission,
                    workflow_input,
                    id=f"permission-eval-{user_id}-{hash(cache_key) % 100000}",
                    task_queue="iam-workflows",
                    execution_timeout=timedelta(seconds=30)
                )

                return result
            else:
                # Direct evaluation without workflow
                return await self._evaluate_permission_direct(
                    user_id, permission_name, resource_type, resource_id, scope_id, context
                )

        except Exception as e:
            logger.error(f"Failed to evaluate permission {permission_name} for user {user_id}: {e}")
            # Return deny by default on errors
            return {
                'access_granted': False,
                'reason': f'evaluation_error: {str(e)}',
                'user_id': user_id,
                'permission': permission_name,
                'evaluated_at': datetime.now().isoformat()
            }

    async def _evaluate_permission_direct(
        self,
        user_id: str,
        permission_name: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        scope_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Direct permission evaluation without Temporal workflow"""

        try:
            # Get user with roles and scopes
            user_query = select(User).options(
                selectinload(User.iam_roles),
                selectinload(User.scopes)
            ).where(User.id == user_id)

            result = await self.db.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                return self._create_permission_result(False, "user_not_found", user_id, permission_name)

            if not user.is_active:
                return self._create_permission_result(False, "user_inactive", user_id, permission_name)

            # Get the permission definition
            permission_query = select(IAMPermission).where(IAMPermission.name == permission_name)
            permission_result = await self.db.execute(permission_query)
            permission = permission_result.scalar_one_or_none()

            if not permission:
                return self._create_permission_result(False, "permission_not_found", user_id, permission_name)

            if not permission.is_active:
                return self._create_permission_result(False, "permission_inactive", user_id, permission_name)

            # Check if user has any roles that grant this permission
            user_roles = user.iam_roles if hasattr(user, 'iam_roles') else []
            granted_by_roles = []

            for role in user_roles:
                if not role.is_active:
                    continue

                # Check if role has this permission
                for role_permission in role.permissions:
                    if role_permission.name == permission_name and role_permission.is_active:
                        # Check scope compatibility
                        if await self._is_permission_applicable_to_scope(
                            role_permission, scope_id, user_id
                        ):
                            granted_by_roles.append(role.name)
                            break

            if granted_by_roles:
                # Check additional constraints (time, IP, etc.)
                constraint_check = await self._check_permission_constraints(
                    permission, user_id, context
                )

                if constraint_check['allowed']:
                    # Cache the positive result
                    await self._cache_permission_evaluation(
                        user_id, permission_name, resource_type, resource_id, scope_id,
                        True, f"granted_by_roles: {', '.join(granted_by_roles)}", granted_by_roles
                    )

                    return self._create_permission_result(
                        True, f"granted_by_roles: {', '.join(granted_by_roles)}",
                        user_id, permission_name, granted_by_roles
                    )
                else:
                    return self._create_permission_result(
                        False, f"constraint_violation: {constraint_check['reason']}",
                        user_id, permission_name
                    )

            # Check if user owns the resource (for resource-specific permissions)
            if resource_id and permission.applies_to_owned_resources:
                is_owner = await self._check_resource_ownership(user_id, resource_type, resource_id)
                if is_owner:
                    await self._cache_permission_evaluation(
                        user_id, permission_name, resource_type, resource_id, scope_id,
                        True, "resource_owner", ['resource_owner']
                    )
                    return self._create_permission_result(
                        True, "resource_owner", user_id, permission_name, ['resource_owner']
                    )

            # Default deny
            return self._create_permission_result(False, "no_matching_roles", user_id, permission_name)

        except Exception as e:
            logger.error(f"Permission evaluation error: {e}")
            return self._create_permission_result(False, f"evaluation_error: {str(e)}", user_id, permission_name)

    # ===== SCOPE MANAGEMENT =====

    async def get_user_accessible_scopes(
        self,
        user_id: str,
        scope_type: Optional[str] = None,
        action: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all scopes a user has access to"""

        try:
            # Base query for user scopes
            scopes_query = select(IAMScope).join(
                user_scopes_table, IAMScope.id == user_scopes_table.c.scope_id
            ).where(
                and_(
                    user_scopes_table.c.user_id == user_id,
                    user_scopes_table.c.is_active == True,
                    IAMScope.is_active == True
                )
            )

            # Filter by scope type if provided
            if scope_type:
                scopes_query = scopes_query.where(IAMScope.scope_type == scope_type)

            result = await self.db.execute(scopes_query)
            accessible_scopes = result.scalars().all()

            # Convert to response format
            scopes_list = []
            for scope in accessible_scopes:
                scope_dict = {
                    'id': scope.id,
                    'name': scope.name,
                    'display_name': scope.display_name,
                    'scope_type': scope.scope_type,
                    'hierarchy_path': scope.hierarchy_path,
                    'level': scope.level,
                    'metadata': scope.metadata
                }

                # Add available actions if requested
                if action:
                    scope_dict['can_perform_action'] = await self._can_perform_action_in_scope(
                        user_id, action, scope.id
                    )

                scopes_list.append(scope_dict)

            return scopes_list

        except Exception as e:
            logger.error(f"Failed to get accessible scopes for user {user_id}: {e}")
            return []

    # ===== AUDIT AND LOGGING =====

    async def _log_iam_audit(
        self,
        actor_id: Optional[str],
        action: str,
        target_type: str,
        target_id: str,
        result: str = 'success',
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log IAM-related actions for audit purposes"""

        try:
            audit_log = IAMAuditLog(
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                result=result,
                details=details,
                error_message=error_message,
                ip_address=ip_address,
                user_agent=user_agent
            )

            self.db.add(audit_log)
            await self.db.commit()

        except Exception as e:
            logger.error(f"Failed to log IAM audit: {e}")

    # ===== HELPER METHODS =====

    def _generate_permission_cache_key(
        self,
        user_id: str,
        permission_name: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        scope_id: Optional[str] = None
    ) -> str:
        """Generate a cache key for permission evaluation"""

        cache_data = {
            'user_id': user_id,
            'permission': permission_name,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'scope_id': scope_id
        }

        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()

    def _create_permission_result(
        self,
        granted: bool,
        reason: str,
        user_id: str,
        permission: str,
        applied_roles: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a standardized permission evaluation result"""

        return {
            'access_granted': granted,
            'reason': reason,
            'user_id': user_id,
            'permission': permission,
            'applied_roles': applied_roles or [],
            'evaluated_at': datetime.now().isoformat()
        }

    async def _get_cached_permission_evaluation(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached permission evaluation result"""

        try:
            cached_query = select(IAMAccessEvaluation).where(
                and_(
                    IAMAccessEvaluation.cache_key == cache_key,
                    IAMAccessEvaluation.expires_at > datetime.now()
                )
            ).order_by(IAMAccessEvaluation.evaluated_at.desc()).limit(1)

            result = await self.db.execute(cached_query)
            cached_eval = result.scalar_one_or_none()

            if cached_eval:
                return {
                    'access_granted': cached_eval.access_granted,
                    'reason': cached_eval.evaluation_reason,
                    'user_id': cached_eval.user_id,
                    'permission': f"{cached_eval.resource_type}:{cached_eval.action}",
                    'applied_roles': cached_eval.applied_roles or [],
                    'evaluated_at': cached_eval.evaluated_at.isoformat(),
                    'cached': True
                }

            return None

        except Exception as e:
            logger.error(f"Failed to get cached permission evaluation: {e}")
            return None

    async def _cache_permission_evaluation(
        self,
        user_id: str,
        permission_name: str,
        resource_type: Optional[str],
        resource_id: Optional[str],
        scope_id: Optional[str],
        access_granted: bool,
        reason: str,
        applied_roles: List[str],
        ttl_seconds: int = 300
    ):
        """Cache permission evaluation result"""

        try:
            cache_key = self._generate_permission_cache_key(
                user_id, permission_name, resource_type, resource_id, scope_id
            )

            cached_eval = IAMAccessEvaluation(
                user_id=user_id,
                resource_type=resource_type or 'system',
                resource_id=resource_id or 'global',
                action=permission_name,
                scope_id=scope_id,
                access_granted=access_granted,
                evaluation_reason=reason,
                applied_roles=applied_roles,
                cache_key=cache_key,
                ttl_seconds=ttl_seconds,
                expires_at=datetime.now() + timedelta(seconds=ttl_seconds)
            )

            self.db.add(cached_eval)
            await self.db.commit()

        except Exception as e:
            logger.error(f"Failed to cache permission evaluation: {e}")

    async def _is_permission_applicable_to_scope(
        self,
        permission: IAMPermission,
        scope_id: Optional[str],
        user_id: str
    ) -> bool:
        """Check if a permission applies to the given scope"""

        if not permission.is_scope_aware:
            return True  # Permission applies globally

        if not scope_id:
            return True  # No scope restriction

        # Check if permission's scope types include the current scope
        if permission.scope_types:
            scope = await self.db.get(IAMScope, scope_id)
            if scope and scope.scope_type not in permission.scope_types:
                return False

        return True

    async def _check_permission_constraints(
        self,
        permission: IAMPermission,
        user_id: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check additional permission constraints (time, IP, etc.)"""

        # For now, return allowed - implement constraint checking as needed
        return {'allowed': True, 'reason': 'no_constraints'}

    async def _check_resource_ownership(
        self,
        user_id: str,
        resource_type: Optional[str],
        resource_id: str
    ) -> bool:
        """Check if user owns the specified resource"""

        if not resource_type or not resource_id:
            return False

        try:
            resource_query = select(IAMResource).where(
                and_(
                    IAMResource.resource_type == resource_type,
                    IAMResource.resource_id == resource_id,
                    IAMResource.owner_id == user_id
                )
            )

            result = await self.db.execute(resource_query)
            resource = result.scalar_one_or_none()

            return resource is not None

        except Exception as e:
            logger.error(f"Failed to check resource ownership: {e}")
            return False

    async def _can_perform_action_in_scope(
        self,
        user_id: str,
        action: str,
        scope_id: str
    ) -> bool:
        """Check if user can perform action in specific scope"""

        # This would involve checking user's roles in the scope and their permissions
        # For now, return True - implement full logic as needed
        return True

# Global IAM service instance
iam_service: Optional[IAMService] = None

def get_iam_service(db: AsyncSession) -> IAMService:
    """Get or create IAM service instance"""
    return IAMService(db)