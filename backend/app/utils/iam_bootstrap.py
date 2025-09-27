"""
IAM Bootstrap Script
Creates initial IAM data including roles, permissions, scopes, and test users
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.connection import AsyncSessionLocal
from app.models.user import User
from app.models.iam import (
    IAMRole, IAMPermission, IAMScope, IAMResource,
    user_roles_table, role_permissions_table, user_scopes_table
)
from app.utils.security import hash_password

logger = logging.getLogger(__name__)

class IAMBootstrap:
    """Bootstrap IAM system with initial data"""

    def __init__(self):
        self.created_items = {
            'permissions': [],
            'roles': [],
            'scopes': [],
            'users': [],
            'assignments': []
        }

    async def bootstrap_all(self) -> Dict[str, any]:
        """Run complete IAM bootstrap process"""

        try:
            async with AsyncSessionLocal() as db:
                # Step 1: Create permissions
                await self._create_permissions(db)
                logger.info(f"Created {len(self.created_items['permissions'])} permissions")

                # Step 2: Create roles
                await self._create_roles(db)
                logger.info(f"Created {len(self.created_items['roles'])} roles")

                # Step 3: Create scopes
                await self._create_scopes(db)
                logger.info(f"Created {len(self.created_items['scopes'])} scopes")

                # Step 4: Assign permissions to roles
                await self._assign_permissions_to_roles(db)
                logger.info("Assigned permissions to roles")

                # Step 5: Create test users
                await self._create_test_users(db)
                logger.info(f"Created {len(self.created_items['users'])} test users")

                # Step 6: Assign roles to users
                await self._assign_roles_to_users(db)
                logger.info("Assigned roles to users")

                # Step 7: Create sample resources
                await self._create_sample_resources(db)
                logger.info("Created sample resources")

                await db.commit()

                return {
                    'success': True,
                    'message': 'IAM system bootstrapped successfully',
                    'created_items': self.created_items,
                    'test_credentials': self._get_test_credentials()
                }

        except Exception as e:
            logger.error(f"IAM bootstrap failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'created_items': self.created_items
            }

    async def _create_permissions(self, db: AsyncSession):
        """Create initial permissions"""

        permissions_data = [
            # User management permissions
            {
                'name': 'user.create',
                'display_name': 'Create Users',
                'description': 'Ability to create new users',
                'category': 'user_management',
                'action': 'create',
                'resource_type': 'users',
                'risk_level': 'medium',
                'scope_types': ['organization', 'department']
            },
            {
                'name': 'user.read',
                'display_name': 'Read Users',
                'description': 'Ability to view user information',
                'category': 'user_management',
                'action': 'read',
                'resource_type': 'users',
                'risk_level': 'low'
            },
            {
                'name': 'user.update',
                'display_name': 'Update Users',
                'description': 'Ability to modify user information',
                'category': 'user_management',
                'action': 'update',
                'resource_type': 'users',
                'risk_level': 'medium'
            },
            {
                'name': 'user.delete',
                'display_name': 'Delete Users',
                'description': 'Ability to delete users',
                'category': 'user_management',
                'action': 'delete',
                'resource_type': 'users',
                'risk_level': 'high'
            },
            {
                'name': 'user.read_own',
                'display_name': 'Read Own Profile',
                'description': 'Ability to view own user information',
                'category': 'user_management',
                'action': 'read',
                'resource_type': 'users',
                'risk_level': 'low',
                'applies_to_owned_resources': True
            },
            {
                'name': 'user.update_own',
                'display_name': 'Update Own Profile',
                'description': 'Ability to modify own user information',
                'category': 'user_management',
                'action': 'update',
                'resource_type': 'users',
                'risk_level': 'low',
                'applies_to_owned_resources': True
            },

            # IAM permissions
            {
                'name': 'iam.roles.create',
                'display_name': 'Create Roles',
                'description': 'Ability to create new roles',
                'category': 'iam',
                'action': 'create',
                'resource_type': 'roles',
                'risk_level': 'high'
            },
            {
                'name': 'iam.roles.read',
                'display_name': 'Read Roles',
                'description': 'Ability to view roles',
                'category': 'iam',
                'action': 'read',
                'resource_type': 'roles',
                'risk_level': 'low'
            },
            {
                'name': 'iam.roles.update',
                'display_name': 'Update Roles',
                'description': 'Ability to modify roles',
                'category': 'iam',
                'action': 'update',
                'resource_type': 'roles',
                'risk_level': 'high'
            },
            {
                'name': 'iam.permissions.create',
                'display_name': 'Create Permissions',
                'description': 'Ability to create new permissions',
                'category': 'iam',
                'action': 'create',
                'resource_type': 'permissions',
                'risk_level': 'critical'
            },
            {
                'name': 'iam.permissions.read',
                'display_name': 'Read Permissions',
                'description': 'Ability to view permissions',
                'category': 'iam',
                'action': 'read',
                'resource_type': 'permissions',
                'risk_level': 'low'
            },
            {
                'name': 'iam.users.assign_roles',
                'display_name': 'Assign Roles to Users',
                'description': 'Ability to assign roles to users',
                'category': 'iam',
                'action': 'assign',
                'resource_type': 'user_roles',
                'risk_level': 'high'
            },
            {
                'name': 'iam.permissions.check',
                'display_name': 'Check Permissions',
                'description': 'Ability to check user permissions',
                'category': 'iam',
                'action': 'check',
                'resource_type': 'permissions',
                'risk_level': 'medium'
            },
            {
                'name': 'iam.permissions.check_own',
                'display_name': 'Check Own Permissions',
                'description': 'Ability to check own permissions',
                'category': 'iam',
                'action': 'check',
                'resource_type': 'permissions',
                'risk_level': 'low',
                'applies_to_owned_resources': True
            },
            {
                'name': 'iam.audit.read',
                'display_name': 'Read Audit Logs',
                'description': 'Ability to view audit logs',
                'category': 'iam',
                'action': 'read',
                'resource_type': 'audit_logs',
                'risk_level': 'medium'
            },

            # Dashboard permissions
            {
                'name': 'dashboard.admin.access',
                'display_name': 'Access Admin Dashboard',
                'description': 'Ability to access admin dashboard',
                'category': 'dashboard',
                'action': 'access',
                'resource_type': 'admin_dashboard',
                'risk_level': 'medium'
            },
            {
                'name': 'dashboard.user.access',
                'display_name': 'Access User Dashboard',
                'description': 'Ability to access user dashboard',
                'category': 'dashboard',
                'action': 'access',
                'resource_type': 'user_dashboard',
                'risk_level': 'low'
            },

            # System permissions
            {
                'name': 'system.admin',
                'display_name': 'System Administration',
                'description': 'Full system administration access',
                'category': 'system',
                'action': 'admin',
                'resource_type': 'system',
                'risk_level': 'critical'
            },
            {
                'name': 'system.health.read',
                'display_name': 'Read System Health',
                'description': 'Ability to view system health status',
                'category': 'system',
                'action': 'read',
                'resource_type': 'system_health',
                'risk_level': 'low'
            },

            # Content permissions
            {
                'name': 'content.moderate',
                'display_name': 'Moderate Content',
                'description': 'Ability to moderate user content',
                'category': 'content',
                'action': 'moderate',
                'resource_type': 'content',
                'risk_level': 'medium'
            },

            # Analytics permissions
            {
                'name': 'analytics.read',
                'display_name': 'Read Analytics',
                'description': 'Ability to view analytics data',
                'category': 'analytics',
                'action': 'read',
                'resource_type': 'analytics',
                'risk_level': 'low'
            }
        ]

        for perm_data in permissions_data:
            # Check if permission already exists
            existing = await db.execute(
                select(IAMPermission).where(IAMPermission.name == perm_data['name'])
            )
            if existing.scalar_one_or_none():
                continue

            permission = IAMPermission(**perm_data)
            db.add(permission)
            await db.flush()
            self.created_items['permissions'].append(permission.name)

    async def _create_roles(self, db: AsyncSession):
        """Create initial roles"""

        roles_data = [
            {
                'name': 'super_admin',
                'display_name': 'Super Administrator',
                'description': 'Full system access with all permissions',
                'scope': 'global',
                'priority': 10,
                'is_system_role': True
            },
            {
                'name': 'admin',
                'display_name': 'Administrator',
                'description': 'Administrative access with most permissions',
                'scope': 'global',
                'priority': 8,
                'is_system_role': True
            },
            {
                'name': 'manager',
                'display_name': 'Manager',
                'description': 'Management role with team oversight',
                'scope': 'organization',
                'priority': 6
            },
            {
                'name': 'moderator',
                'display_name': 'Moderator',
                'description': 'Content moderation and user management',
                'scope': 'organization',
                'priority': 4
            },
            {
                'name': 'analyst',
                'display_name': 'Data Analyst',
                'description': 'Analytics and reporting access',
                'scope': 'organization',
                'priority': 3
            },
            {
                'name': 'user',
                'display_name': 'Standard User',
                'description': 'Basic user access with own profile management',
                'scope': 'global',
                'priority': 1
            },
            {
                'name': 'guest',
                'display_name': 'Guest User',
                'description': 'Limited read-only access',
                'scope': 'global',
                'priority': 0
            }
        ]

        for role_data in roles_data:
            # Check if role already exists
            existing = await db.execute(
                select(IAMRole).where(IAMRole.name == role_data['name'])
            )
            if existing.scalar_one_or_none():
                continue

            role = IAMRole(**role_data)
            db.add(role)
            await db.flush()
            self.created_items['roles'].append(role.name)

    async def _create_scopes(self, db: AsyncSession):
        """Create initial scopes"""

        scopes_data = [
            # Organization level
            {
                'name': 'acme_corp',
                'display_name': 'ACME Corporation',
                'description': 'Main organizational scope',
                'scope_type': 'organization',
                'level': 0,
                'hierarchy_path': '/acme_corp'
            },

            # Department level
            {
                'name': 'engineering',
                'display_name': 'Engineering Department',
                'description': 'Engineering team scope',
                'scope_type': 'department',
                'level': 1,
                'hierarchy_path': '/acme_corp/engineering'
            },
            {
                'name': 'marketing',
                'display_name': 'Marketing Department',
                'description': 'Marketing team scope',
                'scope_type': 'department',
                'level': 1,
                'hierarchy_path': '/acme_corp/marketing'
            },
            {
                'name': 'hr',
                'display_name': 'Human Resources',
                'description': 'HR department scope',
                'scope_type': 'department',
                'level': 1,
                'hierarchy_path': '/acme_corp/hr'
            },

            # Team level
            {
                'name': 'backend_team',
                'display_name': 'Backend Development Team',
                'description': 'Backend development team scope',
                'scope_type': 'team',
                'level': 2,
                'hierarchy_path': '/acme_corp/engineering/backend'
            },
            {
                'name': 'frontend_team',
                'display_name': 'Frontend Development Team',
                'description': 'Frontend development team scope',
                'scope_type': 'team',
                'level': 2,
                'hierarchy_path': '/acme_corp/engineering/frontend'
            }
        ]

        # Track parent relationships for setting later
        parent_relationships = [
            ('engineering', 'acme_corp'),
            ('marketing', 'acme_corp'),
            ('hr', 'acme_corp'),
            ('backend_team', 'engineering'),
            ('frontend_team', 'engineering')
        ]

        # Create scopes first
        scope_lookup = {}
        for scope_data in scopes_data:
            # Check if scope already exists
            existing = await db.execute(
                select(IAMScope).where(IAMScope.name == scope_data['name'])
            )
            if existing.scalar_one_or_none():
                continue

            scope = IAMScope(**scope_data)
            db.add(scope)
            await db.flush()
            scope_lookup[scope.name] = scope
            self.created_items['scopes'].append(scope.name)

        # Set parent relationships
        for child_name, parent_name in parent_relationships:
            if child_name in scope_lookup and parent_name in scope_lookup:
                child_scope = scope_lookup[child_name]
                parent_scope = scope_lookup[parent_name]
                child_scope.parent_scope_id = parent_scope.id

    async def _assign_permissions_to_roles(self, db: AsyncSession):
        """Assign permissions to roles"""

        # Get all roles and permissions
        roles_result = await db.execute(select(IAMRole))
        roles = {role.name: role for role in roles_result.scalars().all()}

        permissions_result = await db.execute(select(IAMPermission))
        permissions = {perm.name: perm for perm in permissions_result.scalars().all()}

        # Define role-permission mappings
        role_permissions = {
            'super_admin': [
                # Super admin gets all permissions
                perm_name for perm_name in permissions.keys()
            ],
            'admin': [
                'user.create', 'user.read', 'user.update', 'user.delete',
                'iam.roles.read', 'iam.permissions.read', 'iam.users.assign_roles',
                'iam.permissions.check', 'iam.audit.read',
                'dashboard.admin.access', 'dashboard.user.access',
                'system.health.read', 'analytics.read'
            ],
            'manager': [
                'user.read', 'user.update',
                'iam.permissions.check', 'iam.audit.read',
                'dashboard.admin.access', 'dashboard.user.access',
                'analytics.read', 'content.moderate'
            ],
            'moderator': [
                'user.read', 'content.moderate',
                'dashboard.user.access', 'iam.permissions.check_own'
            ],
            'analyst': [
                'user.read', 'analytics.read',
                'dashboard.user.access', 'iam.permissions.check_own'
            ],
            'user': [
                'user.read_own', 'user.update_own',
                'dashboard.user.access', 'iam.permissions.check_own'
            ],
            'guest': [
                'dashboard.user.access', 'iam.permissions.check_own'
            ]
        }

        # Assign permissions to roles
        for role_name, permission_names in role_permissions.items():
            if role_name not in roles:
                continue

            role = roles[role_name]

            for permission_name in permission_names:
                if permission_name not in permissions:
                    continue

                permission = permissions[permission_name]

                # Check if assignment already exists
                existing = await db.execute(
                    select(role_permissions_table).where(
                        (role_permissions_table.c.role_id == role.id) &
                        (role_permissions_table.c.permission_id == permission.id)
                    )
                )
                if existing.first():
                    continue

                # Create the assignment
                await db.execute(
                    role_permissions_table.insert().values(
                        role_id=role.id,
                        permission_id=permission.id,
                        granted_at=datetime.now()
                    )
                )

    async def _create_test_users(self, db: AsyncSession):
        """Create test users with different roles"""

        test_users = [
            {
                'email': 'super.admin@temporal-auth.com',
                'username': 'superadmin',
                'password': 'SuperAdmin123!',
                'first_name': 'Super',
                'last_name': 'Administrator',
                'role': 'admin',  # Legacy field
                'is_superuser': True,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'super_admin'
            },
            {
                'email': 'admin@temporal-auth.com',
                'username': 'admin',
                'password': 'Admin123!',
                'first_name': 'System',
                'last_name': 'Admin',
                'role': 'admin',  # Legacy field
                'is_superuser': False,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'admin'
            },
            {
                'email': 'manager@temporal-auth.com',
                'username': 'manager',
                'password': 'Manager123!',
                'first_name': 'Team',
                'last_name': 'Manager',
                'role': 'moderator',  # Legacy field
                'is_superuser': False,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'manager'
            },
            {
                'email': 'moderator@temporal-auth.com',
                'username': 'moderator',
                'password': 'Moderator123!',
                'first_name': 'Content',
                'last_name': 'Moderator',
                'role': 'moderator',  # Legacy field
                'is_superuser': False,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'moderator'
            },
            {
                'email': 'analyst@temporal-auth.com',
                'username': 'analyst',
                'password': 'Analyst123!',
                'first_name': 'Data',
                'last_name': 'Analyst',
                'role': 'user',  # Legacy field
                'is_superuser': False,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'analyst'
            },
            {
                'email': 'user@temporal-auth.com',
                'username': 'regularuser',
                'password': 'User123!',
                'first_name': 'Regular',
                'last_name': 'User',
                'role': 'user',  # Legacy field
                'is_superuser': False,
                'is_verified': True,
                'is_active': True,
                'iam_role': 'user'
            },
            {
                'email': 'guest@temporal-auth.com',
                'username': 'guestuser',
                'password': 'Guest123!',
                'first_name': 'Guest',
                'last_name': 'User',
                'role': 'user',  # Legacy field
                'is_superuser': False,
                'is_verified': False,
                'is_active': True,
                'iam_role': 'guest'
            }
        ]

        for user_data in test_users:
            # Check if user already exists
            existing_result = await db.execute(
                select(User).where(User.email == user_data['email'])
            )
            existing_user = existing_result.scalar_one_or_none()

            # Extract IAM role for later assignment
            iam_role = user_data.pop('iam_role')

            if existing_user:
                # Update existing user with admin privileges if needed
                if user_data.get('is_superuser') or user_data.get('role') in ['admin', 'moderator']:
                    existing_user.role = user_data.get('role', existing_user.role)
                    existing_user.is_superuser = user_data.get('is_superuser', existing_user.is_superuser)
                    existing_user.is_verified = user_data.get('is_verified', existing_user.is_verified)
                    existing_user.is_active = user_data.get('is_active', existing_user.is_active)
                    # Update names if provided
                    if user_data.get('first_name'):
                        existing_user.first_name = user_data.get('first_name')
                    if user_data.get('last_name'):
                        existing_user.last_name = user_data.get('last_name')
                    await db.flush()
                    logger.info(f"Updated existing user {existing_user.email} with admin privileges (role: {existing_user.role}, superuser: {existing_user.is_superuser})")

                # Store for role assignment
                existing_user.iam_role_to_assign = iam_role
                self.created_items['users'].append({
                    'email': existing_user.email,
                    'username': existing_user.username,
                    'iam_role': iam_role
                })
                continue

            # Hash password
            user_data['hashed_password'] = hash_password(user_data.pop('password'))

            # Create user
            user = User(**user_data)
            db.add(user)
            await db.flush()

            # Store for role assignment
            user.iam_role_to_assign = iam_role
            self.created_items['users'].append({
                'email': user.email,
                'username': user.username,
                'iam_role': iam_role
            })

    async def _assign_roles_to_users(self, db: AsyncSession):
        """Assign IAM roles to test users"""

        # Get all users and roles
        users_result = await db.execute(select(User))
        users = users_result.scalars().all()

        roles_result = await db.execute(select(IAMRole))
        roles = {role.name: role for role in roles_result.scalars().all()}

        scopes_result = await db.execute(select(IAMScope))
        scopes = {scope.name: scope for scope in scopes_result.scalars().all()}

        # Assign roles to users
        for user in users:
            if not hasattr(user, 'iam_role_to_assign'):
                continue

            role_name = user.iam_role_to_assign
            if role_name not in roles:
                continue

            role = roles[role_name]

            # Check if assignment already exists
            existing = await db.execute(
                select(user_roles_table).where(
                    (user_roles_table.c.user_id == user.id) &
                    (user_roles_table.c.role_id == role.id)
                )
            )
            if existing.first():
                continue

            # Assign role to user
            await db.execute(
                user_roles_table.insert().values(
                    user_id=user.id,
                    role_id=role.id,
                    granted_at=datetime.now(),
                    is_active=True
                )
            )

            # Assign scope based on role
            scope_assignments = {
                'super_admin': ['acme_corp'],
                'admin': ['acme_corp'],
                'manager': ['acme_corp', 'engineering'],
                'moderator': ['engineering'],
                'analyst': ['marketing'],
                'user': ['frontend_team'],
                'guest': []
            }

            scope_names = scope_assignments.get(role_name, [])
            for scope_name in scope_names:
                if scope_name in scopes:
                    scope = scopes[scope_name]

                    # Check if scope assignment already exists
                    existing_scope = await db.execute(
                        select(user_scopes_table).where(
                            (user_scopes_table.c.user_id == user.id) &
                            (user_scopes_table.c.scope_id == scope.id)
                        )
                    )
                    if existing_scope.first():
                        continue

                    await db.execute(
                        user_scopes_table.insert().values(
                            user_id=user.id,
                            scope_id=scope.id,
                            granted_at=datetime.now(),
                            is_active=True
                        )
                    )

            self.created_items['assignments'].append({
                'user_email': user.email,
                'role': role_name,
                'scopes': scope_names
            })

    async def _create_sample_resources(self, db: AsyncSession):
        """Create sample resources for testing"""

        # This would create sample resources that users can access
        # For now, we'll skip this as it's mainly for demonstration
        pass

    def _get_test_credentials(self) -> Dict[str, Dict[str, str]]:
        """Get test user credentials"""

        return {
            'super_admin': {
                'email': 'super.admin@temporal-auth.com',
                'username': 'superadmin',
                'password': 'SuperAdmin123!',
                'role': 'Super Administrator',
                'permissions': 'All permissions',
                'scopes': 'Global (ACME Corp)'
            },
            'admin': {
                'email': 'admin@temporal-auth.com',
                'username': 'admin',
                'password': 'Admin123!',
                'role': 'Administrator',
                'permissions': 'Most admin permissions',
                'scopes': 'Global (ACME Corp)'
            },
            'manager': {
                'email': 'manager@temporal-auth.com',
                'username': 'manager',
                'password': 'Manager123!',
                'role': 'Manager',
                'permissions': 'Team management, analytics',
                'scopes': 'ACME Corp, Engineering Dept'
            },
            'moderator': {
                'email': 'moderator@temporal-auth.com',
                'username': 'moderator',
                'password': 'Moderator123!',
                'role': 'Moderator',
                'permissions': 'Content moderation, user viewing',
                'scopes': 'Engineering Department'
            },
            'analyst': {
                'email': 'analyst@temporal-auth.com',
                'username': 'analyst',
                'password': 'Analyst123!',
                'role': 'Data Analyst',
                'permissions': 'Analytics, reporting',
                'scopes': 'Marketing Department'
            },
            'user': {
                'email': 'user@temporal-auth.com',
                'username': 'regularuser',
                'password': 'User123!',
                'role': 'Standard User',
                'permissions': 'Own profile management',
                'scopes': 'Frontend Team'
            },
            'guest': {
                'email': 'guest@temporal-auth.com',
                'username': 'guestuser',
                'password': 'Guest123!',
                'role': 'Guest User',
                'permissions': 'Limited read-only',
                'scopes': 'None'
            }
        }

# Global bootstrap instance
bootstrap = IAMBootstrap()

async def run_iam_bootstrap() -> Dict[str, any]:
    """Run IAM bootstrap process"""
    return await bootstrap.bootstrap_all()

if __name__ == "__main__":
    # Run bootstrap directly
    result = asyncio.run(run_iam_bootstrap())
    print("IAM Bootstrap Result:", result)