"""
IAM (Identity and Access Management) Models
Comprehensive role-based access control system with granular permissions
"""

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, ForeignKey, Table, JSON
from sqlalchemy.orm import relationship
from app.database.base import Base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

# Association tables for many-to-many relationships
user_roles_table = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('role_id', String, ForeignKey('iam_roles.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('granted_by', String, ForeignKey('users.id'), nullable=True),
    Column('expires_at', DateTime(timezone=True), nullable=True),
    Column('is_active', Boolean, default=True)
)

role_permissions_table = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', String, ForeignKey('iam_roles.id'), primary_key=True),
    Column('permission_id', String, ForeignKey('iam_permissions.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('granted_by', String, ForeignKey('users.id'), nullable=True)
)

class IAMRole(Base):
    """IAM Role Model - Defines roles that can be assigned to users"""
    __tablename__ = "iam_roles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Role properties
    is_system_role = Column(Boolean, default=False)  # System roles cannot be deleted
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=0)  # Higher priority roles take precedence

    # Role context and scope
    scope = Column(String(50), default='global')  # global, organization, project, etc.
    context_data = Column(JSON, nullable=True)  # Additional context for scoped roles

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String, ForeignKey('users.id'), nullable=True)

    # Relationships
    permissions = relationship('IAMPermission', secondary=role_permissions_table, back_populates='roles')
    users = relationship('User', secondary=user_roles_table, back_populates='iam_roles')

    def __repr__(self):
        return f"<IAMRole(name={self.name}, display_name={self.display_name})>"

class IAMPermission(Base):
    """IAM Permission Model - Defines granular permissions with scope awareness"""
    __tablename__ = "iam_permissions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Permission categorization
    category = Column(String(50), nullable=False)  # user_management, system, security, etc.
    resource_type = Column(String(50), nullable=True)  # users, roles, dashboards, etc.
    action = Column(String(50), nullable=False)  # create, read, update, delete, execute

    # Scope-based permission properties
    scope_types = Column(JSON, nullable=True)  # Which scope types this permission applies to
    is_scope_aware = Column(Boolean, default=True)  # Whether this permission respects scopes
    inherit_to_child_scopes = Column(Boolean, default=True)  # Inherits to child scopes
    applies_to_owned_resources = Column(Boolean, default=False)  # Special handling for resource owners

    # Permission constraints
    conditions = Column(JSON, nullable=True)  # Additional conditions for permission evaluation
    time_restrictions = Column(JSON, nullable=True)  # Time-based access restrictions
    ip_restrictions = Column(JSON, nullable=True)  # IP-based access restrictions

    # Permission properties
    is_system_permission = Column(Boolean, default=False)  # System permissions cannot be deleted
    is_active = Column(Boolean, default=True)
    risk_level = Column(String(20), default='low')  # low, medium, high, critical

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String, ForeignKey('users.id'), nullable=True)

    # Relationships
    roles = relationship('IAMRole', secondary=role_permissions_table, back_populates='permissions')

    def __repr__(self):
        return f"<IAMPermission(name={self.name}, category={self.category}, action={self.action})>"

class IAMPolicy(Base):
    """IAM Policy Model - Complex access control policies"""
    __tablename__ = "iam_policies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Policy definition
    policy_document = Column(JSON, nullable=False)  # JSON policy document
    version = Column(String(10), default='2024-01-01')

    # Policy properties
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    effect = Column(String(20), default='allow')  # allow, deny

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String, ForeignKey('users.id'), nullable=True)

    def __repr__(self):
        return f"<IAMPolicy(name={self.name}, effect={self.effect})>"

# Association table for user-scope assignments
user_scopes_table = Table(
    'user_scopes',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('scope_id', String, ForeignKey('iam_scopes.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('granted_by', String, ForeignKey('users.id'), nullable=True),
    Column('expires_at', DateTime(timezone=True), nullable=True),
    Column('is_active', Boolean, default=True)
)

# Association table for role-scope combinations
role_scope_table = Table(
    'role_scope_assignments',
    Base.metadata,
    Column('role_id', String, ForeignKey('iam_roles.id'), primary_key=True),
    Column('scope_id', String, ForeignKey('iam_scopes.id'), primary_key=True),
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('granted_by', String, ForeignKey('users.id'), nullable=True),
    Column('is_active', Boolean, default=True)
)

class IAMScope(Base):
    """IAM Scope Model - Defines access scopes (organizations, projects, departments, etc.)"""
    __tablename__ = "iam_scopes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, index=True)  # org:acme-corp, project:auth-service
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Scope hierarchy and type
    scope_type = Column(String(50), nullable=False)  # organization, project, department, team, resource
    parent_scope_id = Column(String, ForeignKey('iam_scopes.id'), nullable=True)
    hierarchy_path = Column(String(500), nullable=True)  # /org/dept/team for quick lookups
    level = Column(Integer, default=0)  # 0 = root level, 1 = child, etc.

    # Scope properties
    is_active = Column(Boolean, default=True)
    is_inheritable = Column(Boolean, default=True)  # Child scopes inherit permissions
    auto_assign_users = Column(Boolean, default=False)  # Automatically assign new users

    # Scope configuration
    metadata = Column(JSON, nullable=True)
    settings = Column(JSON, nullable=True)  # Scope-specific settings

    # Geographic or logical boundaries
    region = Column(String(50), nullable=True)
    timezone = Column(String(50), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String, ForeignKey('users.id'), nullable=True)

    # Relationships
    parent_scope = relationship('IAMScope', remote_side=[id], backref='child_scopes')
    users = relationship('User', secondary=user_scopes_table, back_populates='scopes')
    resources = relationship('IAMResource', back_populates='scope')

    def __repr__(self):
        return f"<IAMScope(name={self.name}, type={self.scope_type}, level={self.level})>"

class IAMResource(Base):
    """IAM Resource Model - Defines resources that can be accessed within scopes"""
    __tablename__ = "iam_resources"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_type = Column(String(50), nullable=False, index=True)  # dashboard, user, report, etc.
    resource_id = Column(String(100), nullable=False, index=True)  # Specific resource identifier
    resource_name = Column(String(200), nullable=True)

    # Resource ownership and scope
    owner_id = Column(String, ForeignKey('users.id'), nullable=True)
    scope_id = Column(String, ForeignKey('iam_scopes.id'), nullable=True)  # Resource belongs to scope
    is_public = Column(Boolean, default=False)
    sensitivity_level = Column(String(20), default='normal')  # normal, sensitive, confidential, restricted

    # Resource access controls
    inheritance_blocked = Column(Boolean, default=False)  # Blocks scope inheritance
    requires_explicit_access = Column(Boolean, default=False)  # Requires explicit permission grants

    # Resource metadata
    metadata = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)  # Array of tags for categorization

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scope = relationship('IAMScope', back_populates='resources')

    def __repr__(self):
        return f"<IAMResource(type={self.resource_type}, id={self.resource_id}, scope={self.scope_id})>"

class IAMAuditLog(Base):
    """IAM Audit Log Model - Tracks all IAM-related actions"""
    __tablename__ = "iam_audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Action details
    actor_id = Column(String, ForeignKey('users.id'), nullable=False)
    action = Column(String(100), nullable=False)  # role_assigned, permission_granted, etc.
    target_type = Column(String(50), nullable=False)  # user, role, permission, policy
    target_id = Column(String, nullable=False)

    # Context information
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)  # Supports IPv6
    user_agent = Column(String(500), nullable=True)
    session_id = Column(String(100), nullable=True)

    # Result and details
    result = Column(String(20), nullable=False)  # success, failure, warning
    details = Column(JSON, nullable=True)  # Additional context data
    error_message = Column(Text, nullable=True)

    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    def __repr__(self):
        return f"<IAMAuditLog(action={self.action}, result={self.result}, timestamp={self.timestamp})>"

class IAMSession(Base):
    """IAM Session Model - Tracks user sessions with role context"""
    __tablename__ = "iam_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.id'), nullable=False)
    session_token = Column(String(500), nullable=False, unique=True)

    # Session properties
    active_roles = Column(JSON, nullable=True)  # List of role IDs active in this session
    permissions_cache = Column(JSON, nullable=True)  # Cached permissions for performance
    session_type = Column(String(50), default='web')  # web, api, mobile, etc.

    # Session metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    device_fingerprint = Column(String(100), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<IAMSession(user_id={self.user_id}, session_type={self.session_type})>"

class IAMRoleRequest(Base):
    """IAM Role Request Model - Tracks role assignment requests"""
    __tablename__ = "iam_role_requests"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Request details
    requester_id = Column(String, ForeignKey('users.id'), nullable=False)
    target_user_id = Column(String, ForeignKey('users.id'), nullable=False)
    role_id = Column(String, ForeignKey('iam_roles.id'), nullable=False)

    # Request properties
    request_type = Column(String(20), nullable=False)  # assign, remove, modify
    justification = Column(Text, nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in days, None for permanent

    # Request status
    status = Column(String(20), default='pending')  # pending, approved, denied, expired
    approved_by = Column(String, ForeignKey('users.id'), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    denial_reason = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<IAMRoleRequest(requester={self.requester_id}, status={self.status})>"

class IAMAccessEvaluation(Base):
    """IAM Access Evaluation Model - Caches and tracks access evaluations for performance"""
    __tablename__ = "iam_access_evaluations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Access request context
    user_id = Column(String, ForeignKey('users.id'), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=False)
    action = Column(String(50), nullable=False)
    scope_id = Column(String, ForeignKey('iam_scopes.id'), nullable=True)

    # Evaluation result
    access_granted = Column(Boolean, nullable=False)
    evaluation_reason = Column(Text, nullable=True)
    applied_roles = Column(JSON, nullable=True)  # List of roles that granted/denied access
    applied_permissions = Column(JSON, nullable=True)  # List of permissions evaluated
    policy_matches = Column(JSON, nullable=True)  # Policy evaluation results

    # Context information
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    session_id = Column(String(100), nullable=True)
    request_metadata = Column(JSON, nullable=True)

    # Caching and performance
    ttl_seconds = Column(Integer, default=300)  # Time to live for cached results
    cache_key = Column(String(500), nullable=False, index=True)

    # Timestamps
    evaluated_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self):
        return f"<IAMAccessEvaluation(user={self.user_id}, action={self.action}, granted={self.access_granted})>"

class IAMContextualRole(Base):
    """IAM Contextual Role Model - Roles that are activated based on context"""
    __tablename__ = "iam_contextual_roles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Role assignment
    user_id = Column(String, ForeignKey('users.id'), nullable=False)
    role_id = Column(String, ForeignKey('iam_roles.id'), nullable=False)
    scope_id = Column(String, ForeignKey('iam_scopes.id'), nullable=True)

    # Activation context
    activation_conditions = Column(JSON, nullable=False)  # When this role becomes active
    priority = Column(Integer, default=0)  # Role priority when multiple roles apply

    # Time-based activation
    active_days = Column(JSON, nullable=True)  # Days of week when role is active
    active_hours = Column(JSON, nullable=True)  # Hours when role is active
    timezone = Column(String(50), nullable=True)

    # Location-based activation
    allowed_ip_ranges = Column(JSON, nullable=True)  # IP ranges where role is active
    allowed_countries = Column(JSON, nullable=True)  # Countries where role is active
    allowed_regions = Column(JSON, nullable=True)  # Geographic regions

    # Status and metadata
    is_active = Column(Boolean, default=True)
    auto_activate = Column(Boolean, default=True)  # Automatically activate when conditions met
    requires_approval = Column(Boolean, default=False)  # Requires approval to activate

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_activated = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<IAMContextualRole(user={self.user_id}, role={self.role_id}, scope={self.scope_id})>"

# Update User model to include IAM relationships (this will be done via migration)
# Note: This would be added to the existing User model in user.py
"""
# Add to User model:
    # IAM Relationships
    iam_roles = relationship('IAMRole', secondary=user_roles_table, back_populates='users')
    scopes = relationship('IAMScope', secondary=user_scopes_table, back_populates='users')
    owned_resources = relationship('IAMResource', foreign_keys=[IAMResource.owner_id])
    audit_logs = relationship('IAMAuditLog', foreign_keys=[IAMAuditLog.actor_id])
    sessions = relationship('IAMSession', foreign_keys=[IAMSession.user_id])
    role_requests_made = relationship('IAMRoleRequest', foreign_keys=[IAMRoleRequest.requester_id])
    role_requests_received = relationship('IAMRoleRequest', foreign_keys=[IAMRoleRequest.target_user_id])
    access_evaluations = relationship('IAMAccessEvaluation', foreign_keys=[IAMAccessEvaluation.user_id])
    contextual_roles = relationship('IAMContextualRole', foreign_keys=[IAMContextualRole.user_id])

    # IAM Helper Methods (to be implemented in service layer)
    def get_effective_permissions(self, scope_id=None, context=None):
        pass  # Returns all effective permissions for user in given scope/context

    def has_permission(self, permission_name, resource_type=None, resource_id=None, scope_id=None):
        pass  # Check if user has specific permission

    def get_accessible_scopes(self, action=None):
        pass  # Get all scopes user has access to for given action

    def can_access_resource(self, resource_type, resource_id, action, context=None):
        pass  # Check if user can perform action on specific resource
"""