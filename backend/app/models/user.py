from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import relationship
from app.database.base import Base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

# Import IAM tables for relationships - this will be available after IAM models are loaded
try:
    from app.models.iam import user_roles_table, user_scopes_table
    _IAM_AVAILABLE = True
except ImportError:
    _IAM_AVAILABLE = False

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    
    # Status flags
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    role = Column(String(20), default='user')  # 'user', 'admin', 'moderator'
    
    # Email verification
    email_verification_token = Column(String(255), nullable=True)
    email_verification_expires = Column(DateTime(timezone=True), nullable=True)
    
    # Password reset
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Profile
    profile_picture = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"

# Add IAM relationships if tables are available
if _IAM_AVAILABLE:
    User.iam_roles = relationship('IAMRole', secondary=user_roles_table, back_populates='users',
                                 foreign_keys=[user_roles_table.c.user_id, user_roles_table.c.role_id])
    User.scopes = relationship('IAMScope', secondary=user_scopes_table, back_populates='users',
                              foreign_keys=[user_scopes_table.c.user_id, user_scopes_table.c.scope_id])

    # IAM Relationships - These will be available after IAM tables are created
    def get_iam_relationships(self):
        """
        Dynamic method to set up IAM relationships after tables are created
        This avoids circular import issues during initial database creation
        """
        try:
            from app.models.iam import (
                user_roles_table, user_scopes_table, IAMRole, IAMScope,
                IAMResource, IAMAuditLog, IAMSession, IAMRoleRequest,
                IAMAccessEvaluation, IAMContextualRole
            )

            # Add relationships dynamically if not already present
            if not hasattr(self, 'iam_roles'):
                self.iam_roles = relationship('IAMRole', secondary=user_roles_table, back_populates='users')
            if not hasattr(self, 'scopes'):
                self.scopes = relationship('IAMScope', secondary=user_scopes_table, back_populates='users')
            if not hasattr(self, 'owned_resources'):
                self.owned_resources = relationship('IAMResource', foreign_keys=[IAMResource.owner_id])
            if not hasattr(self, 'audit_logs'):
                self.audit_logs = relationship('IAMAuditLog', foreign_keys=[IAMAuditLog.actor_id])
            if not hasattr(self, 'sessions'):
                self.sessions = relationship('IAMSession', foreign_keys=[IAMSession.user_id])

        except ImportError:
            # IAM models not available yet
            pass

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        try:
            return any(
                role.name == role_name and role.is_active
                for role in getattr(self, 'iam_roles', [])
            )
        except:
            # Fallback to basic role check
            return self.role == role_name

    def get_effective_permissions(self) -> list:
        """Get all effective permissions for this user"""
        permissions = set()
        try:
            for role in getattr(self, 'iam_roles', []):
                if role.is_active:
                    for permission in getattr(role, 'permissions', []):
                        if permission.is_active:
                            permissions.add(permission.name)
        except:
            # Fallback for basic permissions
            if self.is_superuser:
                permissions.add('*')  # Super admin has all permissions
            elif self.role == 'admin':
                permissions.update([
                    'user.read', 'user.create', 'user.update',
                    'admin.dashboard', 'system.manage'
                ])
            elif self.role == 'moderator':
                permissions.update(['user.read', 'content.moderate'])
            else:
                permissions.update(['user.read_own', 'user.update_own'])

        return list(permissions)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_revoked = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id})>"