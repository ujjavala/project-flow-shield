# 🔐 IAM Features Documentation

## Overview

FlowShield's Identity and Access Management (IAM) system provides enterprise-grade role-based access control with scope-aware permissions, Temporal workflow integration, and comprehensive audit logging.

## 🎯 Key Features

### 1. Role-Based Access Control (RBAC)
- **Hierarchical Roles**: Super Admin → Admin → Manager → Moderator → Analyst → User → Guest
- **Dynamic Role Assignment**: Use Temporal workflows for role assignments with approval processes
- **Role Inheritance**: Higher-level roles inherit permissions from lower-level roles
- **System vs Custom Roles**: System roles are protected, custom roles can be created

### 2. Scope-Based Authorization
- **Hierarchical Scopes**: Organization → Department → Team → Resource
- **Inheritance**: Permissions granted at higher scopes inherit to child scopes
- **Context-Aware**: Permissions evaluated based on user's current scope context
- **Multi-Scope Users**: Users can belong to multiple scopes simultaneously

### 3. Granular Permissions
- **Action-Based**: Create, Read, Update, Delete, Execute permissions per resource type
- **Resource-Specific**: Permissions tied to specific resource types (users, roles, dashboards)
- **Risk-Categorized**: Low, Medium, High, Critical risk levels for permissions
- **Conditional**: Time-based, IP-based, and context-based permission restrictions

### 4. Temporal Workflow Integration
- **Role Assignment Workflows**: Automated approval processes for role changes
- **Permission Evaluation**: Distributed, cached permission checking
- **Access Reviews**: Periodic compliance audits and access reviews
- **Automated Provisioning**: Rule-based role assignments based on user attributes

### 5. Audit & Compliance
- **Complete Audit Trail**: Every IAM action logged with context
- **Compliance Reports**: Pre-built reports for SOX, GDPR, HIPAA compliance
- **Real-time Monitoring**: Live tracking of permission changes and access patterns
- **Forensic Analysis**: Detailed investigation capabilities for security incidents

## 📊 IAM Data Model

### Core Entities

#### Users
- Basic user information (email, name, etc.)
- Legacy role field for backward compatibility
- Dynamic IAM relationships

#### IAM Roles
```sql
- id: Unique identifier
- name: Machine-readable role name
- display_name: Human-readable role name
- scope: Role scope (global, organization, etc.)
- priority: Role precedence (0-10)
- is_system_role: Protected system roles
```

#### IAM Permissions
```sql
- id: Unique identifier
- name: Machine-readable permission name
- category: Permission grouping
- action: Operation type (create, read, update, delete)
- resource_type: Target resource
- risk_level: Security risk assessment
- scope_types: Applicable scope types
```

#### IAM Scopes
```sql
- id: Unique identifier
- name: Scope identifier
- scope_type: Type of scope (org, dept, team)
- parent_scope_id: Hierarchical parent
- hierarchy_path: Full path for quick lookups
- level: Depth in hierarchy
```

### Relationships

#### Many-to-Many Tables
- **user_roles**: Users ↔ Roles with expiration and grants
- **role_permissions**: Roles ↔ Permissions
- **user_scopes**: Users ↔ Scopes for context
- **role_scope_assignments**: Role-Scope combinations per user

## 🔄 Temporal Workflows

### Role Assignment Workflow
```python
@workflow.defn
class IAMRoleAssignmentWorkflow:
    async def assign_role(self, request):
        # 1. Validate assignment request
        # 2. Check approval requirements
        # 3. Request approval if needed
        # 4. Execute role assignment
        # 5. Invalidate permission caches
        # 6. Send notifications
        # 7. Schedule periodic reviews
```

### Permission Evaluation Workflow
```python
@workflow.defn
class IAMPermissionEvaluationWorkflow:
    async def evaluate_permission(self, request):
        # 1. Check permission cache
        # 2. Evaluate direct permissions
        # 3. Evaluate role-based permissions
        # 4. Evaluate scope permissions
        # 5. Check resource ownership
        # 6. Apply policy evaluation
        # 7. Make final decision
        # 8. Cache result
        # 9. Log decision
```

### Access Review Workflow
```python
@workflow.defn
class IAMAccessReviewWorkflow:
    async def conduct_access_review(self, request):
        # 1. Collect user's current access
        # 2. Analyze access patterns
        # 3. Identify potential issues
        # 4. Generate recommendations
        # 5. Create review report
        # 6. Send notifications
```

## 🛡️ Permission Decorators

### Basic Permission Checking
```python
@require_permission("user.read")
async def get_users(iam_context: IAMContext = Depends(get_iam_context)):
    # Function only accessible with user.read permission
    pass

@require_any_permission(["user.read", "user.read_own"])
async def get_user_data(iam_context: IAMContext = Depends(get_iam_context)):
    # Function accessible with either permission
    pass
```

### Resource-Specific Permissions
```python
@require_permission("user.update", resource_type="users", resource_id_param="user_id")
async def update_user(user_id: str, iam_context: IAMContext = Depends(get_iam_context)):
    # Permission checked for specific user resource
    pass
```

### Scope-Aware Permissions
```python
@require_scope_access("scope_id", action="read")
async def get_scope_data(scope_id: str, iam_context: IAMContext = Depends(get_iam_context)):
    # Function requires access to specific scope
    pass
```

### Role-Based Access
```python
@require_role("admin")
async def admin_function(iam_context: IAMContext = Depends(get_iam_context)):
    # Function requires specific role
    pass

@require_any_role(["admin", "manager"])
async def management_function(iam_context: IAMContext = Depends(get_iam_context)):
    # Function requires any of the specified roles
    pass
```

## 🎛️ IAM Management API

### Role Management
```bash
# List all roles
GET /iam/roles

# Create new role
POST /iam/roles
{
  "name": "custom_role",
  "display_name": "Custom Role",
  "description": "Custom role description",
  "scope": "organization",
  "priority": 3
}

# Get role details
GET /iam/roles/{role_id}
```

### Permission Management
```bash
# List all permissions
GET /iam/permissions?category=user_management

# Create new permission
POST /iam/permissions
{
  "name": "resource.action",
  "display_name": "Action Resource",
  "category": "resource_management",
  "action": "action",
  "resource_type": "resource",
  "risk_level": "medium"
}
```

### User Role Assignment
```bash
# Assign role to user (with Temporal workflow)
POST /iam/users/{user_id}/roles
{
  "role_id": "role_uuid",
  "scope_id": "scope_uuid",
  "expires_at": "2024-12-31T23:59:59Z",
  "justification": "Business requirement"
}

# Get user's roles and permissions
GET /iam/users/{user_id}/roles
```

### Permission Checking
```bash
# Check specific permission
POST /iam/check-permission?user_id={user_id}&permission_name=user.read&resource_id={resource_id}
```

### Audit Logging
```bash
# Get audit logs
GET /iam/audit/roles?start_date=2024-01-01&end_date=2024-12-31&action=role_assigned
```

## 🏗️ Bootstrap System

The IAM system includes a comprehensive bootstrap script that creates:

### Default Roles
1. **super_admin** - Full system access
2. **admin** - Administrative access
3. **manager** - Team management
4. **moderator** - Content moderation
5. **analyst** - Analytics access
6. **user** - Standard user
7. **guest** - Limited access

### Default Permissions
- **User Management**: user.create, user.read, user.update, user.delete, user.read_own, user.update_own
- **IAM Management**: iam.roles.create, iam.roles.read, iam.permissions.create, iam.users.assign_roles
- **Dashboard Access**: dashboard.admin.access, dashboard.user.access
- **System Access**: system.admin, system.health.read
- **Content Management**: content.moderate
- **Analytics**: analytics.read

### Default Scopes
- **Organization**: ACME Corporation
- **Departments**: Engineering, Marketing, HR
- **Teams**: Backend Team, Frontend Team

### Test Users
- Complete set of test users for each role level
- Realistic organizational structure
- Pre-configured scope assignments

## 🔄 Integration Guide

### Step 1: Bootstrap IAM System
```bash
curl -X POST http://localhost:8000/bootstrap-iam
```

### Step 2: Implement Permission Decorators
```python
from app.utils.iam_decorators import require_permission, get_iam_context

@app.get("/protected-endpoint")
@require_permission("resource.read")
async def protected_endpoint(iam_context: IAMContext = Depends(get_iam_context)):
    return {"message": "Access granted"}
```

### Step 3: Use IAM Service
```python
from app.services.iam_service import get_iam_service

async def check_user_access(user_id: str, permission: str):
    iam_service = get_iam_service(db)
    result = await iam_service.evaluate_user_permission(
        user_id=user_id,
        permission_name=permission,
        use_temporal=True
    )
    return result['access_granted']
```

### Step 4: Frontend Integration
```javascript
// Check user permissions in React
const hasPermission = (permission) => {
  return user.permissions.includes(permission) || user.role === 'super_admin';
};

// Conditionally render components
{hasPermission('user.create') && <CreateUserButton />}
```

## 📈 Performance Considerations

### Caching Strategy
- **Permission Evaluation Cache**: 5-minute TTL for permission checks
- **Role Assignment Cache**: Invalidated on role changes
- **Scope Hierarchy Cache**: Long-lived, invalidated on structure changes

### Temporal Optimization
- **Batch Operations**: Group multiple role assignments
- **Workflow Timeouts**: Reasonable timeouts for approval processes
- **Activity Timeouts**: Quick fails for database operations

### Database Optimization
- **Indexes**: Optimized queries on user_id, role_id, permission_name
- **Partitioning**: Audit logs partitioned by date
- **Archival**: Old audit data archived to reduce query load

## 🔒 Security Best Practices

### Principle of Least Privilege
- Users granted minimum required permissions
- Regular access reviews to remove unused permissions
- Time-limited role assignments where appropriate

### Defense in Depth
- Multiple layers of authorization checks
- API rate limiting per user role
- Audit logging for all permission changes

### Separation of Duties
- Role assignment requires approval for high-risk roles
- Super admin actions logged and monitored
- Critical operations require multiple approvals

## 🚀 Future Enhancements

### Planned Features
1. **Dynamic Policies** - JSON-based policy engine for complex rules
2. **Just-in-Time Access** - Temporary permission elevation
3. **Risk-Based Authentication** - Permission checks based on risk scoring
4. **External IdP Integration** - SAML/OIDC identity provider support
5. **Mobile Device Management** - Device-based permission restrictions
6. **API Rate Limiting by Role** - Different limits per role level
7. **Workflow Approvals** - Human approval steps in role assignment workflows

### Integration Opportunities
1. **SIEM Integration** - Security Information and Event Management
2. **Compliance Automation** - Automated compliance reporting
3. **ML-Based Access Patterns** - Anomaly detection in access patterns
4. **Zero Trust Architecture** - Continuous verification of access decisions

## 📋 Migration Guide

### From Legacy System
1. **Assess Current Roles** - Map existing roles to new IAM model
2. **Import Users** - Migrate user data with role assignments
3. **Permission Mapping** - Map legacy permissions to new granular system
4. **Gradual Rollout** - Phase migration by user groups
5. **Validation** - Extensive testing of access patterns

### Backward Compatibility
- Legacy role field maintained during transition
- Fallback permission checking for unmigrated endpoints
- Gradual deprecation of old authorization methods

This IAM system provides enterprise-grade access control while maintaining flexibility for future growth and integration needs.