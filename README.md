# 🔐 FlowShield - AI-Powered Authentication Platform

**Production-ready OAuth2 authentication system with Temporal.io workflows, AI fraud detection, and comprehensive IAM (Identity & Access Management).**

## 🚀 Quick Start

```bash
# 1. Start the platform
docker-compose up -d

# 2. Bootstrap IAM system (first time only)
curl -X POST http://localhost:8000/bootstrap-iam

# 3. Access the applications
open http://localhost:3000        # Main Application
open http://localhost:3000/admin/login  # Admin Portal
open http://localhost:8081        # Temporal UI (workflows)
```

## 🔑 Test User Credentials

### 🔴 Super Administrator
- **Email:** `super.admin@temporal-auth.com`
- **Username:** `superadmin`
- **Password:** `SuperAdmin123!`
- **Role:** Super Administrator (All permissions, Global scope)
- **Access:** Full system control, all dashboards, all IAM operations

### 🟠 System Administrator
- **Email:** `admin@temporal-auth.com`
- **Username:** `admin`
- **Password:** `Admin123!`
- **Role:** Administrator (Most admin permissions, Global scope)
- **Access:** User management, role assignment, system monitoring

### 🟡 Team Manager
- **Email:** `manager@temporal-auth.com`
- **Username:** `manager`
- **Password:** `Manager123!`
- **Role:** Manager (Team oversight, Engineering department scope)
- **Access:** Team analytics, user viewing, admin dashboard

### 🟢 Content Moderator
- **Email:** `moderator@temporal-auth.com`
- **Username:** `moderator`
- **Password:** `Moderator123!`
- **Role:** Moderator (Content moderation, Engineering department scope)
- **Access:** Content moderation, user dashboard

### 🔵 Data Analyst
- **Email:** `analyst@temporal-auth.com`
- **Username:** `analyst`
- **Password:** `Analyst123!`
- **Role:** Data Analyst (Analytics access, Marketing department scope)
- **Access:** Analytics dashboard, reporting features

### ⚪ Regular User
- **Email:** `user@temporal-auth.com`
- **Username:** `regularuser`
- **Password:** `User123!`
- **Role:** Standard User (Own profile management, Frontend team scope)
- **Access:** User dashboard, own profile settings

### ⚫ Guest User
- **Email:** `guest@temporal-auth.com`
- **Username:** `guestuser`
- **Password:** `Guest123!`
- **Role:** Guest (Limited read-only, No specific scope)
- **Access:** Basic user dashboard (limited features)

## 📋 Services Overview

| Service | Port | Description |
|---------|------|-------------|
| **Frontend** | 3000 | React app with user/admin interfaces |
| **Backend API** | 8000 | FastAPI with authentication & AI features |
| **Temporal UI** | 8081 | Workflow monitoring dashboard |
| **PostgreSQL** | 5432 | Database (auto-configured) |
| **Redis** | 6379 | Caching & rate limiting |

## ✨ Key Features

### 🔐 Authentication & Security
- **OAuth2 Authentication** - JWT tokens with secure sessions
- **AI Fraud Detection** - Real-time risk scoring with ML models
- **Rate Limiting** - DDoS protection & adaptive API throttling
- **Security Headers** - CSRF, CORS, XSS protection
- **Password Visibility** - User-friendly eye icons on password fields

### 👥 Identity & Access Management (IAM)
- **Role-Based Access Control (RBAC)** - Granular permissions system
- **Scope-Based Authorization** - Hierarchical organizational access
- **Temporal Workflows** - Reliable role assignment & permission evaluation
- **Dynamic Permission Evaluation** - Real-time access control decisions
- **Audit Logging** - Complete activity tracking for compliance
- **Multi-level Roles** - Super Admin → Admin → Manager → User → Guest
- **Scope Hierarchy** - Organization → Department → Team → Resource

### 🎯 Management Dashboards
- **Admin Dashboard** - System monitoring, user management, IAM controls
- **User Dashboard** - Role-specific features, profile management
- **Analytics Dashboard** - Usage metrics, security insights
- **IAM Management UI** - Role/permission assignment, scope management

### 🔄 Workflow Engine
- **Temporal Integration** - Distributed workflow processing
- **Role Assignment Workflows** - Automated approval processes
- **Permission Evaluation** - Cached, high-performance access checks
- **Access Reviews** - Periodic compliance audits
- **Automated Provisioning** - Rule-based role assignments

### 📱 User Experience
- **Responsive Design** - Mobile-friendly interface
- **Real-time Updates** - Live permission changes
- **Context-Aware UI** - Role-specific feature visibility

## 🧪 Testing & API Examples

### Running Tests
```bash
# Frontend tests (26 tests)
cd frontend && npm test -- --watchAll=false

# Backend core tests (29 tests - reliable)
cd backend && PYTHONPATH=. python -m pytest tests/test_pkce_implementation.py tests/test_simple.py -v

# All tests (151 total)
cd backend && PYTHONPATH=. python -m pytest tests/ -v
```

### IAM API Examples
```bash
# 1. Login as admin to get token
curl -X POST http://localhost:8000/user/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@temporal-auth.com", "password": "Admin123!"}'

# 2. List all roles (use token from step 1)
curl -X GET http://localhost:8000/iam/roles \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# 3. Check user permissions
curl -X POST "http://localhost:8000/iam/check-permission?user_id=USER_ID&permission_name=user.read" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# 4. Assign role to user (using Temporal workflow)
curl -X POST http://localhost:8000/iam/users/USER_ID/roles \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"role_id": "ROLE_ID", "scope_id": "SCOPE_ID"}'

# 5. View user's roles and permissions
curl -X GET http://localhost:8000/iam/users/USER_ID/roles \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# 6. Get audit log
curl -X GET "http://localhost:8000/iam/audit/roles?limit=50" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Role Hierarchy Examples
```bash
# Super Admin - Can access everything
curl -X GET http://localhost:8000/iam/roles \
  -H "Authorization: Bearer SUPER_ADMIN_TOKEN"

# Manager - Can view team analytics in Engineering scope
curl -X GET http://localhost:8000/dashboard/activity \
  -H "Authorization: Bearer MANAGER_TOKEN"

# Regular User - Can only access own profile
curl -X GET http://localhost:8000/dashboard/profile \
  -H "Authorization: Bearer USER_TOKEN"
```

## 📚 Documentation

- **[FEATURES.md](./FEATURES.md)** - Complete feature list
- **[AI_AUTH_FEATURES.md](./AI_AUTH_FEATURES.md)** - AI-powered capabilities
- **[GUARDFLOW_FEATURE_DEVELOPMENT_GUIDE.md](./GUARDFLOW_FEATURE_DEVELOPMENT_GUIDE.md)** - Future roadmap
- **[SETUP.md](./SETUP.md)** - Detailed setup instructions
- **[API.md](./API.md)** - API reference

## 🔧 Development

```bash
# Stop services
docker-compose down

# View logs
docker logs oauth2_backend
docker logs oauth2_frontend

# Health check
curl http://localhost:8000/health
```

## 🎯 Production Ready

- ✅ **Docker containerized** - One command deployment
- ✅ **Health checks** - Automatic service monitoring
- ✅ **Database migrations** - Schema auto-initialization
- ✅ **Error handling** - Comprehensive error management
- ✅ **Security headers** - CSRF, CORS, rate limiting
- ✅ **Admin controls** - Full system management

---

**Built with:** FastAPI • React • PostgreSQL • Redis • Temporal.io • Docker

*For detailed setup instructions, see [SETUP.md](./SETUP.md)*