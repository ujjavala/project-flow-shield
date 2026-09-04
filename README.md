# FlowShield - AI-Powered Authentication Platform

**OAuth 2.1/OIDC authentication platform with durable Temporal identity operations, explainable risk policy, strong authentication, and comprehensive IAM.**

## Quick Start

### One-command local platform (recommended)
```bash
make demo
```

This builds and waits for the complete local stack, applies schema changes, and idempotently seeds the documented users, IAM roles/scopes, and public PKCE client. No post-start bootstrap command is required.

Optional local Ollama profile:

```bash
make demo-ai
```

See [LOCAL_DEMO.md](./LOCAL_DEMO.md) for URLs, personas, operational checks, the local-only security-lab boundary, and limitations.
See [AI_SDLC.md](./AI_SDLC.md) for model boundaries, versioned evaluation artifacts, release gates, monitoring, and rollback.

### Access the Applications
```bash
open http://localhost:3000        # User Dashboard
open http://localhost:3000/admin/login  # Admin Portal
open http://localhost:8081        # Temporal UI (workflows)
```

All demo accounts are available after the Compose health checks pass. Their random per-install passwords are stored only in a Docker volume. Display them explicitly when needed with `make demo-credentials`; do not copy the output into source files or logs.

## Demo Personas

> **Dashboard Access Summary:**
> - **Admin Dashboard** (http://localhost:3000/admin/login): Super Admin, Manager, Moderator
> - **User Dashboard** (http://localhost:3000): All users including admins

| Persona | Email | Dashboard | Scope |
| --- | --- | --- | --- |
| Super administrator | `super.admin@temporal-auth.com` | Admin | Global |
| Administrator | `admin@temporal-auth.com` | Admin | ACME Corp |
| Team manager | `manager@temporal-auth.com` | Admin | Engineering |
| Content moderator | `moderator@temporal-auth.com` | Admin | Engineering |
| Data analyst | `analyst@temporal-auth.com` | User | Marketing |
| Regular user | `user@temporal-auth.com` | User | Frontend Team |
| Unverified guest | `guest@temporal-auth.com` | User | None |

> **Note:** The Compose migration job creates or reconciles all users above, their IAM assignments, generated passwords, and the local OAuth client idempotently.

## Services Overview

| Service | Port | Description |
|---------|------|-------------|
| **Frontend** | 3000 | React app with user/admin interfaces |
| **Backend API** | 8000 | FastAPI with authentication & AI features |
| **Temporal UI** | 8081 | Workflow monitoring dashboard |
| **PostgreSQL** | Internal only | Database (auto-configured) |
| **Redis** | Internal only | Caching & rate limiting |
| **Mailpit** | 8025 | Local authentication-email inbox |
| **Prometheus** | 9090 | Local metrics and target health |
| **Grafana** | 3001 | Provisioned FlowShield API dashboard |
| **OTel Collector** | 4317/4318 | OTLP trace and metric ingestion |
| **Ollama** | 11434 | Optional local AI profile |

## Key Features

### Authentication & Security
- **OAuth2 Authentication** - JWT tokens with secure sessions
- **Explainable Risk Decisions** - Versioned deterministic policy with reason codes and contribution scores
- **Optional AI Shadow Scoring** - Local Ollama output is observable but cannot override the authoritative policy
- **Security Lab** - Bounded, deterministic, local-only attack simulations with tamper-evident evidence digests
- **Rate Limiting** - DDoS protection & adaptive API throttling
- **Security Headers** - CSRF, CORS, XSS protection
- **Docker-Isolated Security Testing** - Safe attack simulation environments
- **Password Visibility** - User-friendly eye icons on password fields

### Identity & Access Management (IAM)
- **Role-Based Access Control (RBAC)** - Granular permissions system
- **Scope-Based Authorization** - Hierarchical organizational access
- **Temporal Workflows** - Reliable role assignment & permission evaluation
- **Dynamic Permission Evaluation** - Real-time access control decisions
- **Audit Logging** - Complete activity tracking for compliance
- **Multi-level Roles** - Super Admin → Admin → Manager → User → Guest
- **Scope Hierarchy** - Organization → Department → Team → Resource

### Management Dashboards
- **Enhanced Admin Dashboard** - Fancy UI with advanced animations, system monitoring, predictive attack controls
- **Enhanced User Dashboard** - Modern glassmorphism design with real-time metrics and particle effects
- **Predictive Attack Dashboard** - Real-time security simulation monitoring and control center
- **Analytics Dashboard** - Advanced behavioral analytics with AI-powered insights
- **IAM Management UI** - Role/permission assignment, scope management

### Workflow Engine
- **Temporal Integration** - Distributed workflow processing
- **Role Assignment Workflows** - Automated approval processes
- **Permission Evaluation** - Cached, high-performance access checks
- **Access Reviews** - Periodic compliance audits
- **Automated Provisioning** - Rule-based role assignments

### User Experience
- **Responsive Design** - Mobile-friendly interface
- **Real-time Updates** - Live permission changes
- **Context-Aware UI** - Role-specific feature visibility

## Testing & API Examples

### Running Tests
```bash
# Focused backend and frontend merge-gate suites
make test

# Run either suite independently
make test-backend
make test-frontend

# Full suite, including legacy compatibility tests
cd backend && PYTHONPATH=. python -m pytest tests/ -v
```

The focused suite is the merge gate. Some legacy compatibility tests still use outdated dependency overrides and are tracked separately; the heavyweight historical ML workflow tests require the optional AI dependencies.

### IAM API Examples
```bash
# First retrieve the generated local credential file interactively
make demo-credentials

# Browser clients authenticate through the HttpOnly BFF session
open http://localhost:3000/admin/login

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

## Documentation

- **[MODERNIZATION_ROADMAP.md](./MODERNIZATION_ROADMAP.md)** - Evidence-based implementation status and phased delivery plan
- **[FEATURES.md](./FEATURES.md)** - Complete feature list
- **[AI_AUTH_FEATURES.md](./AI_AUTH_FEATURES.md)** - AI-powered capabilities
- **[GUARDFLOW_FEATURE_DEVELOPMENT_GUIDE.md](./GUARDFLOW_FEATURE_DEVELOPMENT_GUIDE.md)** - Future roadmap
- **[SETUP.md](./SETUP.md)** - Detailed setup instructions
- **[API.md](./API.md)** - API reference

## Development

```bash
# Stop services
make down

# View logs
make logs

# Health check
curl --fail http://localhost:8000/health/ready
```

## Current Platform Capabilities

These capabilities exist in the project, but production readiness still depends on completing the security, testing, observability, and delivery work in the modernization roadmap.

- Implemented: **Docker containerized** - One command deployment
- Implemented: **Health checks** - Automatic service monitoring
- Implemented: **Database migrations** - Schema auto-initialization
- Implemented: **Error handling** - Comprehensive error management
- Implemented: **Security headers** - CSRF, CORS, rate limiting
- Implemented: **Admin controls** - Full system management

---

**Built with:** FastAPI • React • PostgreSQL • Redis • Temporal.io • Docker

*For detailed setup instructions, see [SETUP.md](./SETUP.md)*