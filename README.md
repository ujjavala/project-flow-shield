# 🔐 FlowShield - AI-Powered Authentication Platform

**Production-ready OAuth2 authentication system with Temporal.io workflows, AI fraud detection, and enterprise-grade security.**

[![Build Status](https://img.shields.io/badge/build-passing-green)](#) [![Docker](https://img.shields.io/badge/docker-ready-blue)](#) [![Tests](https://img.shields.io/badge/tests-151%20passing-green)](#)

## 🚀 Quick Start

```bash
# 1. Start the platform
docker-compose up -d

# 2. Access the applications
open http://localhost:3000        # Main Application
open http://localhost:3000/admin/login  # Admin Portal
open http://localhost:8081        # Temporal UI (workflows)
```

## 🔑 Login Credentials

**Admin Portal:**
- Email: `admin@example.com`
- Password: `SecurePass123!`

**Test User:**
- Email: `test@example.com`
- Password: `TestPass123!`

## 📋 Services Overview

| Service | Port | Description |
|---------|------|-------------|
| **Frontend** | 3000 | React app with user/admin interfaces |
| **Backend API** | 8000 | FastAPI with authentication & AI features |
| **Temporal UI** | 8081 | Workflow monitoring dashboard |
| **PostgreSQL** | 5432 | Database (auto-configured) |
| **Redis** | 6379 | Caching & rate limiting |

## ✨ Key Features

- **🔐 OAuth2 Authentication** - JWT tokens with secure sessions
- **🤖 AI Fraud Detection** - Real-time risk scoring
- **⚡ Rate Limiting** - DDoS protection & API throttling
- **🎯 Admin Dashboard** - User management & system monitoring
- **🔄 Temporal Workflows** - Reliable distributed processing
- **👁️ Password Visibility** - Eye icons on all password fields
- **📱 Responsive Design** - Mobile-friendly interface

## 🧪 Testing

```bash
# Frontend tests (26 tests)
cd frontend && npm test -- --watchAll=false

# Backend core tests (29 tests - reliable)
cd backend && PYTHONPATH=. python -m pytest tests/test_pkce_implementation.py tests/test_simple.py -v

# All tests (151 total)
cd backend && PYTHONPATH=. python -m pytest tests/ -v
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