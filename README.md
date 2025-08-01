# OAuth2 Authentication System with Temporal.io

A complete OAuth2 authentication system built with **Temporal.io workflows**, **FastAPI**, **React**, **PostgreSQL**, and **Docker**. This project demonstrates modern authentication patterns with reliable, durable workflows for user registration, email verification, and password reset.

## 🚀 Features

### Authentication & Authorization
- **OAuth2 Authorization Code Flow** with PKCE support
- **JWT Access & Refresh Tokens** with automatic refresh
- **Email Verification** via Temporal workflows
- **Password Reset** with secure token-based flow
- **User Registration** with email verification
- **Session Management** with token revocation

### Technical Features
- **Temporal Workflows** for reliable email and auth processes
- **PostgreSQL Database** with proper schema design
- **Docker Containerization** for easy deployment
- **React Frontend** with modern hooks and context
- **FastAPI Backend** with async/await support
- **SMTP Email Integration** with customizable providers
- **Comprehensive Error Handling** and validation
- **Security Best Practices** (password hashing, CORS, etc.)

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   React     │    │   FastAPI   │    │ PostgreSQL  │
│  Frontend   │◄──►│   Backend   │◄──►│  Database   │
└─────────────┘    └─────────────┘    └─────────────┘
                           │
                           ▼
                   ┌─────────────┐    ┌─────────────┐
                   │ Temporal.io │◄──►│    SMTP     │
                   │  Workflows  │    │   Server    │
                   └─────────────┘    └─────────────┘
```

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | FastAPI (Python 3.11+) |
| **Frontend** | React 18 + React Router |
| **Database** | PostgreSQL 15 |
| **Workflows** | Temporal.io |
| **Authentication** | OAuth2 + JWT |
| **Email** | SMTP (Gmail, SendGrid, etc.) |
| **Containerization** | Docker + Docker Compose |
| **State Management** | React Context + Hooks |

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/oauth2-temporal-auth.git
cd oauth2-temporal-auth
```

### 2. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
nano .env
```

### 3. Configure Environment Variables
```bash
# Database
DATABASE_URL=postgresql://oauth2_user:oauth2_password@postgres:5432/oauth2_auth

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Email Configuration (Gmail example)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# OAuth2 Configuration
OAUTH2_CLIENT_ID=oauth2-client
OAUTH2_CLIENT_SECRET=oauth2-client-secret
OAUTH2_REDIRECT_URI=http://localhost:3000/callback

# URLs
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:8000
```

### 4. Launch the Application
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 5. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Temporal UI**: http://localhost:8081
- **PostgreSQL**: localhost:5432

## 📋 Usage Guide

### User Registration Flow
1. Navigate to `/register`
2. Fill in user details
3. Submit registration form
4. **Temporal workflow** creates user and sends verification email
5. Check email and click verification link
6. **Temporal workflow** verifies email and sends welcome email

### Login Flow
1. Navigate to `/login`
2. Enter email and password
3. Receive JWT access and refresh tokens
4. Automatic token refresh on expiry

### Password Reset Flow
1. Click "Forgot Password" on login page
2. Enter email address
3. **Temporal workflow** sends reset email
4. Click reset link in email
5. Enter new password
6. **Temporal workflow** updates password

### OAuth2 Authorization Flow
1. Third-party app redirects to `/oauth/authorize`
2. User logs in and grants permissions
3. Authorization code generated
4. App exchanges code for access token
5. Access protected resources with token

## 🔧 Development

### Running Individual Services

#### Backend Only
```bash
cd backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Only
```bash
cd frontend
npm install
npm start
```

#### Temporal Worker
```bash
cd backend
python worker.py
```

### Database Migrations
```bash
# Access database container
docker-compose exec postgres psql -U oauth2_user -d oauth2_auth

# Or run migrations from backend
docker-compose exec backend python -m app.database.migrations
```

### Testing

#### Backend Tests
```bash
docker-compose exec backend pytest
```

#### Frontend Tests
```bash
docker-compose exec frontend npm test
```

## 📚 API Documentation

### Authentication Endpoints
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Refresh access token
- `POST /auth/password-reset/request` - Request password reset
- `POST /auth/password-reset/confirm` - Confirm password reset
- `POST /auth/verify-email` - Verify email address

### OAuth2 Endpoints
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/authorize` - Handle authorization
- `POST /oauth/token` - Token endpoint
- `POST /oauth/revoke` - Token revocation
- `GET /oauth/userinfo` - User information

### User Endpoints
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update user profile

## 🔒 Security Features

- **Password Hashing** with bcrypt
- **JWT Tokens** with configurable expiration
- **CORS Protection** with whitelist origins
- **Rate Limiting** on authentication endpoints
- **Email Verification** required for account activation
- **Secure Password Reset** with time-limited tokens
- **Token Revocation** support
- **HTTPS Ready** for production deployment
- **SQL Injection Protection** via SQLAlchemy ORM
- **Input Validation** with Pydantic models

## 🌊 Temporal Workflows

### User Registration Workflow
```python
@workflow.defn
class UserRegistrationWorkflow:
    async def run(self, registration_data):
        # Generate verification token
        token = await workflow.execute_activity("generate_verification_token")
        
        # Create user in database
        user = await workflow.execute_activity("create_user", registration_data, token)
        
        # Send verification email
        await workflow.execute_activity("send_verification_email", user.email, token)
        
        return {"success": True, "user_id": user.id}
```

### Password Reset Workflow
```python
@workflow.defn
class PasswordResetWorkflow:
    async def run(self, email):
        # Generate reset token
        token = await workflow.execute_activity("generate_password_reset_token")
        
        # Store reset token
        await workflow.execute_activity("set_password_reset_token", email, token)
        
        # Send reset email
        await workflow.execute_activity("send_password_reset_email", email, token)
        
        return {"success": True}
```

### Email Verification Workflow
```python
@workflow.defn
class EmailVerificationWorkflow:
    async def run(self, verification_token):
        # Verify email
        user = await workflow.execute_activity("verify_user_email", verification_token)
        
        # Send welcome email
        await workflow.execute_activity("send_welcome_email", user.email)
        
        return {"success": True, "user_id": user.id}
```

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP,
    last_login TIMESTAMP
);
```

### OAuth2 Tables
```sql
-- OAuth2 Clients
CREATE TABLE oauth2_clients (
    id VARCHAR PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris JSON NOT NULL,
    grant_types JSON DEFAULT '["authorization_code", "refresh_token"]',
    response_types JSON DEFAULT '["code"]',
    scope VARCHAR(255) DEFAULT 'read write',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Authorization Codes
CREATE TABLE oauth2_authorization_codes (
    id VARCHAR PRIMARY KEY,
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    scope VARCHAR(255),
    state VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Access Tokens
CREATE TABLE oauth2_access_tokens (
    id VARCHAR PRIMARY KEY,
    access_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255),
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR NOT NULL,
    scope VARCHAR(255),
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 🚀 Deployment

### Production Environment Variables
```bash
# Security
JWT_SECRET_KEY=your-production-secret-key-256-bits
OAUTH2_CLIENT_SECRET=your-production-client-secret

# Database
DATABASE_URL=postgresql://user:password@prod-db:5432/oauth2_auth

# Email (SendGrid example)
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=your-sendgrid-api-key

# URLs
FRONTEND_URL=https://yourdomain.com
BACKEND_URL=https://api.yourdomain.com

# SSL/TLS
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

### Docker Production Build
```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Deploy to production
docker-compose -f docker-compose.prod.yml up -d

# Health check
curl https://api.yourdomain.com/health
```

### Kubernetes Deployment
```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oauth2-auth
  template:
    metadata:
      labels:
        app: oauth2-auth
    spec:
      containers:
      - name: backend
        image: oauth2-auth-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: database-url
```

## 🔍 Monitoring & Observability

### Health Checks
- `GET /health` - Application health status
- `GET /health/db` - Database connectivity
- `GET /health/temporal` - Temporal connection status

### Metrics & Logging
- **Structured Logging** with correlation IDs
- **Prometheus Metrics** for monitoring
- **Temporal UI** for workflow observability
- **Database Query Logging** for performance tuning

### Alerting
- Failed authentication attempts
- Email delivery failures
- Database connection issues
- Temporal workflow failures

## 🧪 Testing

### Test Categories
- **Unit Tests** - Individual component testing
- **Integration Tests** - API endpoint testing
- **Workflow Tests** - Temporal workflow testing
- **End-to-End Tests** - Full user journey testing

### Running Tests
```bash
# All tests
docker-compose exec backend pytest

# Unit tests only
docker-compose exec backend pytest tests/unit/

# Integration tests
docker-compose exec backend pytest tests/integration/

# Workflow tests
docker-compose exec backend pytest tests/workflows/

# Frontend tests
docker-compose exec frontend npm test

# E2E tests
docker-compose exec frontend npm run test:e2e
```

## 📈 Performance Optimization

### Backend Optimizations
- **Async/Await** for non-blocking operations
- **Connection Pooling** for database
- **Redis Caching** for session storage
- **Rate Limiting** to prevent abuse
- **Query Optimization** with indexes

### Frontend Optimizations
- **Code Splitting** with React.lazy
- **Memoization** with React.memo
- **Bundle Optimization** with Webpack
- **CDN Integration** for static assets

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Code Style
- **Python**: Follow PEP 8, use Black formatter
- **JavaScript**: Use ESLint and Prettier
- **Commit Messages**: Use conventional commits format

### Pull Request Process
1. Update documentation for any new features
2. Ensure all tests pass
3. Add appropriate labels
4. Request review from maintainers

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Temporal.io** for reliable workflow orchestration
- **FastAPI** for modern Python web framework
- **React** for powerful frontend development
- **PostgreSQL** for robust data storage
- **Docker** for containerization

## 📞 Support

- **Documentation**: Check the `/docs` endpoint
- **Issues**: Use GitHub Issues for bug reports
- **Discussions**: Use GitHub Discussions for questions
- **Email**: support@yourdomain.com

## 🗺️ Roadmap

### Phase 1 (Current)
- ✅ OAuth2 Authorization Code Flow
- ✅ User Registration & Email Verification
- ✅ Password Reset Workflows
- ✅ JWT Token Management

### Phase 2 (Next)
- 🔄 Multi-factor Authentication (MFA)
- 🔄 Social Login Integration (Google, GitHub)
- 🔄 Admin Dashboard
- 🔄 API Rate Limiting Dashboard

### Phase 3 (Future)
- 📋 SAML SSO Support
- 📋 Advanced User Management
- 📋 Audit Logging
- 📋 Compliance Features (GDPR, SOC2)

---

**Built with ❤️ using Temporal.io, FastAPI, React, and PostgreSQL**