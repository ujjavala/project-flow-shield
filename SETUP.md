# OAuth2 Authentication System Setup Guide

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git (for cloning)

### 1. Clone and Setup Environment
```bash
git clone <repository-url>
cd temporal-auth-demo

# Copy environment template
cp .env.example .env

# Edit .env file with your settings (optional for demo)
nano .env
```

### 2. Start the System
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 3. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Temporal UI**: http://localhost:8081

## 📋 Testing the Complete Auth Workflow

### 1. User Registration with Email Verification
1. Navigate to http://localhost:3000
2. Click "Sign up here"
3. Fill in the registration form:
   - First Name: "John"
   - Last Name: "Doe"
   - Email: "john@example.com"
   - Password: "SecurePass123!"
4. Submit the form
5. **Temporal Workflow**: Check Temporal UI at http://localhost:8081 to see the UserRegistrationWorkflow running
6. **Email**: Check the backend logs for the email verification link (in production, this would be sent via SMTP)

### 2. Email Verification Process
1. Find the verification link in the backend logs
2. Visit the verification link
3. **Temporal Workflow**: The EmailVerificationWorkflow will run automatically
4. You should see "Email verified successfully!" message

### 3. User Login
1. Go back to http://localhost:3000/login
2. Use the credentials from registration:
   - Email: "john@example.com"
   - Password: "SecurePass123!"
3. Click "Sign In"
4. You'll be redirected to the dashboard

### 4. Dashboard Features
The dashboard shows:
- User profile information
- OAuth2 system details
- Authentication method (OAuth2 with Temporal workflows)
- System features overview

### 5. Password Reset Flow
1. On login page, click "Forgot your password?"
2. Enter your email address
3. **Temporal Workflow**: PasswordResetWorkflow executes
4. Check backend logs for the reset link
5. Visit the reset link and set a new password
6. **Temporal Workflow**: PasswordResetConfirmationWorkflow completes the process

### 6. OAuth2 Authorization Flow
Test the OAuth2 server functionality:

```bash
# 1. Get authorization code
curl -X GET "http://localhost:8000/oauth/authorize?response_type=code&client_id=oauth2-client&redirect_uri=http://localhost:3000/callback&scope=read%20profile%20email&state=random123"

# 2. Exchange code for tokens (replace CODE with actual code)
curl -X POST "http://localhost:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=CODE&client_id=oauth2-client&client_secret=oauth2-client-secret&redirect_uri=http://localhost:3000/callback"

# 3. Access user info (replace TOKEN with access token)
curl -X GET "http://localhost:8000/oauth/userinfo" \
  -H "Authorization: Bearer TOKEN"
```

## 🔧 Development

### Running Individual Services

#### Backend Only
```bash
cd backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start PostgreSQL and Temporal first
docker-compose up -d postgres temporal

# Run backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Temporal Worker
```bash
cd backend
source venv/bin/activate
python worker.py
```

#### Frontend Only
```bash
cd frontend
npm install
npm start
```

### Environment Configuration

Key environment variables in `.env`:

```bash
# Database
DATABASE_URL=postgresql://oauth2_user:oauth2_password@localhost:5432/oauth2_auth

# JWT Secrets (change in production!)
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production

# Email Settings
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## 🌊 Temporal Workflows in Action

This system demonstrates several Temporal workflows:

### 1. User Registration Workflow
- **Trigger**: User submits registration form
- **Activities**: 
  - Generate verification token
  - Create user in database
  - Send verification email
- **Reliability**: Automatic retries, durable execution

### 2. Email Verification Workflow
- **Trigger**: User clicks verification link
- **Activities**:
  - Verify email token
  - Update user status
  - Send welcome email
- **Reliability**: Ensures email verification completes even if interrupted

### 3. Password Reset Workflow
- **Trigger**: User requests password reset
- **Activities**:
  - Generate reset token
  - Store token with expiry
  - Send reset email
- **Reliability**: Handles email delivery failures gracefully

### 4. Password Reset Confirmation Workflow
- **Trigger**: User submits new password
- **Activities**:
  - Validate reset token
  - Update password
  - Clear reset token
- **Reliability**: Atomic password update process

## 🔍 Monitoring

### Temporal UI
Access http://localhost:8081 to:
- View workflow executions
- Monitor activity success/failure
- See workflow history and details
- Debug workflow issues

### Application Logs
```bash
# View all services
docker-compose logs -f

# View specific service
docker-compose logs -f backend
docker-compose logs -f worker
docker-compose logs -f frontend
```

### Health Checks
- Backend: http://localhost:8000/health
- Temporal connection: Check worker logs
- Database: Check postgres logs

## 🚨 Troubleshooting

### Common Issues

#### "Backend is currently offline"
- Check if backend container is running: `docker-compose ps`
- Check backend logs: `docker-compose logs backend`
- Verify environment variables in `.env`

#### Email not being sent
- Check SMTP settings in `.env`
- For demo purposes, check backend logs for email content
- Ensure Temporal worker is running

#### Temporal workflows not executing
- Check if Temporal server is running: `docker-compose ps temporal`
- Check worker logs: `docker-compose logs worker`
- Verify Temporal connection in backend logs

#### Database connection issues
- Check if PostgreSQL is running: `docker-compose ps postgres`
- Verify DATABASE_URL in `.env`
- Check postgres logs: `docker-compose logs postgres`

### Reset Everything
```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Rebuild and start
docker-compose up -d --build
```

## 🎯 Production Considerations

1. **Security**:
   - Change all default secrets in `.env`
   - Use proper HTTPS certificates
   - Configure CORS properly
   - Enable rate limiting

2. **Email**:
   - Configure proper SMTP provider (SendGrid, AWS SES, etc.)
   - Set up email templates
   - Configure email analytics

3. **Database**:
   - Use managed PostgreSQL service
   - Set up backups
   - Configure connection pooling

4. **Temporal**:
   - Use Temporal Cloud or self-hosted cluster
   - Set up monitoring and alerting
   - Configure retention policies

5. **Deployment**:
   - Use container orchestration (Kubernetes, Docker Swarm)
   - Set up CI/CD pipelines
   - Configure health checks and monitoring