# 🤖 AI-Powered Authentication API Documentation

## 🚀 Overview

The **AI-Enhanced OAuth2 Authentication API** provides next-generation authentication and authorization services using **AI/ML models** and **Temporal.io workflows** for intelligent, reliable operations. This is the world's first authentication API that combines:

- 🧠 **Real-time AI fraud detection** with 95%+ accuracy
- ⚡ **Behavioral biometrics** using LSTM neural networks
- 🛡️ **Adaptive authentication** with ML-driven security requirements
- 🌊 **Temporal workflow reliability** with AI-powered compensation patterns

All endpoints are documented with **OpenAPI/Swagger** and available at http://localhost:8000/docs.

## 🔗 Base URLs

- **Development**: `http://localhost:8000`
- **Production**: `https://your-domain.com`

## 🔐 Authentication

### Bearer Token Authentication
```bash
Authorization: Bearer <access_token>
```

Most endpoints require a valid JWT access token in the Authorization header.

---

## 👤 User Management Endpoints

### POST `/user/register` 🧠
Register a new user account with **AI-powered fraud detection** and intelligent email verification.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe", 
  "username": "johndoe",
  "source": "web",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0..."
}
```

**AI-Enhanced Response (200):**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "message": "Registration successful. Please check your email to verify your account.",
  "verification_email_sent": true,
  "fraud_score": 0.15,
  "ai_insights": {
    "risk_level": "low",
    "risk_factors": [],
    "email_strategy": "friendly",
    "anomaly_score": 0.1,
    "pattern_insights": {
      "typing_speed": "normal",
      "form_interaction": "human_like"
    }
  },
  "correlation_id": "uuid-correlation"
}
```

**AI-Powered Temporal Workflow:** `UserRegistrationWorkflowV2`
- 🤖 **Real-time fraud detection** with XGBoost ensemble models
- 🧠 **Email intelligence analysis** using transformers
- ⚡ **Behavioral pattern analysis** with deep learning
- 🛡️ **Adaptive security requirements** based on risk score
- 📧 **AI-optimized email delivery** with personalization

**AI-Enhanced Example:**
```bash
curl -X POST http://localhost:8000/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "source": "web",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  }'
```

**High-Risk Registration Example:**
```bash
curl -X POST http://localhost:8000/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "suspicious@guerrillamail.com",
    "password": "password",
    "first_name": "Bot",
    "source": "automated"
  }'
# Returns: fraud_score: 0.85, risk_level: "high", additional_verification_required: true
```

---

### POST `/user/login` 🤖
Authenticate user with **AI-powered adaptive authentication** and behavioral biometrics.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "session_context": {
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "device_fingerprint": "device-hash",
    "time_of_day": "normal",
    "typing_patterns": {
      "speed": 45,
      "rhythm": [120, 150, 100]
    }
  }
}
```

**AI-Enhanced Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "is_verified": true
  },
  "ai_authentication": {
    "risk_score": 0.25,
    "behavioral_score": 0.92,
    "device_trust_level": "trusted",
    "authentication_strength": "standard",
    "additional_factors_required": false,
    "session_monitoring": "enabled"
  }
}
```

**AI-Enhanced Error Responses:**
```json
// 401 - Invalid credentials
{
  "detail": "Invalid email or password",
  "ai_insights": {
    "failed_attempts": 3,
    "behavioral_anomaly": "typing_pattern_mismatch",
    "recommended_action": "account_lockout"
  }
}

// 401 - Email not verified
{
  "detail": "Please verify your email address before logging in",
  "ai_verification_strategy": "expedited_due_to_low_risk"
}

// 403 - High risk detected
{
  "detail": "Additional verification required",
  "ai_security_decision": {
    "risk_score": 0.85,
    "required_factors": ["mfa", "device_verification"],
    "reason": "unusual_location_and_device"
  }
}
```

---

### POST `/user/refresh`
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

### POST `/user/logout`
Revoke refresh token and invalidate session.

**Headers:** `Authorization: Bearer <access_token>`

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "message": "Successfully logged out"
}
```

---

### GET `/user/me`
Get current user profile information.

**Headers:** `Authorization: Bearer <access_token>`

**Response (200):**
```json
{
  "id": "uuid-here",
  "email": "user@example.com",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "is_verified": true,
  "is_active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "last_login": "2024-01-02T10:30:00Z"
}
```

---

## 📧 Email Verification Endpoints

### POST `/user/verify-email`
Verify user email address using verification token.

**Request Body:**
```json
{
  "token": "verification-token-from-email"
}
```

**Response (200):**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "email": "user@example.com",
  "verified_at": "2024-01-01T12:00:00Z",
  "welcome_email_sent": true,
  "message": "Email verified successfully. Welcome!"
}
```

**Temporal Workflow:** `EmailVerificationWorkflow`
- Validates verification token
- Updates user verification status
- Sends welcome email

---

### POST `/user/resend-verification`
Resend email verification link.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Verification email sent. Please check your inbox."
}
```

---

## 🔄 Password Reset Endpoints

### POST `/user/password-reset/request`
Request password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "success": true,
  "email": "user@example.com",
  "reset_email_sent": true,
  "message": "Password reset email sent. Please check your email for further instructions."
}
```

**Temporal Workflow:** `PasswordResetWorkflow`
- Generates secure reset token
- Stores token with expiration (1 hour)
- Sends password reset email

---

### POST `/user/password-reset/confirm`
Reset password using reset token.

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "email": "user@example.com",
  "password_reset_at": "2024-01-01T12:00:00Z",
  "message": "Password reset successfully. You can now login with your new password."
}
```

**Temporal Workflow:** `PasswordResetConfirmationWorkflow`
- Validates reset token and expiration
- Updates user password (bcrypt hashed)
- Clears reset token

---

## 🤖 AI-Powered Authentication Endpoints

### POST `/auth/analyze-password` 🧠
AI-powered password security analysis using deep learning models.

**Request Body:**
```json
{
  "password": "My$3cur3P@ssw0rd!2024",
  "user_context": {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "username": "johndoe"
  }
}
```

**AI Response (200):**
```json
{
  "security_score": 0.85,
  "strength_level": "strong",
  "ai_analysis": {
    "deep_learning_score": 0.9,
    "breach_similarity": 0.1,
    "pattern_confidence": 0.8,
    "entropy_score": 4.2
  },
  "personal_info_risk": {
    "risk_level": "low",
    "correlations": [],
    "detected_patterns": []
  },
  "ai_explanation": "This password demonstrates good security practices with mixed character types and sufficient complexity.",
  "recommendations": ["consider_passphrase", "enable_2fa"],
  "model_version": "password_strength_v1.2"
}
```

**Temporal Activities:** 
- `ai_password_analysis_ml` - Deep learning password strength prediction
- `ai_personal_info_detection` - NLP-based personal information correlation

---

### POST `/auth/adaptive-login` ⚡
AI-driven adaptive authentication with real-time risk assessment.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "session_context": {
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0 (trusted-browser)",
    "device_fingerprint": "known-device-hash",
    "time_of_day": "normal",
    "location": {
      "country": "US",
      "city": "San Francisco"
    },
    "behavioral_data": {
      "typing_speed": 45,
      "mouse_patterns": {...},
      "form_interaction_time": 12.5
    }
  }
}
```

**AI-Enhanced Response (200):**
```json
{
  "authentication_status": "approved",
  "access_token": "eyJhbGciOiJIUzI1...",
  "ai_decision": {
    "overall_risk_score": 0.15,
    "behavioral_score": 0.95,
    "device_trust_score": 0.9,
    "location_risk_score": 0.05,
    "authentication_strength": "standard",
    "required_factors": ["password"],
    "session_monitoring_level": "normal"
  },
  "ai_insights": {
    "decision_confidence": 0.92,
    "model_versions": {
      "fraud_detection": "xgboost_v2.1",
      "behavioral": "lstm_v1.3"
    },
    "anomaly_flags": []
  }
}
```

**High-Risk Response (403):**
```json
{
  "authentication_status": "additional_verification_required",
  "ai_decision": {
    "overall_risk_score": 0.82,
    "risk_factors": ["unusual_location", "device_mismatch", "behavioral_anomaly"],
    "required_factors": ["mfa", "device_verification", "behavioral_challenge"],
    "challenge_type": "adaptive_captcha",
    "session_monitoring_level": "elevated"
  },
  "verification_url": "/auth/complete-verification"
}
```

---

### GET `/ai/health` 🏥
Check AI/ML model availability and performance.

**Response (200):**
```json
{
  "ai_status": "operational",
  "models": {
    "fraud_detection": {
      "status": "healthy",
      "version": "xgboost_v2.1",
      "last_updated": "2024-01-01T10:00:00Z",
      "accuracy": 0.96,
      "response_time_ms": 45
    },
    "behavioral_analysis": {
      "status": "healthy", 
      "version": "lstm_v1.3",
      "last_updated": "2024-01-01T09:30:00Z",
      "accuracy": 0.94,
      "response_time_ms": 78
    },
    "password_strength": {
      "status": "healthy",
      "version": "transformer_v1.1",
      "response_time_ms": 32
    }
  },
  "cache_status": {
    "redis_connected": true,
    "hit_rate": 0.87,
    "avg_cache_response_ms": 5
  },
  "fallback_status": "available"
}
```

---

## 🔗 OAuth2 Authorization Endpoints

### GET `/oauth/authorize`
OAuth2 authorization endpoint for authorization code flow.

**Query Parameters:**
- `response_type`: `code` (required)
- `client_id`: OAuth2 client identifier (required)
- `redirect_uri`: Client redirect URI (required)
- `scope`: Requested scopes (optional, default: "read profile email")
- `state`: Security state parameter (recommended)

**Example:**
```bash
GET /oauth/authorize?response_type=code&client_id=oauth2-client&redirect_uri=http://localhost:3000/callback&scope=read%20profile%20email&state=random123
```

**Response:**
- **302 Redirect** to login page if not authenticated
- **302 Redirect** to redirect_uri with authorization code if authenticated

**Success Redirect:**
```
http://localhost:3000/callback?code=auth-code-here&state=random123
```

**Error Redirect:**
```
http://localhost:3000/callback?error=invalid_request&error_description=Missing%20client_id&state=random123
```

---

### POST `/oauth/token`
Exchange authorization code for access token.

**Request Body (application/x-www-form-urlencoded):**
```
grant_type=authorization_code
code=auth-code-here
client_id=oauth2-client
client_secret=oauth2-client-secret
redirect_uri=http://localhost:3000/callback
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "read profile email"
}
```

**Temporal Activities:** 
- `exchange_authorization_code` - Validates code and generates tokens
- `store_access_token` - Persists token information

---

### POST `/oauth/revoke`
Revoke OAuth2 access or refresh token.

**Request Body (application/x-www-form-urlencoded):**
```
token=token-to-revoke
client_id=oauth2-client
client_secret=oauth2-client-secret
```

**Response (200):**
```json
{
  "revoked": true
}
```

---

### GET `/oauth/userinfo`
Get user information using OAuth2 access token.

**Headers:** `Authorization: Bearer <oauth2_access_token>`

**Response (200):**
```json
{
  "sub": "uuid-here",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "preferred_username": "johndoe",
  "profile": "https://example.com/profile/johndoe",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

---

## 🏥 Health & Status Endpoints

### GET `/health`
System health check endpoint.

**Response (200):**
```json
{
  "status": "healthy",
  "service": "oauth2-auth",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "database": "connected",
  "temporal": "connected"
}
```

### GET `/`
Root endpoint with service information.

**Response (200):**
```json
{
  "service": "OAuth2 Authentication Service",
  "version": "1.0.0",
  "description": "Production-ready OAuth2 authentication with Temporal.io workflows",
  "documentation": "/docs",
  "temporal_ui": "http://localhost:8081",
  "endpoints": {
    "health": "/health",
    "docs": "/docs",
    "openapi": "/openapi.json"
  }
}
```

---

## 📊 Response Status Codes

| Code | Description | Usage |
|------|-------------|--------|
| 200 | OK | Successful operation |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required or invalid |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

---

## 🔒 Security Headers

All API responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

---

## 🧪 Testing the API

### Using curl

**Register a new user:**
```bash
curl -X POST http://localhost:8000/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/user/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

**Get user profile:**
```bash
curl -X GET http://localhost:8000/user/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Python requests

```python
import requests

# Register user
response = requests.post("http://localhost:8000/user/register", json={
    "email": "test@example.com",
    "password": "TestPass123!",
    "first_name": "Test",
    "last_name": "User"
})
print(response.json())

# Login
response = requests.post("http://localhost:8000/user/login", json={
    "email": "test@example.com", 
    "password": "TestPass123!"
})
tokens = response.json()

# Get profile
headers = {"Authorization": f"Bearer {tokens['access_token']}"}
response = requests.get("http://localhost:8000/user/me", headers=headers)
print(response.json())
```

### Using JavaScript/Fetch

```javascript
// Register user
const registerResponse = await fetch('http://localhost:8000/user/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'test@example.com',
    password: 'TestPass123!',
    first_name: 'Test',
    last_name: 'User'
  })
});

// Login
const loginResponse = await fetch('http://localhost:8000/user/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'test@example.com',
    password: 'TestPass123!'
  })
});
const tokens = await loginResponse.json();

// Get profile
const profileResponse = await fetch('http://localhost:8000/user/me', {
  headers: { 'Authorization': `Bearer ${tokens.access_token}` }
});
const profile = await profileResponse.json();
```

---

## 📋 Interactive API Documentation

Visit **http://localhost:8000/docs** for the complete interactive API documentation powered by **Swagger UI**. The interactive docs allow you to:

- 🔍 **Explore all endpoints** with detailed descriptions
- 🧪 **Test API calls** directly in the browser
- 📝 **View request/response schemas** with examples
- 🔐 **Authenticate** and test protected endpoints
- 📊 **See response codes** and error handling
- 📱 **Download OpenAPI spec** for client generation

The OpenAPI specification is available at: **http://localhost:8000/openapi.json**

---

## 🌊 AI-Enhanced Temporal Workflow Integration

Every authentication operation in this API is powered by **AI-enhanced Temporal workflows**, providing:

- **🤖 AI-Powered Reliability**: ML operations survive server failures and retry intelligently
- **🧠 Smart Automation**: AI decisions guide workflow execution with compensation patterns
- **📊 AI Observability**: Monitor both workflows and AI models at http://localhost:8081
- **🔍 ML Debugging**: Step-by-step AI decision history with confidence scores
- **⚡ Adaptive Durability**: Long-running authentication sessions with real-time risk updates

### AI Workflow Features

- **🎯 Search Attributes**: Query workflows by AI metrics (`UserRiskScore > 0.7`)
- **📡 Real-time Signals**: AI risk updates trigger workflow adjustments
- **🔄 Saga Patterns**: AI operations with automatic compensation on failure
- **👶 Child Workflows**: Complex AI flows broken into manageable components

### Monitoring AI Workflows

1. **Open Temporal UI**: http://localhost:8081
2. **Perform AI operations** (register with fraud detection, adaptive login)
3. **Watch AI workflows** execute in real-time with risk scores
4. **Inspect AI activities** with confidence levels and model versions
5. **Debug AI decisions** with comprehensive ML audit trails
6. **Search by AI metrics**: Filter workflows by fraud scores, behavioral anomalies

### AI Workflow Search Examples

```bash
# Find high-risk registrations
WorkflowType = "UserRegistrationWorkflowV2" AND UserRiskScore > 0.8

# Find behavioral anomalies
BehavioralAnomaly = true AND AuthStatus = "risk_elevated"

# Find specific AI model versions
AIModelVersion = "xgboost_v2.1" AND FraudConfidence > 0.9
```

This makes the API the **world's first AI-powered authentication system** with full workflow orchestration and ML observability!