#!/usr/bin/env python3
"""
Pure Temporal-Powered Backend with AI Enhancement
Everything runs through Temporal workflows - no database needed
"""

import asyncio
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import uuid
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio import workflow, activity
from temporalio.common import RetryPolicy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Pure Temporal AI Auth Server")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
temporal_client = None

# Pydantic Models
class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

# In-memory storage powered by Temporal workflows (no database!)
temporal_user_store = {}

# ====================
# TEMPORAL WORKFLOWS
# ====================

@workflow.defn
class AIAuthenticationWorkflow:
    """AI-Enhanced Authentication Workflow"""
    
    @workflow.run
    async def run(self, email: str, password: str, device_info: dict = None) -> dict:
        workflow.logger.info(f"🤖 Starting AI-enhanced authentication for {email}")
        
        try:
            # Step 1: AI Risk Assessment
            risk_analysis = await workflow.execute_activity(
                ai_risk_assessment,
                args=[email, device_info or {}],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            # Step 2: User Authentication
            auth_result = await workflow.execute_activity(
                authenticate_user_temporal,
                args=[email, password],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            if not auth_result["success"]:
                # Log failed attempt with AI context
                await workflow.execute_activity(
                    ai_log_security_event,
                    args=["failed_login", email, risk_analysis],
                    start_to_close_timeout=timedelta(seconds=5)
                )
                return auth_result
            
            # Step 3: AI-Enhanced Token Generation
            token_result = await workflow.execute_activity(
                ai_generate_smart_tokens,
                args=[auth_result["user_id"], email, risk_analysis],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            # Step 4: Real-time Security Monitoring
            await workflow.execute_activity(
                ai_monitor_session,
                args=[auth_result["user_id"], risk_analysis],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            workflow.logger.info(f"✅ AI-enhanced authentication successful for {email}")
            
            return {
                "success": True,
                "access_token": token_result["access_token"],
                "refresh_token": token_result["refresh_token"],
                "expires_in": token_result["expires_in"],
                "ai_risk_score": risk_analysis["risk_score"],
                "ai_confidence": risk_analysis["confidence"],
                "method": "temporal_ai_workflow"
            }
            
        except Exception as e:
            workflow.logger.error(f"❌ AI authentication failed for {email}: {e}")
            return {
                "success": False,
                "error": str(e),
                "method": "temporal_ai_workflow"
            }

@workflow.defn
class SmartRegistrationWorkflow:
    """AI-Enhanced Registration with Fraud Detection"""
    
    @workflow.run
    async def run(self, email: str, password: str, first_name: str = None, last_name: str = None, metadata: dict = None) -> dict:
        workflow.logger.info(f"🧠 Starting smart registration for {email}")
        
        try:
            # Step 1: AI Fraud Detection
            fraud_check = await workflow.execute_activity(
                ai_fraud_detection,
                args=[email, first_name, last_name, metadata or {}],
                start_to_close_timeout=timedelta(seconds=10)
            )
            
            if fraud_check["is_suspicious"]:
                workflow.logger.warning(f"⚠️ Suspicious registration attempt: {email}")
                return {
                    "success": False,
                    "error": "Registration requires additional verification",
                    "fraud_score": fraud_check["fraud_score"],
                    "method": "temporal_ai_workflow"
                }
            
            # Step 2: Check User Existence (Temporal-powered)
            existence_check = await workflow.execute_activity(
                check_user_exists_temporal,
                args=[email],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            if existence_check["exists"]:
                return {
                    "success": False,
                    "error": "User already exists",
                    "method": "temporal_ai_workflow"
                }
            
            # Step 3: AI-Enhanced User Creation
            user_result = await workflow.execute_activity(
                ai_create_smart_user,
                args=[email, password, first_name, last_name, fraud_check],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            # Step 4: Smart Welcome & Onboarding
            await workflow.execute_activity(
                ai_smart_onboarding,
                args=[email, user_result["user_id"], fraud_check["user_profile"]],
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            workflow.logger.info(f"✅ Smart registration completed for {email}")
            
            return {
                "success": True,
                "user_id": user_result["user_id"],
                "email": email,
                "message": "Smart registration successful",
                "ai_profile": fraud_check["user_profile"],
                "trust_score": fraud_check["trust_score"],
                "method": "temporal_ai_workflow"
            }
            
        except Exception as e:
            workflow.logger.error(f"❌ Smart registration failed for {email}: {e}")
            return {
                "success": False,
                "error": str(e),
                "method": "temporal_ai_workflow"
            }

@workflow.defn
class ContinuousAIMonitoringWorkflow:
    """Continuous AI-powered security monitoring"""
    
    @workflow.run
    async def run(self, user_id: str, initial_risk: dict) -> dict:
        workflow.logger.info(f"🔍 Starting continuous AI monitoring for user {user_id}")
        
        # Monitor for 1 hour with AI analysis every 5 minutes
        for i in range(12):  # 12 * 5 minutes = 1 hour
            await asyncio.sleep(300)  # 5 minutes
            
            # AI behavioral analysis
            analysis = await workflow.execute_activity(
                ai_behavioral_analysis,
                args=[user_id, i * 5],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            if analysis["threat_detected"]:
                # Immediate security response
                await workflow.execute_activity(
                    ai_security_response,
                    args=[user_id, analysis],
                    start_to_close_timeout=timedelta(seconds=10)
                )
                
                workflow.logger.warning(f"🚨 Threat detected for user {user_id}")
                break
        
        return {"monitoring_completed": True, "duration_minutes": (i + 1) * 5}

# ====================
# TEMPORAL ACTIVITIES
# ====================

@activity.defn
async def ai_risk_assessment(email: str, device_info: dict) -> dict:
    """AI-powered risk assessment"""
    activity.logger.info(f"🤖 Analyzing risk for {email}")
    
    # Simulate AI risk analysis
    risk_factors = []
    
    # Check email patterns
    if ".temp" in email or "+" in email:
        risk_factors.append("temporary_email")
    
    # Device analysis
    if device_info.get("new_device", False):
        risk_factors.append("new_device")
    
    # Time-based analysis
    current_hour = datetime.now().hour
    if current_hour < 6 or current_hour > 22:
        risk_factors.append("unusual_time")
    
    # Calculate AI risk score
    base_risk = 0.1
    risk_score = min(base_risk + (len(risk_factors) * 0.2), 1.0)
    
    return {
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "confidence": 0.85 + random.uniform(0, 0.15),
        "recommendation": "allow" if risk_score < 0.5 else "monitor"
    }

@activity.defn
async def authenticate_user_temporal(email: str, password: str) -> dict:
    """Temporal-powered user authentication (no database)"""
    activity.logger.info(f"🔐 Authenticating {email} via Temporal")
    
    # Default test user (in real system, this would be in Temporal workflows/activities)
    if email == "test@example.com" and password == "password123":
        return {
            "success": True,
            "user_id": "temporal_user_123",
            "email": email
        }
    
    # Check Temporal user store
    if email in temporal_user_store:
        user = temporal_user_store[email]
        if user["password"] == password:
            return {
                "success": True,
                "user_id": user["user_id"],
                "email": email
            }
    
    return {"success": False, "error": "Invalid credentials"}

@activity.defn
async def ai_generate_smart_tokens(user_id: str, email: str, risk_analysis: dict) -> dict:
    """AI-enhanced smart token generation"""
    activity.logger.info(f"🎟️ Generating smart tokens for {email}")
    
    # Adjust token expiry based on risk
    base_expiry = 3600  # 1 hour
    risk_multiplier = 1.0 - risk_analysis["risk_score"]
    smart_expiry = int(base_expiry * risk_multiplier)
    
    # Generate AI-enhanced tokens
    access_token = f"temporal_ai_access_{uuid.uuid4().hex[:12]}"
    refresh_token = f"temporal_ai_refresh_{uuid.uuid4().hex[:12]}"
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": max(smart_expiry, 1800),  # Minimum 30 minutes
        "token_type": "ai_enhanced"
    }

@activity.defn
async def ai_monitor_session(user_id: str, risk_analysis: dict):
    """Start AI session monitoring"""
    activity.logger.info(f"👁️ Starting AI monitoring for {user_id}")
    
    # In a real system, this would trigger the monitoring workflow
    # For demo, we'll log the monitoring start
    activity.logger.info(f"Session monitoring active for {user_id} with risk score: {risk_analysis['risk_score']}")

@activity.defn
async def ai_log_security_event(event_type: str, email: str, risk_context: dict):
    """Log security events with AI context"""
    activity.logger.info(f"📝 Logging security event: {event_type} for {email}")
    
    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "email": email,
        "risk_context": risk_context
    }
    
    # In production, this would be sent to security monitoring systems
    activity.logger.warning(f"SECURITY EVENT: {json.dumps(event)}")

@activity.defn
async def ai_fraud_detection(email: str, first_name: str, last_name: str, metadata: dict) -> dict:
    """AI-powered fraud detection for registration"""
    activity.logger.info(f"🕵️ Running fraud detection for {email}")
    
    suspicion_score = 0.0
    fraud_indicators = []
    
    # Email analysis
    if not first_name or not last_name:
        suspicion_score += 0.2
        fraud_indicators.append("incomplete_profile")
    
    if len(email.split("@")[0]) < 3:
        suspicion_score += 0.3
        fraud_indicators.append("suspicious_email")
    
    # Generate user profile insights
    user_profile = {
        "estimated_age": random.randint(20, 60),
        "likely_location": "Unknown",
        "account_purpose": "personal" if suspicion_score < 0.3 else "uncertain"
    }
    
    return {
        "is_suspicious": suspicion_score > 0.5,
        "fraud_score": suspicion_score,
        "fraud_indicators": fraud_indicators,
        "trust_score": 1.0 - suspicion_score,
        "user_profile": user_profile
    }

@activity.defn
async def check_user_exists_temporal(email: str) -> dict:
    """Check user existence in Temporal store"""
    activity.logger.info(f"🔍 Checking if user exists: {email}")
    
    exists = email in temporal_user_store or email == "test@example.com"
    return {"exists": exists}

@activity.defn
async def ai_create_smart_user(email: str, password: str, first_name: str, last_name: str, ai_context: dict) -> dict:
    """AI-enhanced user creation"""
    activity.logger.info(f"👤 Creating smart user: {email}")
    
    user_id = f"temporal_ai_user_{uuid.uuid4().hex[:8]}"
    
    # Store in Temporal memory (no database!)
    temporal_user_store[email] = {
        "user_id": user_id,
        "email": email,
        "password": password,  # In real system, would be hashed
        "first_name": first_name,
        "last_name": last_name,
        "created_at": datetime.now().isoformat(),
        "ai_profile": ai_context["user_profile"],
        "trust_score": ai_context["trust_score"]
    }
    
    return {"user_id": user_id, "email": email}

@activity.defn
async def ai_smart_onboarding(email: str, user_id: str, ai_profile: dict):
    """AI-powered smart onboarding"""
    activity.logger.info(f"🎓 Starting smart onboarding for {email}")
    
    # Personalized onboarding based on AI profile
    onboarding_plan = []
    
    if ai_profile["account_purpose"] == "personal":
        onboarding_plan = ["welcome_tour", "security_setup", "preferences"]
    else:
        onboarding_plan = ["verification", "extended_welcome", "security_audit"]
    
    activity.logger.info(f"Onboarding plan for {email}: {onboarding_plan}")

@activity.defn
async def ai_behavioral_analysis(user_id: str, session_duration: int) -> dict:
    """AI behavioral analysis during session"""
    activity.logger.info(f"🧠 Analyzing behavior for user {user_id} at {session_duration}min")
    
    # Simulate behavioral analysis
    threat_probability = random.uniform(0, 0.1)  # Usually low
    
    return {
        "threat_detected": threat_probability > 0.08,
        "threat_probability": threat_probability,
        "behavioral_score": 1.0 - threat_probability,
        "session_duration": session_duration
    }

@activity.defn
async def ai_security_response(user_id: str, threat_analysis: dict):
    """AI-driven security response"""
    activity.logger.warning(f"🚨 Executing security response for {user_id}")
    
    response_actions = ["alert_admin", "require_mfa", "limit_permissions"]
    activity.logger.warning(f"Security actions: {response_actions}")

# ====================
# FASTAPI SETUP
# ====================

async def init_temporal():
    """Initialize Temporal client and worker"""
    global temporal_client
    
    try:
        temporal_client = await Client.connect("localhost:7233")
        logger.info("🚀 Connected to Temporal server")
        
        # Start worker in background
        asyncio.create_task(start_temporal_worker())
        return True
    except Exception as e:
        logger.error(f"❌ Failed to connect to Temporal: {e}")
        return False

async def start_temporal_worker():
    """Start Temporal worker with all workflows and activities"""
    try:
        worker = Worker(
            temporal_client,
            task_queue="ai-auth-queue",
            workflows=[
                AIAuthenticationWorkflow,
                SmartRegistrationWorkflow,
                ContinuousAIMonitoringWorkflow
            ],
            activities=[
                ai_risk_assessment,
                authenticate_user_temporal,
                ai_generate_smart_tokens,
                ai_monitor_session,
                ai_log_security_event,
                ai_fraud_detection,
                check_user_exists_temporal,
                ai_create_smart_user,
                ai_smart_onboarding,
                ai_behavioral_analysis,
                ai_security_response
            ]
        )
        
        logger.info("🔧 Starting Temporal AI worker...")
        await worker.run()
    except Exception as e:
        logger.error(f"❌ Worker failed: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    await init_temporal()

# ====================
# API ENDPOINTS
# ====================

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "temporal-ai-auth-server",
        "temporal_connected": temporal_client is not None,
        "ai_enabled": True,
        "database_free": True
    }

@app.post("/user/login", response_model=TokenResponse)
async def ai_login(user_data: UserLogin):
    """AI-Enhanced Login - Pure Temporal Power"""
    
    if not temporal_client:
        raise HTTPException(status_code=503, detail="Temporal AI service unavailable")
    
    try:
        workflow_id = f"ai-login-{user_data.email}-{uuid.uuid4().hex[:6]}"
        
        result = await temporal_client.execute_workflow(
            AIAuthenticationWorkflow.run,
            args=[user_data.email, user_data.password],
            id=workflow_id,
            task_queue="ai-auth-queue",
            execution_timeout=timedelta(seconds=30)
        )
        
        if result["success"]:
            return TokenResponse(
                access_token=result["access_token"],
                refresh_token=result["refresh_token"],
                expires_in=result["expires_in"]
            )
        else:
            error_msg = result.get("error", "AI authentication failed")
            status_code = 401 if "credentials" in error_msg.lower() else 500
            raise HTTPException(status_code=status_code, detail=error_msg)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI login failed: {e}")
        raise HTTPException(status_code=500, detail="AI authentication service error")

@app.post("/user/register")
async def ai_register(user_data: UserRegister):
    """AI-Enhanced Registration - Pure Temporal Power"""
    
    if not temporal_client:
        raise HTTPException(status_code=503, detail="Temporal AI service unavailable")
    
    try:
        workflow_id = f"ai-register-{user_data.email}-{uuid.uuid4().hex[:6]}"
        
        result = await temporal_client.execute_workflow(
            SmartRegistrationWorkflow.run,
            args=[user_data.email, user_data.password, user_data.first_name, user_data.last_name],
            id=workflow_id,
            task_queue="ai-auth-queue",
            execution_timeout=timedelta(seconds=30)
        )
        
        if result["success"]:
            return result
        else:
            error_msg = result.get("error", "Smart registration failed")
            status_code = 400 if "exists" in error_msg or "verification" in error_msg else 500
            raise HTTPException(status_code=status_code, detail=error_msg)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI registration failed: {e}")
        raise HTTPException(status_code=500, detail="AI registration service error")

@app.get("/")
async def root():
    return {
        "message": "🤖 Pure Temporal AI Auth Server",
        "features": [
            "AI-Enhanced Authentication",
            "Smart Fraud Detection", 
            "Behavioral Analysis",
            "Continuous Monitoring",
            "Database-Free Architecture"
        ],
        "temporal_connected": temporal_client is not None,
        "test_credentials": {
            "email": "test@example.com",
            "password": "password123"
        },
        "ai_workflows": [
            "AIAuthenticationWorkflow",
            "SmartRegistrationWorkflow",
            "ContinuousAIMonitoringWorkflow"
        ]
    }

if __name__ == "__main__":
    print("🤖 Starting Pure Temporal AI Auth Server...")
    print("✨ Features: AI-Enhanced Auth, Fraud Detection, Behavioral Analysis")
    print("🗄️  Database-Free: Everything powered by Temporal workflows")
    print("🔧 Requires: Temporal server on localhost:7233")
    print("🧪 Test: test@example.com / password123")
    uvicorn.run(app, host="0.0.0.0", port=8000)