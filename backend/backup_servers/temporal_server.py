#!/usr/bin/env python3
"""
Temporal-enabled backend server that leverages Temporal workflows for all operations
"""

import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio import workflow, activity
from datetime import timedelta
import uuid
import logging
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Temporal Auth Server")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Temporal client
temporal_client = None

# Mock user data (in real app, this would be a database)
users_db = {
    "test@example.com": {
        "id": "user_123",
        "email": "test@example.com",
        "password": "password123",  # In real app, this would be hashed
        "is_active": True,
        "is_verified": True
    }
}

# Pydantic Models
class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    first_name: str = None
    last_name: str = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

# Temporal Workflows
@workflow.defn
class LoginWorkflow:
    @workflow.run
    async def run(self, email: str, password: str) -> dict:
        """Login workflow using Temporal"""
        
        try:
            # Step 1: Authenticate user
            auth_result = await workflow.execute_activity(
                authenticate_user,
                args=[email, password],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            if not auth_result["success"]:
                return auth_result
            
            # Step 2: Generate tokens
            token_result = await workflow.execute_activity(
                generate_tokens,
                args=[auth_result["user_id"], email],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            # Step 3: Log the login
            await workflow.execute_activity(
                log_login,
                args=[email, "success"],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            return {
                "success": True,
                "access_token": token_result["access_token"],
                "refresh_token": token_result["refresh_token"],
                "expires_in": token_result["expires_in"],
                "method": "temporal_workflow"
            }
            
        except Exception as e:
            # Log failed login
            await workflow.execute_activity(
                log_login,
                args=[email, f"failed: {str(e)}"],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            return {
                "success": False,
                "error": str(e),
                "method": "temporal_workflow"
            }

@workflow.defn
class RegistrationWorkflow:
    @workflow.run
    async def run(self, email: str, password: str, first_name: str = None, last_name: str = None) -> dict:
        """Registration workflow using Temporal"""
        
        try:
            # Step 1: Check if user exists
            check_result = await workflow.execute_activity(
                check_user_exists,
                args=[email],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            if check_result["exists"]:
                return {
                    "success": False,
                    "error": "User with this email already exists",
                    "method": "temporal_workflow"
                }
            
            # Step 2: Create user
            create_result = await workflow.execute_activity(
                create_user,
                args=[email, password, first_name, last_name],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            # Step 3: Send welcome notification
            await workflow.execute_activity(
                send_welcome_notification,
                args=[email],
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            return {
                "success": True,
                "user_id": create_result["user_id"],
                "email": email,
                "message": "Registration successful",
                "method": "temporal_workflow"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "temporal_workflow"
            }

# Temporal Activities
@activity.defn
async def authenticate_user(email: str, password: str) -> dict:
    """Authenticate user credentials"""
    logger.info(f"Authenticating user: {email}")
    
    user = users_db.get(email)
    if not user:
        return {"success": False, "error": "Invalid credentials"}
    
    if user["password"] != password:
        return {"success": False, "error": "Invalid credentials"}
    
    if not user["is_active"]:
        return {"success": False, "error": "Account deactivated"}
    
    return {
        "success": True,
        "user_id": user["id"],
        "email": user["email"]
    }

@activity.defn
async def generate_tokens(user_id: str, email: str) -> dict:
    """Generate JWT tokens"""
    logger.info(f"Generating tokens for user: {email}")
    
    # In real app, these would be proper JWT tokens
    access_token = f"temporal_access_token_{uuid.uuid4().hex[:8]}"
    refresh_token = f"temporal_refresh_token_{uuid.uuid4().hex[:8]}"
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 3600
    }

@activity.defn
async def log_login(email: str, status: str):
    """Log login attempt"""
    logger.info(f"LOGIN: {email} - {status}")

@activity.defn
async def check_user_exists(email: str) -> dict:
    """Check if user already exists"""
    logger.info(f"Checking if user exists: {email}")
    
    return {
        "exists": email in users_db
    }

@activity.defn
async def create_user(email: str, password: str, first_name: str = None, last_name: str = None) -> dict:
    """Create a new user"""
    logger.info(f"Creating user: {email}")
    
    user_id = f"user_{uuid.uuid4().hex[:8]}"
    
    users_db[email] = {
        "id": user_id,
        "email": email,
        "password": password,  # In real app, would be hashed
        "first_name": first_name,
        "last_name": last_name,
        "is_active": True,
        "is_verified": True  # Auto-verify for demo
    }
    
    return {
        "user_id": user_id,
        "email": email
    }

@activity.defn
async def send_welcome_notification(email: str):
    """Send welcome notification"""
    logger.info(f"Sending welcome notification to: {email}")

# Initialize Temporal connection
async def init_temporal():
    """Initialize Temporal client and worker"""
    global temporal_client
    
    try:
        # Connect to Temporal server
        temporal_client = await Client.connect("localhost:7233")
        logger.info("Connected to Temporal server")
        
        # Start worker in background
        asyncio.create_task(start_worker())
        
        return True
    except Exception as e:
        logger.error(f"Failed to connect to Temporal: {e}")
        return False

async def start_worker():
    """Start Temporal worker"""
    try:
        worker = Worker(
            temporal_client,
            task_queue="auth-task-queue",
            workflows=[LoginWorkflow, RegistrationWorkflow],
            activities=[
                authenticate_user,
                generate_tokens,
                log_login,
                check_user_exists,
                create_user,
                send_welcome_notification
            ]
        )
        
        logger.info("Starting Temporal worker...")
        await worker.run()
    except Exception as e:
        logger.error(f"Worker failed: {e}")

# API Endpoints
@app.on_event("startup")
async def startup_event():
    """Initialize Temporal on startup"""
    temporal_available = await init_temporal()
    if not temporal_available:
        logger.warning("Temporal not available - some features may not work")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "temporal-auth-server",
        "temporal_connected": temporal_client is not None
    }

@app.post("/user/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    """Login endpoint - always uses Temporal workflow"""
    
    if not temporal_client:
        raise HTTPException(status_code=503, detail="Temporal service unavailable")
    
    try:
        # Execute login workflow
        workflow_id = f"login-{user_data.email}-{uuid.uuid4().hex[:8]}"
        
        result = await temporal_client.execute_workflow(
            LoginWorkflow.run,
            args=[user_data.email, user_data.password],
            id=workflow_id,
            task_queue="auth-task-queue",
            execution_timeout=timedelta(seconds=30)
        )
        
        if result["success"]:
            return TokenResponse(
                access_token=result["access_token"],
                refresh_token=result["refresh_token"],
                expires_in=result["expires_in"]
            )
        else:
            error_msg = result.get("error", "Login failed")
            if "Invalid credentials" in error_msg or "deactivated" in error_msg:
                raise HTTPException(status_code=401, detail=error_msg)
            else:
                raise HTTPException(status_code=500, detail=error_msg)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/user/register")
async def register(user_data: UserRegister):
    """Register endpoint - always uses Temporal workflow"""
    
    if not temporal_client:
        raise HTTPException(status_code=503, detail="Temporal service unavailable")
    
    try:
        # Execute registration workflow
        workflow_id = f"register-{user_data.email}-{uuid.uuid4().hex[:8]}"
        
        result = await temporal_client.execute_workflow(
            RegistrationWorkflow.run,
            args=[user_data.email, user_data.password, user_data.first_name, user_data.last_name],
            id=workflow_id,
            task_queue="auth-task-queue",
            execution_timeout=timedelta(seconds=30)
        )
        
        if result["success"]:
            return result
        else:
            error_msg = result.get("error", "Registration failed")
            if "already exists" in error_msg:
                raise HTTPException(status_code=400, detail=error_msg)
            else:
                raise HTTPException(status_code=500, detail=error_msg)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.get("/")
async def root():
    return {
        "message": "Temporal Auth Server",
        "temporal_connected": temporal_client is not None,
        "available_users": list(users_db.keys()),
        "test_credentials": {
            "email": "test@example.com",
            "password": "password123"
        },
        "workflows": ["LoginWorkflow", "RegistrationWorkflow"]
    }

if __name__ == "__main__":
    print("Starting Temporal-enabled auth server on port 8000...")
    print("Test user: test@example.com / password123")
    print("Requires Temporal server running on localhost:7233")
    uvicorn.run(app, host="0.0.0.0", port=8000)