#!/usr/bin/env python3
"""
Simplified backend server for testing login functionality
without complex dependencies
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Simple Auth Server")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock data
mock_users = {
    "test@example.com": {
        "id": "user_123",
        "email": "test@example.com", 
        "password": "password123",  # In real app, this would be hashed
        "is_active": True,
        "is_verified": True
    }
}

# Models
class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "simple-auth"}

@app.post("/user/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    """Simple login endpoint for testing"""
    
    # Check if user exists
    user = mock_users.get(user_data.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check password (in real app, would verify hashed password)
    if user["password"] != user_data.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(status_code=401, detail="Account is deactivated")
    
    # Return mock tokens
    return TokenResponse(
        access_token="mock_access_token_12345",
        refresh_token="mock_refresh_token_67890", 
        expires_in=3600
    )

@app.post("/user/register")
async def register(user_data: dict):
    """Simple register endpoint"""
    email = user_data.get("email")
    password = user_data.get("password")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    
    if email in mock_users:
        raise HTTPException(status_code=400, detail="User with this email already exists")
    
    # Add user to mock data
    mock_users[email] = {
        "id": f"user_{len(mock_users) + 1}",
        "email": email,
        "password": password,
        "is_active": True,
        "is_verified": True  # Auto-verify for testing
    }
    
    return {
        "success": True,
        "message": "Registration successful",
        "email": email
    }

@app.get("/")
async def root():
    return {
        "message": "Simple Auth Server",
        "available_users": list(mock_users.keys()),
        "test_credentials": {
            "email": "test@example.com", 
            "password": "password123"
        }
    }

if __name__ == "__main__":
    print("Starting simple auth server on port 8001...")
    print("Test user: test@example.com / password123")
    uvicorn.run(app, host="0.0.0.0", port=8001)