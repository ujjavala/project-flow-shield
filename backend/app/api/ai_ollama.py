"""
Ollama-Powered AI Endpoints for Authentication
Local AI endpoints using Ollama for privacy-preserving authentication intelligence
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.services.ollama_ai_service import OllamaAIService
from app.temporal.activities.ai_auth_ollama import ollama_activities

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/ai", tags=["AI Authentication (Ollama)"])

# Request/Response models
class PasswordAnalysisRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password to analyze")
    user_context: Dict[str, Any] = Field(default_factory=dict, description="User context for analysis")

class FraudDetectionRequest(BaseModel):
    email: str = Field(..., description="User email")
    first_name: str = Field(default="", description="User first name")
    last_name: str = Field(default="", description="User last name")
    ip_address: str = Field(default="", description="User IP address")
    user_agent: str = Field(default="", description="User agent string")
    source: str = Field(default="web", description="Registration source")

class BehavioralAnalysisRequest(BaseModel):
    typing_speed: float = Field(default=50.0, description="Typing speed (WPM)")
    form_interaction_time: float = Field(default=30.0, description="Time spent on form (seconds)")
    click_count: int = Field(default=10, description="Number of clicks/taps")
    scroll_events: int = Field(default=5, description="Number of scroll events")
    user_agent: str = Field(default="", description="User agent string")

# Global Ollama service instance
ollama_service = OllamaAIService()

@router.get("/health")
async def ai_health():
    """
    Check AI service health and availability
    """
    try:
        health_status = await ollama_activities.health_check()
        return {
            "timestamp": datetime.now().isoformat(),
            "ai_status": health_status.get("overall_status", "unknown"),
            "services": {
                "ollama": health_status.get("ollama", {}),
                "redis_cache": health_status.get("redis_cache", {}),
                "fallback_models": health_status.get("fallback_models", {})
            },
            "features": {
                "fraud_detection": True,
                "password_analysis": True,
                "behavioral_analysis": True,
                "email_optimization": True
            },
            "provider": "ollama_local"
        }
    except Exception as e:
        logger.error(f"AI health check failed: {e}")
        return {
            "timestamp": datetime.now().isoformat(),
            "ai_status": "unhealthy",
            "error": str(e),
            "provider": "ollama_local"
        }

@router.post("/analyze-password")
async def analyze_password(request: PasswordAnalysisRequest):
    """
    Analyze password security using local AI
    """
    try:
        password_data = {
            "password": request.password,
            "user_context": request.user_context
        }
        
        result = await ollama_activities.ollama_password_analysis(password_data)
        
        return {
            "success": True,
            "analysis": result,
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Password analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Password analysis failed: {str(e)}")

@router.post("/detect-fraud")
async def detect_fraud(request: FraudDetectionRequest):
    """
    Detect registration fraud using local AI
    """
    try:
        registration_data = {
            "email": request.email,
            "first_name": request.first_name,
            "last_name": request.last_name,
            "ip_address": request.ip_address,
            "user_agent": request.user_agent,
            "source": request.source
        }
        
        result = await ollama_activities.ollama_fraud_detection(registration_data)
        
        return {
            "success": True,
            "fraud_analysis": result,
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Fraud detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Fraud detection failed: {str(e)}")

@router.post("/analyze-behavior")
async def analyze_behavior(request: BehavioralAnalysisRequest):
    """
    Analyze user behavioral patterns for anomaly detection
    """
    try:
        behavioral_data = {
            "typing_speed": request.typing_speed,
            "form_interaction_time": request.form_interaction_time,
            "click_count": request.click_count,
            "scroll_events": request.scroll_events,
            "user_agent": request.user_agent
        }
        
        result = await ollama_activities.ollama_behavioral_analysis(behavioral_data)
        
        return {
            "success": True,
            "behavioral_analysis": result,
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Behavioral analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {str(e)}")

@router.post("/test-fraud-detection")
async def test_fraud_detection():
    """
    Test fraud detection with sample data
    """
    try:
        # Test with a suspicious registration
        test_data = {
            "email": "suspicious@guerrillamail.com",
            "first_name": "Bot",
            "last_name": "User",
            "ip_address": "1.2.3.4",
            "user_agent": "curl/7.0",
            "source": "automated"
        }
        
        result = await ollama_activities.ollama_fraud_detection(test_data)
        
        return {
            "test_name": "High Risk Registration",
            "test_data": test_data,
            "ai_result": result,
            "expected_outcome": "High fraud score",
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Fraud detection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

@router.post("/test-password-analysis")
async def test_password_analysis():
    """
    Test password analysis with sample data
    """
    try:
        # Test with a strong password
        test_data = {
            "password": "My$3cur3P@ssw0rd!2024",
            "user_context": {
                "first_name": "Test",
                "last_name": "User",
                "email": "test@example.com"
            }
        }
        
        result = await ollama_activities.ollama_password_analysis(test_data)
        
        return {
            "test_name": "Strong Password Analysis",
            "test_data": {
                "password": "[REDACTED]",
                "user_context": test_data["user_context"]
            },
            "ai_result": result,
            "expected_outcome": "High security score",
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Password analysis test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

@router.get("/model-status")
async def model_status():
    """
    Get detailed status of AI models
    """
    try:
        ollama_health = await ollama_service.health_check()
        
        return {
            "models": {
                "ollama": {
                    "status": ollama_health.get("status", "unknown"),
                    "model": ollama_health.get("model", "unknown"),
                    "endpoint": ollama_health.get("endpoint", "unknown"),
                    "available": ollama_health.get("available", False)
                },
                "fallback_ml": {
                    "status": "available",
                    "models": ["isolation_forest", "rule_based_analysis"],
                    "description": "Backup models for when Ollama is unavailable"
                }
            },
            "capabilities": {
                "fraud_detection": True,
                "password_analysis": True,
                "behavioral_analysis": True,
                "email_optimization": True,
                "real_time_processing": True,
                "cache_supported": True
            },
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Model status check failed: {e}")
        return {
            "error": str(e),
            "models": {
                "ollama": {"status": "error"},
                "fallback_ml": {"status": "available"}
            },
            "provider": "ollama_local",
            "timestamp": datetime.now().isoformat()
        }

@router.get("/debug-models")
async def debug_models():
    """
    Debug endpoint for model troubleshooting
    """
    try:
        # Test Ollama connectivity
        ollama_test = await ollama_service.health_check()
        
        # Test simple analysis
        test_password = await ollama_service.analyze_password_security(
            "TestPass123!", 
            {"first_name": "Debug", "last_name": "User"}
        )
        
        return {
            "debug_info": {
                "ollama_connectivity": ollama_test,
                "sample_password_analysis": test_password,
                "system_status": "operational"
            },
            "troubleshooting": {
                "ollama_running": ollama_test.get("available", False),
                "models_loaded": "Check 'ollama list' command",
                "redis_cache": "Check Redis connection in health endpoint"
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Debug check failed: {e}")
        return {
            "debug_info": {
                "error": str(e),
                "system_status": "error"
            },
            "troubleshooting": {
                "ollama_running": False,
                "suggestion": "Run 'ollama serve' to start Ollama server"
            },
            "timestamp": datetime.now().isoformat()
        }