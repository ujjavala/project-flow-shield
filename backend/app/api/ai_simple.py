"""
Simple AI endpoints for testing without additional dependencies
Demonstrates AI concepts using basic Python and external API calls
"""

import httpx
import asyncio
import json
import logging
import re
import hashlib
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/ai", tags=["AI Authentication (Simple)"])

# Request/Response models
class PasswordAnalysisRequest(BaseModel):
    password: str = Field(..., min_length=1)
    user_context: Dict[str, Any] = Field(default_factory=dict)

class FraudDetectionRequest(BaseModel):
    email: str
    first_name: str = ""
    last_name: str = ""
    ip_address: str = ""
    user_agent: str = ""
    source: str = "web"

class OllamaService:
    """Simple Ollama API client using httpx"""
    
    def __init__(self, host="host.docker.internal", port=11434):
        self.base_url = f"http://{host}:{port}"
    
    async def generate_response(self, prompt: str, model: str = "llama3") -> str:
        """Generate response using Ollama"""
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 200,
                "temperature": 0.1
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("response", "").strip()
                else:
                    logger.error(f"Ollama error: {response.status_code}")
                    return ""
        except Exception as exc:
            logger.error("Ollama request failed exception_type=%s", type(exc).__name__)
            return ""
    
    async def check_health(self) -> bool:
        """Check if Ollama is available"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except:
            return False

# Global service instance
ollama = OllamaService()

@router.get("/health")
async def ai_health():
    """Check AI service health"""
    try:
        ollama_available = await ollama.check_health()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "ai_status": "healthy" if ollama_available else "degraded",
            "services": {
                "ollama": {
                    "status": "available" if ollama_available else "unavailable",
                    "model": "llama3"
                },
                "fallback": {
                    "status": "available",
                    "description": "Rule-based analysis available"
                }
            },
            "features": {
                "password_analysis": True,
                "fraud_detection": True,
                "local_ai": ollama_available
            }
        }
    except Exception as exc:
        logger.error("AI health check failed exception_type=%s", type(exc).__name__)
        return {
            "timestamp": datetime.now().isoformat(),
            "ai_status": "error",
            "error": "AI health check failed"
        }

@router.post("/analyze-password")
async def analyze_password(request: PasswordAnalysisRequest):
    """Analyze password security"""
    try:
        password = request.password
        user_context = request.user_context
        
        # Try Ollama first
        ollama_result = None
        if await ollama.check_health():
            password_features = {
                "length_bucket": "short" if len(password) < 12 else "medium" if len(password) < 20 else "long",
                "has_uppercase": bool(re.search(r'[A-Z]', password)),
                "has_lowercase": bool(re.search(r'[a-z]', password)),
                "has_numbers": bool(re.search(r'[0-9]', password)),
                "has_special": bool(re.search(r'[^A-Za-z0-9]', password)),
                "has_repeated_sequence": bool(re.search(r'(.)\1{2,}', password)),
            }
            prompt = f"""
            Analyze these non-identifying password-strength features:
            {json.dumps(password_features, sort_keys=True)}

            The raw password and user identity are intentionally unavailable.
            
            Rate the security from 0.0 to 1.0 and respond with only:
            SCORE: <number>
            LEVEL: <weak|medium|strong>
            EXPLANATION: <one sentence>
            """
            
            ollama_response = await ollama.generate_response(prompt)
            if ollama_response:
                try:
                    score_match = re.search(r'SCORE:\s*([\d.]+)', ollama_response)
                    level_match = re.search(r'LEVEL:\s*(\w+)', ollama_response)
                    explanation_match = re.search(r'EXPLANATION:\s*(.+)', ollama_response)
                    
                    if score_match and level_match:
                        ollama_result = {
                            "security_score": float(score_match.group(1)),
                            "strength_level": level_match.group(1),
                            "ai_explanation": explanation_match.group(1) if explanation_match else "AI analysis completed"
                        }
                except:
                    pass
        
        # Fallback rule-based analysis
        score = 0.0
        if len(password) >= 8: score += 0.3
        if re.search(r'[A-Z]', password): score += 0.2
        if re.search(r'[a-z]', password): score += 0.2
        if re.search(r'[0-9]', password): score += 0.15
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 0.15
        
        # Check for personal info
        personal_info = False
        first_name = user_context.get('first_name', '').lower()
        if first_name and first_name in password.lower():
            personal_info = True
            score *= 0.7
        
        strength_level = "weak" if score < 0.4 else "medium" if score < 0.7 else "strong"
        
        result = {
            "success": True,
            "analysis": {
                "security_score": ollama_result["security_score"] if ollama_result else score,
                "strength_level": ollama_result["strength_level"] if ollama_result else strength_level,
                "personal_info_detected": personal_info,
                "password_length": len(password),
                "complexity_indicators": {
                    "has_uppercase": bool(re.search(r'[A-Z]', password)),
                    "has_lowercase": bool(re.search(r'[a-z]', password)),
                    "has_numbers": bool(re.search(r'[0-9]', password)),
                    "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
                },
                "ai_explanation": ollama_result["ai_explanation"] if ollama_result else "Rule-based analysis completed",
                "provider": "ollama" if ollama_result else "rule_based"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return result
        
    except Exception as exc:
        logger.error("Password analysis failed exception_type=%s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Password analysis failed") from exc

@router.post("/detect-fraud")
async def detect_fraud(request: FraudDetectionRequest):
    """Detect registration fraud"""
    try:
        # Try Ollama first
        ollama_result = None
        if await ollama.check_health():
            email_domain = request.email.rpartition('@')[2].lower()
            suspicious_domains = ['guerrillamail', 'mailinator', '10minutemail', 'tempmail']
            fraud_features = {
                "disposable_email_domain": any(domain in email_domain for domain in suspicious_domains),
                "automated_source": request.source == 'automated',
                "suspicious_user_agent": 'bot' in request.user_agent.lower() or len(request.user_agent) < 20,
                "identity_fields_present": bool(request.first_name and request.last_name),
                "network_context_present": bool(request.ip_address),
            }
            prompt = f"""
            Analyze these non-identifying registration-risk features:
            {json.dumps(fraud_features, sort_keys=True)}

            Direct identifiers and raw network/device data are intentionally unavailable.
            
            Rate fraud risk 0.0-1.0 and respond with only:
            FRAUD_SCORE: <number>
            RISK_LEVEL: <low|medium|high>
            EXPLANATION: <one sentence>
            """
            
            ollama_response = await ollama.generate_response(prompt)
            if ollama_response:
                try:
                    score_match = re.search(r'FRAUD_SCORE:\s*([\d.]+)', ollama_response)
                    level_match = re.search(r'RISK_LEVEL:\s*(\w+)', ollama_response)
                    explanation_match = re.search(r'EXPLANATION:\s*(.+)', ollama_response)
                    
                    if score_match and level_match:
                        ollama_result = {
                            "fraud_score": float(score_match.group(1)),
                            "risk_level": level_match.group(1),
                            "explanation": explanation_match.group(1) if explanation_match else "AI analysis completed"
                        }
                except:
                    pass
        
        # Fallback rule-based analysis
        fraud_score = 0.1
        risk_factors = []
        
        email = request.email.lower()
        suspicious_domains = ['guerrillamail', 'mailinator', '10minutemail', 'tempmail']
        if any(domain in email for domain in suspicious_domains):
            fraud_score += 0.4
            risk_factors.append("suspicious_email_domain")
        
        if 'bot' in request.user_agent.lower() or len(request.user_agent) < 20:
            fraud_score += 0.3
            risk_factors.append("suspicious_user_agent")
        
        if request.source == 'automated':
            fraud_score += 0.3
            risk_factors.append("automated_source")
        
        fraud_score = min(fraud_score, 1.0)
        risk_level = "low" if fraud_score < 0.3 else "medium" if fraud_score < 0.7 else "high"
        
        result = {
            "success": True,
            "fraud_analysis": {
                "fraud_score": ollama_result["fraud_score"] if ollama_result else fraud_score,
                "risk_level": ollama_result["risk_level"] if ollama_result else risk_level,
                "risk_factors": risk_factors,
                "confidence": 0.8 if ollama_result else 0.6,
                "ai_insights": {
                    "explanation": ollama_result["explanation"] if ollama_result else "Rule-based fraud analysis",
                    "provider": "ollama" if ollama_result else "rule_based"
                },
                "correlation_id": hashlib.sha256(f"{request.email}{datetime.now().timestamp()}".encode()).hexdigest()[:16]
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return result
        
    except Exception as exc:
        logger.error("Fraud detection failed exception_type=%s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Fraud detection failed") from exc

@router.post("/test-fraud-detection")
async def test_fraud_detection():
    """Test fraud detection with sample data"""
    test_request = FraudDetectionRequest(
        email="suspicious@guerrillamail.com",
        first_name="Bot",
        last_name="User",
        ip_address="1.2.3.4",
        user_agent="curl/7.0",
        source="automated"
    )
    
    result = await detect_fraud(test_request)
    
    return {
        "test_name": "High Risk Registration Test",
        "test_data": {
            "email": test_request.email,
            "user_agent": test_request.user_agent,
            "source": test_request.source
        },
        "result": result,
        "timestamp": datetime.now().isoformat()
    }

@router.post("/test-password-analysis")
async def test_password_analysis():
    """Test password analysis with sample data"""
    test_request = PasswordAnalysisRequest(
        password="My$3cur3P@ssw0rd!2024",
        user_context={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com"
        }
    )
    
    result = await analyze_password(test_request)
    
    return {
        "test_name": "Strong Password Analysis Test",
        "test_data": {
            "password": "[REDACTED]",
            "user_context": test_request.user_context
        },
        "result": result,
        "timestamp": datetime.now().isoformat()
    }