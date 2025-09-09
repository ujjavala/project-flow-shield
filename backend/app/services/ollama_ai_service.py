"""
Ollama AI Service for Local Authentication Intelligence
Provides AI capabilities using locally hosted Ollama models instead of cloud APIs
"""

import aiohttp
import asyncio
import json
import logging
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

class OllamaAIService:
    """Local AI service using Ollama for authentication intelligence"""
    
    def __init__(self, host: str = "localhost", port: int = 11434, model: str = "llama3"):
        self.base_url = f"http://{host}:{port}"
        self.model = model
        self.session = None
    
    async def _ensure_session(self):
        """Ensure aiohttp session is initialized"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def _make_request(self, prompt: str, max_tokens: int = 200) -> str:
        """Make request to Ollama API"""
        await self._ensure_session()
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,  # Lower temperature for more consistent responses
                "top_p": 0.9
            }
        }
        
        try:
            async with self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=30
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("response", "").strip()
                else:
                    logger.error(f"Ollama API error: {response.status}")
                    return ""
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return ""
    
    async def analyze_password_security(self, password: str, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze password security using AI"""
        prompt = f"""
        Analyze the security of this password: "{password}"
        
        User context: {user_context.get('first_name', 'N/A')} {user_context.get('last_name', 'N/A')}
        Email: {user_context.get('email', 'N/A')}
        
        Provide analysis in this exact JSON format:
        {{
            "security_score": <float between 0.0 and 1.0>,
            "strength_level": "<weak|medium|strong|very_strong>",
            "personal_info_detected": <boolean>,
            "common_patterns": [<list of detected patterns>],
            "recommendations": [<list of improvement suggestions>],
            "explanation": "<brief one-sentence explanation>"
        }}
        
        Only respond with valid JSON, nothing else.
        """
        
        try:
            response = await self._make_request(prompt, max_tokens=300)
            
            # Extract JSON from response
            json_match = re.search(r'\\{.*\\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                data = json.loads(json_str)
                
                # Validate and normalize the response
                return {
                    "security_score": max(0.0, min(1.0, float(data.get("security_score", 0.5)))),
                    "strength_level": data.get("strength_level", "medium"),
                    "ai_analysis": {
                        "personal_info_detected": bool(data.get("personal_info_detected", False)),
                        "common_patterns": data.get("common_patterns", []),
                        "ai_explanation": data.get("explanation", "AI analysis completed")
                    },
                    "recommendations": data.get("recommendations", ["Enable 2FA", "Consider longer password"]),
                    "model_version": f"ollama_{self.model}",
                    "ai_provider": "ollama_local"
                }
            else:
                # Fallback analysis if JSON parsing fails
                return self._fallback_password_analysis(password, user_context)
                
        except Exception as e:
            logger.error(f"Password analysis failed: {e}")
            return self._fallback_password_analysis(password, user_context)
    
    async def detect_registration_fraud(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect registration fraud using AI"""
        prompt = f"""
        Analyze this user registration for potential fraud:
        
        Email: {registration_data.get('email', 'N/A')}
        Name: {registration_data.get('first_name', 'N/A')} {registration_data.get('last_name', 'N/A')}
        IP: {registration_data.get('ip_address', 'N/A')}
        User Agent: {registration_data.get('user_agent', 'N/A')}
        Source: {registration_data.get('source', 'web')}
        
        Analyze for fraud indicators and respond in this exact JSON format:
        {{
            "fraud_score": <float between 0.0 and 1.0>,
            "risk_level": "<low|medium|high|critical>",
            "risk_factors": [<list of detected risk factors>],
            "confidence": <float between 0.0 and 1.0>,
            "explanation": "<brief explanation of the assessment>"
        }}
        
        Only respond with valid JSON, nothing else.
        """
        
        try:
            response = await self._make_request(prompt, max_tokens=300)
            
            # Extract JSON from response
            json_match = re.search(r'\\{.*\\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                data = json.loads(json_str)
                
                return {
                    "fraud_score": max(0.0, min(1.0, float(data.get("fraud_score", 0.1)))),
                    "risk_level": data.get("risk_level", "low"),
                    "risk_factors": data.get("risk_factors", []),
                    "confidence": max(0.0, min(1.0, float(data.get("confidence", 0.7)))),
                    "ai_insights": {
                        "explanation": data.get("explanation", "Registration analyzed"),
                        "model": self.model,
                        "provider": "ollama_local"
                    },
                    "correlation_id": f"ollama_{int(datetime.now().timestamp())}"
                }
            else:
                # Fallback if JSON parsing fails
                return self._fallback_fraud_analysis(registration_data)
                
        except Exception as e:
            logger.error(f"Fraud detection failed: {e}")
            return self._fallback_fraud_analysis(registration_data)
    
    async def generate_security_explanation(self, context: str, risk_level: str) -> str:
        """Generate user-friendly security explanations"""
        prompt = f"""
        Generate a brief, user-friendly explanation for this security situation:
        
        Context: {context}
        Risk Level: {risk_level}
        
        Write a single, clear sentence explaining what this means for the user.
        Be helpful and not alarming. Focus on actionable advice.
        
        Example: "Your registration looks normal, but consider enabling two-factor authentication for extra security."
        
        Response:
        """
        
        try:
            response = await self._make_request(prompt, max_tokens=100)
            return response or "Security analysis completed successfully."
        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return "Security analysis completed successfully."
    
    def _fallback_password_analysis(self, password: str, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback password analysis when AI fails"""
        # Simple rule-based analysis
        score = 0.0
        
        if len(password) >= 8:
            score += 0.3
        if re.search(r'[A-Z]', password):
            score += 0.2
        if re.search(r'[a-z]', password):
            score += 0.2
        if re.search(r'[0-9]', password):
            score += 0.15
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 0.15
        
        # Check for personal info
        personal_info = False
        first_name = user_context.get('first_name', '').lower()
        last_name = user_context.get('last_name', '').lower()
        
        if first_name and first_name in password.lower():
            personal_info = True
            score *= 0.5
        if last_name and last_name in password.lower():
            personal_info = True
            score *= 0.5
        
        strength_level = "weak" if score < 0.4 else "medium" if score < 0.7 else "strong"
        
        return {
            "security_score": score,
            "strength_level": strength_level,
            "ai_analysis": {
                "personal_info_detected": personal_info,
                "common_patterns": [],
                "ai_explanation": "Fallback analysis completed"
            },
            "recommendations": ["Enable 2FA", "Use longer passwords", "Avoid personal information"],
            "model_version": "rule_based_fallback",
            "ai_provider": "fallback"
        }
    
    def _fallback_fraud_analysis(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback fraud analysis when AI fails"""
        # Simple rule-based fraud detection
        risk_factors = []
        fraud_score = 0.1  # Base low risk
        
        email = registration_data.get('email', '').lower()
        
        # Check for suspicious email patterns
        suspicious_domains = ['guerrillamail.com', 'mailinator.com', '10minutemail.com']
        if any(domain in email for domain in suspicious_domains):
            risk_factors.append("suspicious_email_domain")
            fraud_score += 0.4
        
        # Check for bot-like behavior
        user_agent = registration_data.get('user_agent', '')
        if 'bot' in user_agent.lower() or len(user_agent) < 20:
            risk_factors.append("suspicious_user_agent")
            fraud_score += 0.3
        
        # Check source
        if registration_data.get('source') == 'automated':
            risk_factors.append("automated_source")
            fraud_score += 0.3
        
        fraud_score = min(fraud_score, 1.0)
        risk_level = "low" if fraud_score < 0.3 else "medium" if fraud_score < 0.7 else "high"
        
        return {
            "fraud_score": fraud_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "confidence": 0.6,
            "ai_insights": {
                "explanation": "Rule-based fraud analysis completed",
                "model": "rule_based",
                "provider": "fallback"
            },
            "correlation_id": f"fallback_{int(datetime.now().timestamp())}"
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if Ollama service is healthy"""
        try:
            await self._ensure_session()
            async with self.session.get(f"{self.base_url}/api/tags", timeout=5) as response:
                if response.status == 200:
                    return {
                        "status": "healthy",
                        "provider": "ollama_local",
                        "model": self.model,
                        "endpoint": self.base_url,
                        "available": True
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "provider": "ollama_local",
                        "error": f"HTTP {response.status}",
                        "available": False
                    }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "ollama_local",
                "error": str(e),
                "available": False
            }
    
    async def close(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None