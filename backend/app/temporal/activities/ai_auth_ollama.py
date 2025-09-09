"""
Ollama-Enhanced Authentication Activities
Combines local Ollama AI with traditional ML models for authentication intelligence
"""

import os
import json
import asyncio
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import redis.asyncio as redis

# Import our Ollama service
from app.services.ollama_ai_service import OllamaAIService

# Basic ML for fallbacks
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from temporalio import activity

logger = logging.getLogger(__name__)

class OllamaAuthActivities:
    """Authentication activities powered by local Ollama AI"""
    
    def __init__(self):
        self.ollama_service = OllamaAIService()
        self.redis_client = None
        self.isolation_forest = None
        self._setup_models()
    
    def _setup_models(self):
        """Initialize ML models for fallback analysis"""
        try:
            # Simple anomaly detection model for fallback
            np.random.seed(42)
            # Generate some sample "normal" behavior data
            normal_data = np.random.normal(0, 1, (100, 5))
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.isolation_forest.fit(normal_data)
            logger.info("Fallback ML models initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize fallback models: {e}")
    
    async def _get_redis(self):
        """Get Redis client for caching"""
        if self.redis_client is None:
            try:
                redis_host = os.getenv("REDIS_HOST", "localhost")
                redis_port = int(os.getenv("REDIS_PORT", "6379"))
                self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
                await self.redis_client.ping()
                logger.info("Redis connected successfully")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}")
                self.redis_client = None
        return self.redis_client

    @activity.defn(name="ollama_fraud_detection")
    async def ollama_fraud_detection(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered fraud detection using local Ollama model
        Provides real-time fraud scoring with detailed insights
        """
        start_time = datetime.now()
        correlation_id = f"fraud_{int(start_time.timestamp())}_{secrets.token_hex(4)}"
        
        try:
            logger.info(f"Starting Ollama fraud detection: {correlation_id}")
            
            # Check Redis cache first
            cache_key = f"fraud_analysis:{hashlib.sha256(str(registration_data).encode()).hexdigest()}"
            redis_client = await self._get_redis()
            
            if redis_client:
                cached_result = await redis_client.get(cache_key)
                if cached_result:
                    logger.info(f"Using cached fraud analysis: {correlation_id}")
                    result = json.loads(cached_result)
                    result["cache_hit"] = True
                    return result
            
            # Analyze with Ollama
            analysis_result = await self.ollama_service.detect_registration_fraud(registration_data)
            
            # Enhance with additional metadata
            processing_time = (datetime.now() - start_time).total_seconds()
            
            result = {
                **analysis_result,
                "correlation_id": correlation_id,
                "processing_time_ms": int(processing_time * 1000),
                "timestamp": start_time.isoformat(),
                "ai_provider": "ollama_local",
                "cache_hit": False,
                "fallback_used": False
            }
            
            # Cache result for 1 hour
            if redis_client:
                await redis_client.setex(cache_key, 3600, json.dumps(result))
            
            logger.info(f"Fraud detection completed: {correlation_id}, score: {result.get('fraud_score')}")
            return result
            
        except Exception as e:
            logger.error(f"Ollama fraud detection failed: {correlation_id}, error: {e}")
            
            # Use fallback analysis
            fallback_result = await self._fallback_fraud_detection(registration_data, correlation_id)
            return fallback_result

    @activity.defn(name="ollama_password_analysis")
    async def ollama_password_analysis(self, password_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered password security analysis using Ollama
        Provides detailed password strength assessment
        """
        start_time = datetime.now()
        correlation_id = f"pwd_{int(start_time.timestamp())}_{secrets.token_hex(4)}"
        
        try:
            logger.info(f"Starting Ollama password analysis: {correlation_id}")
            
            password = password_data.get("password", "")
            user_context = password_data.get("user_context", {})
            
            # Analyze with Ollama
            analysis_result = await self.ollama_service.analyze_password_security(password, user_context)
            
            # Add metadata
            processing_time = (datetime.now() - start_time).total_seconds()
            
            result = {
                **analysis_result,
                "correlation_id": correlation_id,
                "processing_time_ms": int(processing_time * 1000),
                "timestamp": start_time.isoformat(),
                "password_length": len(password),
                "complexity_indicators": {
                    "has_uppercase": any(c.isupper() for c in password),
                    "has_lowercase": any(c.islower() for c in password),
                    "has_numbers": any(c.isdigit() for c in password),
                    "has_special": any(not c.isalnum() for c in password)
                }
            }
            
            logger.info(f"Password analysis completed: {correlation_id}, score: {result.get('security_score')}")
            return result
            
        except Exception as e:
            logger.error(f"Ollama password analysis failed: {correlation_id}, error: {e}")
            
            # Use fallback analysis
            fallback_result = await self._fallback_password_analysis(password_data, correlation_id)
            return fallback_result

    @activity.defn(name="ollama_behavioral_analysis")
    async def ollama_behavioral_analysis(self, behavioral_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered behavioral analysis for adaptive authentication
        """
        start_time = datetime.now()
        correlation_id = f"behavior_{int(start_time.timestamp())}_{secrets.token_hex(4)}"
        
        try:
            logger.info(f"Starting behavioral analysis: {correlation_id}")
            
            # Extract behavioral features
            features = self._extract_behavioral_features(behavioral_data)
            
            # Use ML model for anomaly detection (fallback approach)
            if self.isolation_forest and len(features) >= 5:
                anomaly_score = self.isolation_forest.decision_function([features])[0]
                is_anomaly = self.isolation_forest.predict([features])[0] == -1
            else:
                anomaly_score = 0.0
                is_anomaly = False
            
            # Generate AI explanation using Ollama
            context = f"User behavioral patterns: typing_speed={behavioral_data.get('typing_speed', 'N/A')}, interaction_time={behavioral_data.get('form_interaction_time', 'N/A')}"
            explanation = await self.ollama_service.generate_security_explanation(
                context, 
                "anomaly detected" if is_anomaly else "normal behavior"
            )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            result = {
                "behavioral_score": float(1.0 if anomaly_score > 0 else 0.5 - abs(anomaly_score) * 0.1),
                "anomaly_detected": bool(is_anomaly),
                "anomaly_score": float(anomaly_score),
                "confidence": 0.8,
                "analysis": {
                    "typing_pattern": "normal" if not is_anomaly else "unusual",
                    "interaction_pattern": "human-like" if not is_anomaly else "suspicious",
                    "ai_explanation": explanation
                },
                "correlation_id": correlation_id,
                "processing_time_ms": int(processing_time * 1000),
                "timestamp": start_time.isoformat(),
                "ai_provider": "ollama_local"
            }
            
            logger.info(f"Behavioral analysis completed: {correlation_id}")
            return result
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {correlation_id}, error: {e}")
            
            return {
                "behavioral_score": 0.7,
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "confidence": 0.5,
                "analysis": {
                    "typing_pattern": "normal",
                    "interaction_pattern": "human-like",
                    "ai_explanation": "Behavioral analysis completed with fallback method"
                },
                "correlation_id": correlation_id,
                "processing_time_ms": 100,
                "timestamp": start_time.isoformat(),
                "ai_provider": "fallback"
            }

    @activity.defn(name="ollama_email_optimization")
    async def ollama_email_optimization(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-optimized email delivery strategy using Ollama
        """
        start_time = datetime.now()
        correlation_id = f"email_{int(start_time.timestamp())}_{secrets.token_hex(4)}"
        
        try:
            logger.info(f"Starting email optimization: {correlation_id}")
            
            fraud_score = email_data.get("fraud_score", 0.1)
            user_source = email_data.get("source", "web")
            
            # Generate personalized email strategy using Ollama
            context = f"User registration with fraud score {fraud_score}, from {user_source} source"
            
            if fraud_score > 0.7:
                strategy = "high_security"
                explanation = await self.ollama_service.generate_security_explanation(
                    "High risk registration detected", "high"
                )
            elif fraud_score > 0.3:
                strategy = "standard_verification"
                explanation = await self.ollama_service.generate_security_explanation(
                    "Medium risk registration", "medium"
                )
            else:
                strategy = "friendly_welcome"
                explanation = await self.ollama_service.generate_security_explanation(
                    "Low risk registration", "low"
                )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            result = {
                "email_strategy": strategy,
                "personalization": {
                    "tone": "professional" if fraud_score > 0.5 else "friendly",
                    "urgency": "high" if fraud_score > 0.7 else "normal",
                    "additional_verification": fraud_score > 0.6
                },
                "delivery_optimization": {
                    "optimal_send_time": "immediate",
                    "template_variant": f"{strategy}_template",
                    "follow_up_required": fraud_score > 0.8
                },
                "ai_explanation": explanation,
                "correlation_id": correlation_id,
                "processing_time_ms": int(processing_time * 1000),
                "timestamp": start_time.isoformat(),
                "ai_provider": "ollama_local"
            }
            
            logger.info(f"Email optimization completed: {correlation_id}, strategy: {strategy}")
            return result
            
        except Exception as e:
            logger.error(f"Email optimization failed: {correlation_id}, error: {e}")
            
            return {
                "email_strategy": "standard",
                "personalization": {
                    "tone": "professional",
                    "urgency": "normal",
                    "additional_verification": False
                },
                "delivery_optimization": {
                    "optimal_send_time": "immediate",
                    "template_variant": "default_template",
                    "follow_up_required": False
                },
                "ai_explanation": "Standard email strategy applied",
                "correlation_id": correlation_id,
                "processing_time_ms": 50,
                "timestamp": start_time.isoformat(),
                "ai_provider": "fallback"
            }

    async def _fallback_fraud_detection(self, registration_data: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """Fallback fraud detection when Ollama fails"""
        logger.info(f"Using fallback fraud detection: {correlation_id}")
        
        risk_score = 0.1
        risk_factors = []
        
        # Simple rule-based checks
        email = registration_data.get("email", "").lower()
        suspicious_domains = ["guerrillamail", "mailinator", "10minutemail"]
        
        if any(domain in email for domain in suspicious_domains):
            risk_score += 0.4
            risk_factors.append("suspicious_email_domain")
        
        user_agent = registration_data.get("user_agent", "")
        if "bot" in user_agent.lower() or len(user_agent) < 20:
            risk_score += 0.3
            risk_factors.append("suspicious_user_agent")
        
        return {
            "fraud_score": min(risk_score, 1.0),
            "risk_level": "low" if risk_score < 0.3 else "medium" if risk_score < 0.7 else "high",
            "risk_factors": risk_factors,
            "confidence": 0.6,
            "ai_insights": {
                "explanation": "Rule-based fraud analysis (Ollama unavailable)",
                "model": "rule_based_fallback",
                "provider": "fallback"
            },
            "correlation_id": correlation_id,
            "processing_time_ms": 10,
            "timestamp": datetime.now().isoformat(),
            "ai_provider": "fallback",
            "fallback_used": True
        }

    async def _fallback_password_analysis(self, password_data: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """Fallback password analysis when Ollama fails"""
        logger.info(f"Using fallback password analysis: {correlation_id}")
        
        password = password_data.get("password", "")
        user_context = password_data.get("user_context", {})
        
        # Rule-based scoring
        score = 0.0
        if len(password) >= 8: score += 0.3
        if any(c.isupper() for c in password): score += 0.2
        if any(c.islower() for c in password): score += 0.2
        if any(c.isdigit() for c in password): score += 0.15
        if any(not c.isalnum() for c in password): score += 0.15
        
        return {
            "security_score": score,
            "strength_level": "weak" if score < 0.4 else "medium" if score < 0.7 else "strong",
            "ai_analysis": {
                "personal_info_detected": False,
                "common_patterns": [],
                "ai_explanation": "Rule-based analysis (Ollama unavailable)"
            },
            "recommendations": ["Enable 2FA", "Use longer passwords"],
            "correlation_id": correlation_id,
            "processing_time_ms": 5,
            "timestamp": datetime.now().isoformat(),
            "ai_provider": "fallback",
            "fallback_used": True
        }

    def _extract_behavioral_features(self, behavioral_data: Dict[str, Any]) -> List[float]:
        """Extract numerical features from behavioral data"""
        features = []
        
        # Extract and normalize various behavioral metrics
        features.append(behavioral_data.get("typing_speed", 50) / 100.0)  # Normalize typing speed
        features.append(behavioral_data.get("form_interaction_time", 30) / 60.0)  # Normalize time
        features.append(behavioral_data.get("click_count", 10) / 20.0)  # Normalize clicks
        features.append(behavioral_data.get("scroll_events", 5) / 10.0)  # Normalize scrolls
        features.append(len(behavioral_data.get("user_agent", "")) / 200.0)  # Normalize UA length
        
        return features

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all AI services"""
        ollama_health = await self.ollama_service.health_check()
        
        redis_health = {"status": "unknown"}
        try:
            redis_client = await self._get_redis()
            if redis_client:
                await redis_client.ping()
                redis_health = {"status": "healthy"}
        except Exception as e:
            redis_health = {"status": "unhealthy", "error": str(e)}
        
        return {
            "overall_status": "healthy" if ollama_health["status"] == "healthy" else "degraded",
            "ollama": ollama_health,
            "redis_cache": redis_health,
            "fallback_models": {"status": "available" if self.isolation_forest else "unavailable"},
            "timestamp": datetime.now().isoformat()
        }

# Global instance
ollama_activities = OllamaAuthActivities()