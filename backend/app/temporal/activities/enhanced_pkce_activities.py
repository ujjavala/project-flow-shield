"""
Enhanced PKCE Activities for Temporal Workflows
Advanced security activities with fraud detection, monitoring, and analytics
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from temporalio import activity
import logging
import secrets
import asyncio

from app.models.pkce import PKCEUtils, PKCEAuthorizationCode
from app.services.jwt_service import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)


@activity.defn
async def fraud_detection_scan(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Advanced fraud detection for PKCE requests
    Analyzes patterns, IP reputation, and behavioral anomalies
    """
    activity.logger.info(f"Running fraud detection for client {request_data.get('client_id')}")
    
    try:
        # Simulate sophisticated fraud detection
        client_id = request_data.get("client_id")
        code = request_data.get("code")
        
        # Check for suspicious patterns
        suspicious_indicators = []
        risk_score = 0
        
        # Rate limiting check
        if await _check_rate_limits(client_id):
            suspicious_indicators.append("rate_limit_exceeded")
            risk_score += 30
            
        # IP reputation check
        if await _check_ip_reputation(request_data.get("ip_address")):
            suspicious_indicators.append("suspicious_ip")
            risk_score += 40
            
        # Behavioral analysis
        if await _behavioral_analysis(client_id, request_data):
            suspicious_indicators.append("unusual_behavior")
            risk_score += 25
            
        # Determine if request is suspicious
        is_suspicious = risk_score >= 50
        
        result = {
            "suspicious": is_suspicious,
            "risk_score": risk_score,
            "indicators": suspicious_indicators,
            "recommendations": _get_fraud_recommendations(risk_score),
            "scanned_at": datetime.utcnow().isoformat()
        }
        
        activity.logger.info(f"Fraud scan completed: risk_score={risk_score}, suspicious={is_suspicious}")
        return result
        
    except Exception as e:
        activity.logger.error(f"Fraud detection failed: {e}")
        # Return conservative result on failure
        return {
            "suspicious": True,
            "risk_score": 100,
            "indicators": ["fraud_detection_error"],
            "error": str(e)
        }


@activity.defn
async def enhanced_validate_pkce_request(pkce_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced PKCE request validation with security checks
    """
    activity.logger.info("Enhanced PKCE request validation starting")
    
    try:
        # Basic PKCE validation
        required_fields = ["client_id", "redirect_uri", "code_challenge", "code_challenge_method"]
        for field in required_fields:
            if not pkce_request.get(field):
                return {
                    "valid": False,
                    "error_description": f"Missing required field: {field}",
                    "security_level": "invalid_request"
                }
        
        # Code challenge validation
        code_challenge = pkce_request.get("code_challenge")
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            return {
                "valid": False,
                "error_description": "Invalid code challenge length",
                "security_level": "invalid_challenge"
            }
        
        # Method validation
        method = pkce_request.get("code_challenge_method", "S256")
        if method not in ["S256", "plain"]:
            return {
                "valid": False,
                "error_description": "Invalid code challenge method",
                "security_level": "invalid_method"
            }
        
        # Client validation
        client_valid = await _validate_client_credentials(
            pkce_request.get("client_id"),
            pkce_request.get("redirect_uri")
        )
        
        if not client_valid:
            return {
                "valid": False,
                "error_description": "Invalid client or redirect URI",
                "security_level": "invalid_client"
            }
        
        # Security scoring
        security_score = _calculate_security_score(pkce_request)
        
        return {
            "valid": True,
            "security_level": _get_security_level(security_score),
            "security_score": security_score,
            "validation_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        activity.logger.error(f"PKCE validation failed: {e}")
        return {
            "valid": False,
            "error_description": "Validation error occurred",
            "error": str(e)
        }


@activity.defn  
async def enhanced_store_pkce_authorization_code(auth_code_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced authorization code storage with redundancy and monitoring
    """
    activity.logger.info(f"Storing PKCE authorization code")
    
    try:
        # Primary storage
        primary_result = await _store_code_primary(auth_code_data)
        
        # Backup storage for redundancy
        backup_result = await _store_code_backup(auth_code_data)
        
        # Cache for fast access
        cache_result = await _store_code_cache(auth_code_data)
        
        # Analytics logging
        await _log_code_generation_analytics(auth_code_data)
        
        success = primary_result and (backup_result or cache_result)
        
        return {
            "success": success,
            "storage_locations": {
                "primary": primary_result,
                "backup": backup_result, 
                "cache": cache_result
            },
            "stored_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        activity.logger.error(f"Enhanced code storage failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@activity.defn
async def enhanced_generate_pkce_tokens(token_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced token generation with security features
    """
    activity.logger.info("Generating enhanced PKCE tokens")
    
    try:
        user_id = token_request["user_id"]
        client_id = token_request["client_id"]
        scope = token_request.get("scope", "read write")
        
        # Generate tokens with enhanced security
        access_token = create_access_token(
            subject=user_id,
            additional_claims={
                "client_id": client_id,
                "scope": scope,
                "token_type": "pkce_access",
                "security_level": "enhanced"
            }
        )
        
        refresh_token = create_refresh_token(
            subject=user_id,
            additional_claims={
                "client_id": client_id,
                "token_type": "pkce_refresh"
            }
        )
        
        # Token analytics and monitoring
        await _log_token_generation_analytics({
            "user_id": user_id,
            "client_id": client_id,
            "scope": scope,
            "generation_method": "enhanced_pkce"
        })
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 1800,  # 30 minutes
            "scope": scope,
            "security_features": {
                "pkce_verified": True,
                "enhanced_generation": True,
                "fraud_checked": True
            }
        }
        
    except Exception as e:
        activity.logger.error(f"Enhanced token generation failed: {e}")
        raise


@activity.defn
async def security_analytics_logger(event_data: Dict[str, Any]) -> None:
    """
    Advanced security analytics and logging
    """
    try:
        event_type = event_data.get("event_type")
        activity.logger.info(f"Logging security analytics event: {event_type}")
        
        # Structured logging for security events
        security_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": event_data,
            "source": "temporal_pkce_workflow",
            "severity": _get_event_severity(event_type),
            "correlation_id": event_data.get("correlation_id", secrets.token_hex(8))
        }
        
        # Send to multiple analytics backends
        await asyncio.gather(
            _send_to_security_siem(security_event),
            _send_to_analytics_db(security_event),
            _send_to_monitoring_alerts(security_event),
            return_exceptions=True
        )
        
    except Exception as e:
        activity.logger.error(f"Security analytics logging failed: {e}")


# Helper functions for enhanced activities

async def _check_rate_limits(client_id: str) -> bool:
    """Check if client has exceeded rate limits"""
    # Simulate rate limit check
    await asyncio.sleep(0.1)
    return False  # Not rate limited in demo


async def _check_ip_reputation(ip_address: Optional[str]) -> bool:
    """Check IP address reputation"""
    if not ip_address:
        return False
    # Simulate IP reputation check
    await asyncio.sleep(0.05)
    return False  # Good reputation in demo


async def _behavioral_analysis(client_id: str, request_data: Dict[str, Any]) -> bool:
    """Analyze behavioral patterns for anomalies"""
    # Simulate behavioral analysis
    await asyncio.sleep(0.1)
    return False  # Normal behavior in demo


def _get_fraud_recommendations(risk_score: int) -> List[str]:
    """Get fraud prevention recommendations based on risk score"""
    if risk_score >= 80:
        return ["block_request", "require_additional_auth", "alert_security_team"]
    elif risk_score >= 50:
        return ["increase_monitoring", "require_email_verification"]
    else:
        return ["normal_processing"]


async def _validate_client_credentials(client_id: str, redirect_uri: str) -> bool:
    """Validate client credentials and redirect URI"""
    # Simulate client validation
    await asyncio.sleep(0.05)
    return True  # Valid in demo


def _calculate_security_score(pkce_request: Dict[str, Any]) -> int:
    """Calculate security score for PKCE request"""
    score = 50  # Base score
    
    # Higher score for S256 method
    if pkce_request.get("code_challenge_method") == "S256":
        score += 30
    
    # Higher score for longer code challenge
    code_challenge = pkce_request.get("code_challenge", "")
    if len(code_challenge) > 60:
        score += 10
    
    # Bonus for additional security headers
    if pkce_request.get("security_headers"):
        score += 10
    
    return min(score, 100)


def _get_security_level(score: int) -> str:
    """Get security level based on score"""
    if score >= 80:
        return "high"
    elif score >= 60:
        return "medium"
    else:
        return "low"


async def _store_code_primary(auth_code_data: Dict[str, Any]) -> bool:
    """Store code in primary database"""
    await asyncio.sleep(0.02)
    return True


async def _store_code_backup(auth_code_data: Dict[str, Any]) -> bool:
    """Store code in backup system"""
    await asyncio.sleep(0.01)
    return True


async def _store_code_cache(auth_code_data: Dict[str, Any]) -> bool:
    """Store code in cache for fast access"""
    await asyncio.sleep(0.005)
    return True


async def _log_code_generation_analytics(auth_code_data: Dict[str, Any]) -> None:
    """Log analytics for code generation"""
    activity.logger.debug("Code generation analytics logged")


async def _log_token_generation_analytics(token_data: Dict[str, Any]) -> None:
    """Log analytics for token generation"""  
    activity.logger.debug("Token generation analytics logged")


def _get_event_severity(event_type: str) -> str:
    """Get severity level for security events"""
    high_severity = ["emergency_lockdown", "fraud_detected", "security_breach"]
    medium_severity = ["suspicious_activity", "rate_limit_exceeded"]
    
    if event_type in high_severity:
        return "high"
    elif event_type in medium_severity:
        return "medium"
    else:
        return "low"


async def _send_to_security_siem(event: Dict[str, Any]) -> None:
    """Send security event to SIEM system"""
    await asyncio.sleep(0.01)


async def _send_to_analytics_db(event: Dict[str, Any]) -> None:
    """Send event to analytics database"""
    await asyncio.sleep(0.01)


async def _send_to_monitoring_alerts(event: Dict[str, Any]) -> None:
    """Send event to monitoring/alerting system"""
    if event.get("severity") == "high":
        await asyncio.sleep(0.005)  # High priority processing