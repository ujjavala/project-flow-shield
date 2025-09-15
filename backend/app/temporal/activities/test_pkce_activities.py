"""
Test PKCE Activities for Temporal Testing
Simplified activities that work in test environment without external dependencies
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from temporalio import activity
import logging
import secrets

from app.models.pkce import PKCEUtils

logger = logging.getLogger(__name__)


@activity.defn
async def validate_pkce_request(pkce_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test version of PKCE request validation
    """
    activity.logger.info("Validating PKCE request in test environment")
    
    try:
        # Basic validation checks
        required_fields = ["client_id", "redirect_uri", "code_challenge", "code_challenge_method"]
        for field in required_fields:
            if not pkce_request.get(field):
                return {
                    "valid": False,
                    "error_description": f"Missing required field: {field}"
                }
        
        # Simulate client validation failure
        if pkce_request.get("client_id") == "invalid-client":
            return {
                "valid": False,
                "error_description": "Invalid client_id"
            }
        
        # Code challenge validation
        code_challenge = pkce_request.get("code_challenge")
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            return {
                "valid": False,
                "error_description": "Invalid code challenge length"
            }
        
        # Method validation
        method = pkce_request.get("code_challenge_method", "S256")
        if method not in ["S256", "plain"]:
            return {
                "valid": False,
                "error_description": "Invalid code challenge method"
            }
        
        return {
            "valid": True,
            "security_level": "high",
            "security_score": 85,
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
async def store_pkce_authorization_code(auth_code_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test version of authorization code storage
    """
    activity.logger.info("Storing PKCE authorization code in test environment")
    
    try:
        # Simulate storage operations
        code = auth_code_data.get("code")
        if not code:
            return {
                "success": False,
                "error": "No authorization code provided"
            }
        
        # Simulate successful storage
        return {
            "success": True,
            "storage_location": "test_memory",
            "stored_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        activity.logger.error(f"Code storage failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@activity.defn
async def retrieve_pkce_authorization_code(code: str) -> Dict[str, Any]:
    """
    Test version of authorization code retrieval
    """
    activity.logger.info(f"Retrieving PKCE authorization code in test environment")
    
    try:
        # Simulate code not found
        if code == "invalid-code" or code == "expired-code":
            return {"found": False}
        
        # Generate a test code challenge for the test verifier
        test_verifier = "a" * 43
        code_challenge = PKCEUtils.generate_code_challenge(test_verifier, "S256")
        
        # Simulate successful retrieval
        return {
            "found": True,
            "auth_code": {
                "code": code,
                "client_id": "test-client",
                "user_id": "user-123",
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
                "state": "test-state",
                "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
                "is_used": False,
                "created_at": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        activity.logger.error(f"Code retrieval failed: {e}")
        return {
            "found": False,
            "error": str(e)
        }


@activity.defn
async def mark_authorization_code_used(code: str) -> Dict[str, Any]:
    """
    Test version of marking authorization code as used
    """
    activity.logger.info(f"Marking authorization code as used in test environment")
    
    try:
        # Simulate marking code as used
        return {
            "success": True,
            "code": code,
            "marked_used_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        activity.logger.error(f"Failed to mark code as used: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@activity.defn
async def generate_pkce_tokens(token_request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test version of PKCE token generation
    """
    activity.logger.info("Generating PKCE tokens in test environment")
    
    try:
        user_id = token_request["user_id"]
        client_id = token_request["client_id"]
        scope = token_request.get("scope", "read write")
        
        # Generate mock tokens
        access_token = f"test_access_token_{secrets.token_urlsafe(16)}"
        refresh_token = f"test_refresh_token_{secrets.token_urlsafe(16)}"
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 1800,  # 30 minutes
            "scope": scope,
            "user_id": user_id,
            "client_id": client_id,
            "issued_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        activity.logger.error(f"Token generation failed: {e}")
        raise


@activity.defn
async def log_security_event(event_data: Dict[str, Any]) -> None:
    """
    Test version of security event logging
    """
    activity.logger.info(f"Logging security event in test environment: {event_data.get('event_type', 'unknown')}")
    
    try:
        # Simulate logging to various backends
        event_type = event_data.get("event_type", "unknown")
        timestamp = datetime.utcnow().isoformat()
        
        # In test environment, just log to activity logger
        activity.logger.info(f"Security Event: {event_type} at {timestamp}")
        
    except Exception as e:
        activity.logger.error(f"Security event logging failed: {e}")


@activity.defn
async def fraud_detection_scan(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test version of fraud detection scanning
    """
    activity.logger.info("Running fraud detection scan in test environment")
    
    try:
        client_id = request_data.get("client_id", "unknown")
        
        # Simulate fraud detection logic
        risk_indicators = []
        risk_score = 0
        
        # Simulate some basic checks
        if "suspicious" in client_id.lower():
            risk_indicators.append("suspicious_client_name")
            risk_score += 40
        
        if "bot" in client_id.lower():
            risk_indicators.append("bot_pattern")
            risk_score += 30
        
        # Determine if suspicious
        is_suspicious = risk_score >= 50
        
        return {
            "suspicious": is_suspicious,
            "risk_score": risk_score,
            "indicators": risk_indicators,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "scan_duration_ms": 15  # Simulate scan time
        }
        
    except Exception as e:
        activity.logger.error(f"Fraud detection scan failed: {e}")
        return {
            "suspicious": True,  # Conservative approach on error
            "risk_score": 100,
            "indicators": ["scan_error"],
            "error": str(e)
        }


# Activity registration helper for tests
def get_test_activities():
    """Get list of test activities for worker registration"""
    return [
        validate_pkce_request,
        store_pkce_authorization_code,
        retrieve_pkce_authorization_code,
        mark_authorization_code_used,
        generate_pkce_tokens,
        log_security_event,
        fraud_detection_scan
    ]