"""
GuardFlow Multi-Factor Authentication Activities
Temporal activities for 2FA/MFA system implementation
"""

import asyncio
import secrets
import string
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging
import json
import requests

from temporalio import activity

logger = logging.getLogger(__name__)

class MFAActivities:
    """Activities for Multi-Factor Authentication workflow"""
    
    def __init__(self):
        self.mfa_codes = {}  # In-memory storage for demo
        self.user_configs = {}  # User MFA configurations
        self.audit_logs = []  # Audit trail
        
    @activity.defn
    async def assess_mfa_risk(self, mfa_request: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk score for MFA request based on various factors"""
        
        risk_factors = {
            "ip_reputation": 0.0,
            "device_trust": 0.0,
            "location_anomaly": 0.0,
            "time_anomaly": 0.0,
            "velocity_check": 0.0
        }
        
        # Simulate IP reputation check
        ip_address = mfa_request.get("ip_address", "")
        if ip_address.startswith("192.168.") or ip_address.startswith("127."):
            risk_factors["ip_reputation"] = 0.1  # Local network - low risk
        else:
            risk_factors["ip_reputation"] = 0.3  # External IP - medium risk
            
        # Device trust analysis
        user_agent = mfa_request.get("user_agent", "")
        if "Chrome" in user_agent or "Firefox" in user_agent:
            risk_factors["device_trust"] = 0.2  # Known browser - low risk
        else:
            risk_factors["device_trust"] = 0.5  # Unknown client - higher risk
            
        # Time-based anomaly detection
        current_hour = datetime.now().hour
        if 9 <= current_hour <= 17:  # Business hours
            risk_factors["time_anomaly"] = 0.1
        elif 22 <= current_hour or current_hour <= 6:  # Late night/early morning
            risk_factors["time_anomaly"] = 0.4
        else:
            risk_factors["time_anomaly"] = 0.2
            
        # Calculate overall risk score
        total_risk = sum(risk_factors.values()) / len(risk_factors)
        
        logger.info(f"Risk assessment for user {mfa_request.get('user_id')}: {total_risk:.2f}")
        
        return {
            "risk_score": min(total_risk, 1.0),
            "risk_factors": risk_factors,
            "recommendation": "require_mfa" if total_risk > 0.3 else "optional_mfa",
            "assessed_at": datetime.now().isoformat()
        }
    
    @activity.defn
    async def send_mfa_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send MFA challenge via specified method"""
        
        user_id = challenge_data["user_id"]
        method = challenge_data["method"]
        email = challenge_data["email"]
        risk_score = challenge_data.get("risk_score", 0.0)
        
        # Generate MFA code based on method
        if method == "totp":
            # For TOTP, we'd normally use the user's secret key
            mfa_code = self._generate_totp_code(user_id)
        else:
            # Generate 6-digit numeric code for SMS/Email
            mfa_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        
        # Store code with expiration
        code_key = f"{user_id}:{method}"
        self.mfa_codes[code_key] = {
            "code": mfa_code,
            "expires_at": datetime.now() + timedelta(minutes=5),
            "attempts": 0,
            "method": method
        }
        
        # Send challenge based on method
        success = False
        if method == "email":
            success = await self._send_email_challenge(email, mfa_code, risk_score)
        elif method == "sms":
            success = await self._send_sms_challenge(user_id, mfa_code)
        elif method == "push":
            success = await self._send_push_notification(user_id, risk_score)
        elif method == "totp":
            success = True  # TOTP doesn't require sending, just validation
            
        logger.info(f"MFA challenge sent to user {user_id} via {method}: {'success' if success else 'failed'}")
        
        return {
            "success": success,
            "code": mfa_code if success else None,
            "method": method,
            "expires_in": 300  # 5 minutes
        }
    
    @activity.defn
    async def verify_mfa_code(self, verification_data: Dict[str, Any]) -> Dict[str, bool]:
        """Verify provided MFA code against expected code"""
        
        provided_code = verification_data["provided_code"]
        expected_code = verification_data["expected_code"]
        user_id = verification_data["user_id"]
        method = verification_data["method"]
        
        code_key = f"{user_id}:{method}"
        stored_data = self.mfa_codes.get(code_key)
        
        if not stored_data:
            logger.warning(f"No stored MFA code found for user {user_id} method {method}")
            return {"valid": False, "reason": "no_code_found"}
        
        # Check expiration
        if datetime.now() > stored_data["expires_at"]:
            logger.warning(f"MFA code expired for user {user_id}")
            del self.mfa_codes[code_key]
            return {"valid": False, "reason": "expired"}
        
        # Increment attempts
        stored_data["attempts"] += 1
        
        # Check attempt limit
        if stored_data["attempts"] > 3:
            logger.warning(f"Too many MFA attempts for user {user_id}")
            del self.mfa_codes[code_key]
            return {"valid": False, "reason": "too_many_attempts"}
        
        # Verify code
        is_valid = False
        if method == "totp":
            is_valid = self._verify_totp_code(user_id, provided_code)
        else:
            is_valid = provided_code == expected_code
        
        if is_valid:
            # Clean up successful verification
            del self.mfa_codes[code_key]
            logger.info(f"MFA verification successful for user {user_id}")
        else:
            logger.warning(f"Invalid MFA code provided by user {user_id}")
            
        return {
            "valid": is_valid,
            "attempts_used": stored_data["attempts"],
            "reason": "valid" if is_valid else "invalid_code"
        }
    
    @activity.defn
    async def generate_mfa_token(self, token_data: Dict[str, Any]) -> str:
        """Generate MFA verification token for successful authentication"""
        
        user_id = token_data["user_id"]
        method = token_data["method"]
        session_id = token_data["session_id"]
        
        # Create token payload
        token_payload = {
            "user_id": user_id,
            "method": method,
            "session_id": session_id,
            "mfa_verified": True,
            "issued_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=8)).isoformat()
        }
        
        # Generate secure token (in production, use proper JWT)
        token_string = json.dumps(token_payload)
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()
        
        logger.info(f"Generated MFA token for user {user_id}")
        return f"mfa_{token_hash[:32]}"
    
    @activity.defn
    async def get_user_mfa_config(self, user_id: str) -> Dict[str, Any]:
        """Get user's MFA configuration and preferences"""
        
        # Default MFA configuration
        default_config = {
            "enabled_methods": ["email", "totp"],
            "preferred_method": "email",
            "backup_methods": ["totp"],
            "require_mfa": True,
            "backup_codes_remaining": 8
        }
        
        # Get user-specific config (from in-memory storage for demo)
        user_config = self.user_configs.get(user_id, default_config)
        
        logger.info(f"Retrieved MFA config for user {user_id}: {user_config['enabled_methods']}")
        return user_config
    
    @activity.defn
    async def log_mfa_success(self, log_data: Dict[str, Any]) -> None:
        """Log successful MFA authentication"""
        
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "mfa_success",
            "user_id": log_data["user_id"],
            "method": log_data["method"],
            "ip_address": log_data["ip_address"],
            "attempts": log_data["attempts"],
            "risk_score": log_data["risk_score"]
        }
        
        self.audit_logs.append(audit_entry)
        logger.info(f"MFA success logged for user {log_data['user_id']}")
    
    @activity.defn
    async def log_mfa_failure(self, log_data: Dict[str, Any]) -> None:
        """Log failed MFA authentication attempt"""
        
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "mfa_failure",
            "user_id": log_data["user_id"],
            "error": log_data["error"],
            "attempts": log_data["attempts"],
            "ip_address": log_data["ip_address"]
        }
        
        self.audit_logs.append(audit_entry)
        logger.warning(f"MFA failure logged for user {log_data['user_id']}: {log_data['error']}")
    
    @activity.defn
    async def send_mfa_retry_notification(self, notification_data: Dict[str, Any]) -> bool:
        """Send retry notification to user"""
        
        user_id = notification_data["user_id"]
        attempts_remaining = notification_data["attempts_remaining"]
        method = notification_data["method"]
        
        message = f"Invalid MFA code. {attempts_remaining} attempts remaining."
        
        # In production, send via appropriate channel
        logger.info(f"Retry notification sent to user {user_id}: {message}")
        return True
    
    def _generate_totp_code(self, user_id: str) -> str:
        """Generate TOTP code (simplified implementation)"""
        # In production, use proper TOTP library with user's secret
        current_time = int(time.time()) // 30  # 30-second window
        secret = f"secret_{user_id}"  # Demo secret
        
        # Simple HMAC-based code generation
        message = str(current_time).encode()
        digest = hmac.new(secret.encode(), message, hashlib.sha1).digest()
        offset = digest[-1] & 0xf
        code = ((digest[offset] & 0x7f) << 24 |
                (digest[offset + 1] & 0xff) << 16 |
                (digest[offset + 2] & 0xff) << 8 |
                (digest[offset + 3] & 0xff))
        
        return f"{code % 1000000:06d}"
    
    def _verify_totp_code(self, user_id: str, provided_code: str) -> bool:
        """Verify TOTP code with time window tolerance"""
        current_time = int(time.time()) // 30
        
        # Check current window and ±1 window for clock drift
        for time_window in [current_time - 1, current_time, current_time + 1]:
            expected_code = self._generate_totp_for_time(user_id, time_window)
            if provided_code == expected_code:
                return True
        
        return False
    
    def _generate_totp_for_time(self, user_id: str, time_window: int) -> str:
        """Generate TOTP code for specific time window"""
        secret = f"secret_{user_id}"
        message = str(time_window).encode()
        digest = hmac.new(secret.encode(), message, hashlib.sha1).digest()
        offset = digest[-1] & 0xf
        code = ((digest[offset] & 0x7f) << 24 |
                (digest[offset + 1] & 0xff) << 16 |
                (digest[offset + 2] & 0xff) << 8 |
                (digest[offset + 3] & 0xff))
        
        return f"{code % 1000000:06d}"
    
    async def _send_email_challenge(self, email: str, code: str, risk_score: float) -> bool:
        """Send MFA code via email"""
        # In production, integrate with email service
        subject = "GuardFlow Security Code"
        if risk_score > 0.5:
            subject += " - High Risk Login Detected"
        
        logger.info(f"Email MFA code sent to {email}: {code}")
        return True
    
    async def _send_sms_challenge(self, user_id: str, code: str) -> bool:
        """Send MFA code via SMS"""
        # In production, integrate with SMS service (Twilio, etc.)
        logger.info(f"SMS MFA code sent to user {user_id}: {code}")
        return True
    
    async def _send_push_notification(self, user_id: str, risk_score: float) -> bool:
        """Send push notification for MFA"""
        # In production, integrate with push notification service
        message = "Approve login request"
        if risk_score > 0.5:
            message += " - High risk detected"
        
        logger.info(f"Push notification sent to user {user_id}: {message}")
        return True