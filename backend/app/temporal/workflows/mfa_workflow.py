"""
GuardFlow Multi-Factor Authentication (MFA) Workflow
Temporal-powered 2FA/MFA system for enhanced security
"""

import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import logging

from temporalio import workflow
from temporalio.common import RetryPolicy

logger = logging.getLogger(__name__)

@dataclass
class MFARequest:
    user_id: str
    email: str
    method: str  # 'sms', 'totp', 'email', 'push'
    ip_address: str
    user_agent: str
    session_id: str
    backup_methods: List[str] = None

@dataclass
class MFAResponse:
    success: bool
    method_used: str
    verification_token: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    error_message: Optional[str] = None
    retry_after: Optional[int] = None
    risk_score: float = 0.0

@workflow.defn
class MFAWorkflow:
    """Multi-Factor Authentication Workflow with Temporal reliability"""
    
    def __init__(self) -> None:
        self.attempts = 0
        self.max_attempts = 3
        self.mfa_code: Optional[str] = None
        self.verification_token: Optional[str] = None
        self.method_used: Optional[str] = None
        self.risk_assessment: Dict[str, Any] = {}
        
    @workflow.run
    async def run(self, mfa_request: MFARequest) -> MFAResponse:
        """Main MFA workflow execution"""
        
        logger.info(f"Starting MFA workflow for user {mfa_request.user_id}")
        
        try:
            # Step 1: Risk Assessment
            self.risk_assessment = await workflow.execute_activity(
                "assess_mfa_risk",
                mfa_request,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            # Step 2: Choose MFA Method
            chosen_method = await self._choose_mfa_method(mfa_request)
            
            # Step 3: Send MFA Challenge
            challenge_result = await workflow.execute_activity(
                "send_mfa_challenge",
                {
                    "user_id": mfa_request.user_id,
                    "method": chosen_method,
                    "email": mfa_request.email,
                    "risk_score": self.risk_assessment.get("risk_score", 0.0)
                },
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=RetryPolicy(maximum_attempts=3)
            )
            
            if not challenge_result.get("success"):
                return MFAResponse(
                    success=False,
                    method_used=chosen_method,
                    error_message="Failed to send MFA challenge"
                )
            
            self.mfa_code = challenge_result.get("code")
            self.method_used = chosen_method
            
            # Step 4: Wait for User Verification (with timeout)
            verification_result = await self._wait_for_verification(mfa_request)
            
            # Step 5: Process Verification Result
            if verification_result.success:
                # Generate verification token
                self.verification_token = await workflow.execute_activity(
                    "generate_mfa_token",
                    {
                        "user_id": mfa_request.user_id,
                        "method": self.method_used,
                        "session_id": mfa_request.session_id
                    },
                    start_to_close_timeout=timedelta(seconds=30)
                )
                
                # Log successful MFA
                await workflow.execute_activity(
                    "log_mfa_success",
                    {
                        "user_id": mfa_request.user_id,
                        "method": self.method_used,
                        "ip_address": mfa_request.ip_address,
                        "attempts": self.attempts,
                        "risk_score": self.risk_assessment.get("risk_score", 0.0)
                    },
                    start_to_close_timeout=timedelta(seconds=10)
                )
            
            return verification_result
            
        except Exception as e:
            logger.error(f"MFA workflow failed for user {mfa_request.user_id}: {e}")
            
            # Log failed MFA attempt
            await workflow.execute_activity(
                "log_mfa_failure",
                {
                    "user_id": mfa_request.user_id,
                    "error": str(e),
                    "attempts": self.attempts,
                    "ip_address": mfa_request.ip_address
                },
                start_to_close_timeout=timedelta(seconds=10)
            )
            
            return MFAResponse(
                success=False,
                method_used=self.method_used or "unknown",
                error_message=f"MFA workflow error: {str(e)}"
            )
    
    async def _choose_mfa_method(self, mfa_request: MFARequest) -> str:
        """Choose the best MFA method based on risk and user preferences"""
        
        # Get user's MFA preferences
        user_mfa_config = await workflow.execute_activity(
            "get_user_mfa_config",
            mfa_request.user_id,
            start_to_close_timeout=timedelta(seconds=15)
        )
        
        risk_score = self.risk_assessment.get("risk_score", 0.0)
        
        # High risk users require stronger MFA
        if risk_score > 0.7:
            if "totp" in user_mfa_config.get("enabled_methods", []):
                return "totp"
            elif "push" in user_mfa_config.get("enabled_methods", []):
                return "push"
        
        # Default to user's preferred method
        preferred_method = mfa_request.method
        if preferred_method in user_mfa_config.get("enabled_methods", []):
            return preferred_method
        
        # Fallback to first available method
        available_methods = user_mfa_config.get("enabled_methods", ["email"])
        return available_methods[0] if available_methods else "email"
    
    async def _wait_for_verification(self, mfa_request: MFARequest) -> MFAResponse:
        """Wait for user to provide MFA verification"""
        
        timeout_minutes = 5  # 5 minute timeout for MFA
        
        while self.attempts < self.max_attempts:
            self.attempts += 1
            
            try:
                # Wait for user input (signals from UI)
                verification_code = await workflow.wait_condition(
                    lambda: workflow.info().get_current_activity_result("mfa_verification"),
                    timeout=timedelta(minutes=timeout_minutes)
                )
                
                # Verify the code
                verification_result = await workflow.execute_activity(
                    "verify_mfa_code",
                    {
                        "provided_code": verification_code,
                        "expected_code": self.mfa_code,
                        "user_id": mfa_request.user_id,
                        "method": self.method_used
                    },
                    start_to_close_timeout=timedelta(seconds=10)
                )
                
                if verification_result.get("valid"):
                    return MFAResponse(
                        success=True,
                        method_used=self.method_used,
                        verification_token=self.verification_token,
                        risk_score=self.risk_assessment.get("risk_score", 0.0)
                    )
                else:
                    # Invalid code, allow retry
                    if self.attempts >= self.max_attempts:
                        return MFAResponse(
                            success=False,
                            method_used=self.method_used,
                            error_message="Maximum MFA attempts exceeded",
                            retry_after=300  # 5 minutes
                        )
                    
                    # Send retry notification
                    await workflow.execute_activity(
                        "send_mfa_retry_notification",
                        {
                            "user_id": mfa_request.user_id,
                            "attempts_remaining": self.max_attempts - self.attempts,
                            "method": self.method_used
                        },
                        start_to_close_timeout=timedelta(seconds=30)
                    )
                    
            except asyncio.TimeoutError:
                return MFAResponse(
                    success=False,
                    method_used=self.method_used,
                    error_message="MFA verification timeout",
                    retry_after=60
                )
        
        return MFAResponse(
            success=False,
            method_used=self.method_used,
            error_message="Maximum MFA attempts exceeded",
            retry_after=300
        )
    
    @workflow.signal
    async def submit_mfa_code(self, code: str):
        """Signal to submit MFA verification code"""
        workflow.info().set_current_activity_result("mfa_verification", code)
    
    @workflow.query
    def get_mfa_status(self) -> Dict[str, Any]:
        """Query current MFA status"""
        return {
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "method_used": self.method_used,
            "risk_score": self.risk_assessment.get("risk_score", 0.0),
            "has_verification_token": self.verification_token is not None
        }