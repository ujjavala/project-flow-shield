from temporalio import workflow
from datetime import timedelta
from dataclasses import dataclass
from typing import Optional
import logging

from app.temporal.activities.user import UserCreateData

logger = logging.getLogger(__name__)

@dataclass
class RegistrationRequest:
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None

@workflow.defn
class UserRegistrationWorkflow:
    """Workflow for user registration with email verification"""
    
    @workflow.run
    async def run(self, registration_data: RegistrationRequest) -> dict:
        """Execute user registration workflow"""
        
        try:
            # Step 0: AI-powered pre-registration checks
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "fraud_detection"
            })
            
            fraud_analysis = await workflow.execute_activity(
                "analyze_registration_fraud_risk",
                registration_data.to_dict(),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3,
                    backoff_coefficient=2.0
                )
            )
            
            fraud_score = fraud_analysis.get("fraud_score", 0.0)
            
            # Block high-risk registrations
            if fraud_score > 0.8:
                workflow.upsert_search_attributes({
                    WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "blocked_fraud"
                })
                raise UserRegistrationError(f"Registration blocked due to high fraud risk: {fraud_score}")
            
            # Step 1: Generate verification token
            token_result = await workflow.execute_activity(
                "generate_verification_token",
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            verification_token = token_result["token"]
            
            # Step 2: Create user in database            
            user_data = UserCreateData(
                email=registration_data.email,
                password=registration_data.password,
                first_name=registration_data.first_name,
                last_name=registration_data.last_name,
                username=registration_data.username
            )
            
            user_result = await workflow.execute_activity(
                "create_user",
                user_data,
                verification_token,
                start_to_close_timeout=timedelta(minutes=2)
            )
            
            # Step 3: Send verification email
            email_sent = await workflow.execute_activity(
                "send_verification_email",
                registration_data.email,
                verification_token,
                user_result.get("first_name") or user_result.get("username"),
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            if not email_sent:
                logger.warning(f"Failed to send verification email to {registration_data.email}")
                # Continue with registration even if email fails
            
            logger.info(f"User registration workflow completed for {registration_data.email}")
            
            return {
                "success": True,
                "user_id": user_result["user_id"],
                "email": user_result["email"],
                "verification_email_sent": email_sent,
                "message": "Registration successful. Please check your email to verify your account."
            }
            
        except Exception as e:
            logger.error(f"User registration workflow failed for {registration_data.email}: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Registration failed. Please try again."
            }

@workflow.defn  
class EmailVerificationWorkflow:
    """Workflow for handling email verification"""
    
    @workflow.run
    async def run(self, verification_token: str) -> dict:
        """Execute email verification workflow"""
        
        try:
            # Step 1: Verify email using token
            verification_result = await workflow.execute_activity(
                "verify_user_email",
                verification_token,
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            # Step 2: Send welcome email
            welcome_email_sent = await workflow.execute_activity(
                "send_welcome_email",
                verification_result["email"],
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            logger.info(f"Email verification workflow completed for user {verification_result['user_id']}")
            
            return {
                "success": True,
                "user_id": verification_result["user_id"],
                "email": verification_result["email"],
                "verified_at": verification_result["verified_at"],
                "welcome_email_sent": welcome_email_sent,
                "message": "Email verified successfully. Welcome!"
            }
            
        except Exception as e:
            logger.error(f"Email verification workflow failed for token {verification_token}: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Email verification failed. Please try again or request a new verification email."
            }