from temporalio import workflow
from datetime import timedelta, datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class PasswordResetRequest:
    email: str

@dataclass
class PasswordResetConfirmation:
    reset_token: str
    new_password: str

@workflow.defn
class PasswordResetWorkflow:
    """Workflow for password reset process"""
    
    @workflow.run
    async def run(self, reset_request: PasswordResetRequest) -> dict:
        """Execute password reset workflow"""
        
        try:
            # Step 1: Generate password reset token
            token_result = await workflow.execute_activity(
                "generate_password_reset_token",
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            reset_token = token_result["token"]
            expires_at = datetime.fromisoformat(token_result["expires_at"])
            
            # Step 2: Set reset token for user
            await workflow.execute_activity(
                "set_password_reset_token",
                reset_request.email,
                reset_token,
                expires_at,
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            # Step 3: Send password reset email
            email_sent = await workflow.execute_activity(
                "send_password_reset_email",
                reset_request.email,
                reset_token,
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            if not email_sent:
                logger.warning(f"Failed to send password reset email to {reset_request.email}")
                return {
                    "success": False,
                    "error": "Failed to send reset email",
                    "message": "Failed to send password reset email. Please try again."
                }
            
            logger.info(f"Password reset workflow completed for {reset_request.email}")
            
            return {
                "success": True,
                "email": reset_request.email,
                "reset_email_sent": email_sent,
                "message": "Password reset email sent. Please check your email for further instructions."
            }
            
        except Exception as e:
            logger.error(f"Password reset workflow failed for {reset_request.email}: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Password reset request failed. Please try again."
            }

@workflow.defn
class PasswordResetConfirmationWorkflow:
    """Workflow for confirming password reset"""
    
    @workflow.run
    async def run(self, reset_confirmation: PasswordResetConfirmation) -> dict:
        """Execute password reset confirmation workflow"""
        
        try:
            # Step 1: Validate reset token
            is_valid = await workflow.execute_activity(
                "validate_password_reset_token",
                reset_confirmation.reset_token,
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            if not is_valid:
                return {
                    "success": False,
                    "error": "Invalid or expired reset token",
                    "message": "The password reset link is invalid or has expired. Please request a new one."
                }
            
            # Step 2: Reset password
            reset_result = await workflow.execute_activity(
                "reset_user_password",
                reset_confirmation.reset_token,
                reset_confirmation.new_password,
                start_to_close_timeout=timedelta(minutes=1)
            )
            
            logger.info(f"Password reset confirmation workflow completed for user {reset_result['user_id']}")
            
            return {
                "success": True,
                "user_id": reset_result["user_id"],
                "email": reset_result["email"],
                "password_reset_at": reset_result["password_reset_at"],
                "message": "Password reset successfully. You can now login with your new password."
            }
            
        except Exception as e:
            logger.error(f"Password reset confirmation workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Password reset failed. Please try again."
            }