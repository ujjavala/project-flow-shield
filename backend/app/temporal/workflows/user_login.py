from temporalio import workflow
from temporalio.common import RetryPolicy
from datetime import timedelta
from typing import Optional
import logging

from app.temporal.types import LoginRequest

logger = logging.getLogger(__name__)

@workflow.defn
class UserLoginWorkflow:
    """Workflow for user login with authentication"""
    
    @workflow.run
    async def run(self, login_data: LoginRequest) -> dict:
        """Execute user login workflow"""
        
        try:
            logger.info(f"Starting login workflow for {login_data.email}")
            
            # Step 1: Authenticate user credentials
            auth_result = await workflow.execute_activity(
                "authenticate_user",
                args=[login_data.email, login_data.password],
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3,
                    non_retryable_error_types=["InvalidCredentialsError", "UserNotFoundError"]
                )
            )
            
            if not auth_result["success"]:
                return {
                    "success": False,
                    "error": auth_result.get("error", "Authentication failed"),
                    "method": "temporal_workflow"
                }
            
            # Step 2: Create JWT tokens
            token_result = await workflow.execute_activity(
                "create_login_tokens",
                args=[auth_result["user_id"], auth_result["email"]],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )
            
            # Step 3: Store refresh token and update last login
            storage_result = await workflow.execute_activity(
                "store_login_session",
                args=[auth_result["user_id"], token_result["refresh_token"]],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )
            
            logger.info(f"Login workflow completed successfully for {login_data.email}")
            
            return {
                "success": True,
                "access_token": token_result["access_token"],
                "refresh_token": token_result["refresh_token"],
                "token_type": "bearer",
                "expires_in": token_result["expires_in"],
                "user_id": auth_result["user_id"],
                "email": auth_result["email"],
                "method": "temporal_workflow"
            }
            
        except Exception as e:
            logger.error(f"Login workflow failed for {login_data.email}: {str(e)}")
            return {
                "success": False,
                "error": f"Login workflow failed: {str(e)}",
                "method": "temporal_workflow"
            }