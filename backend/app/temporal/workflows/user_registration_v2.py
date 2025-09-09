from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey
from temporalio.exceptions import ApplicationError
from datetime import timedelta
from dataclasses import dataclass
from typing import Optional, Dict, Any
import logging
import uuid

from app.temporal.activities.user import UserCreateData

logger = logging.getLogger(__name__)

@dataclass
class RegistrationRequest:
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    source: str = "web"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "source": self.source
        }

class UserRegistrationError(ApplicationError):
    """Custom error for user registration failures"""
    pass

class EmailDeliveryError(ApplicationError):
    """Custom error for email delivery failures"""
    pass

# Search attributes for workflow observability
USER_EMAIL_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("UserEmail")
REGISTRATION_SOURCE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("RegistrationSource")
WORKFLOW_STATUS_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("WorkflowStatus")

@workflow.defn
class UserRegistrationWorkflowV2:
    """Production-ready workflow for user registration with AI-powered enhancements
    
    Features:
    - AI-powered fraud detection and risk scoring
    - Intelligent retry policies with exponential backoff
    - Idempotent activities with compensation logic
    - Search attributes for observability
    - Predictive email delivery optimization
    - Comprehensive error handling with specific error types
    - Real-time anomaly detection
    """
    
    @workflow.run
    async def run(self, registration_data: RegistrationRequest) -> dict:
        """Execute AI-enhanced user registration workflow
        
        Args:
            registration_data: User registration information
            
        Returns:
            Dict containing registration result with AI insights
        """
        
        # Set search attributes for observability
        workflow.upsert_search_attributes({
            USER_EMAIL_SEARCH_ATTRIBUTE: registration_data.email,
            REGISTRATION_SOURCE_SEARCH_ATTRIBUTE: registration_data.source,
            WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "started"
        })
        
        # Generate unique workflow correlation ID
        correlation_id = str(uuid.uuid4())
        workflow.logger.info(f"Starting AI-enhanced user registration workflow", extra={
            "correlation_id": correlation_id,
            "user_email": registration_data.email,
            "source": registration_data.source
        })
        
        fraud_score = 0.0
        
        try:
            # Step 0: AI-powered pre-registration fraud analysis
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
            risk_factors = fraud_analysis.get("risk_factors", [])
            
            # Block high-risk registrations
            if fraud_score > 0.8:
                workflow.upsert_search_attributes({
                    WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "blocked_fraud"
                })
                raise UserRegistrationError(f"Registration blocked due to high fraud risk: {fraud_score}")
            
            # Step 1: Generate AI-optimized verification token
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "generating_token"
            })
            
            token_result = await workflow.execute_activity(
                "generate_verification_token",
                {
                    "email": registration_data.email,
                    "fraud_score": fraud_score,  # AI adjusts token expiry based on risk
                    "source": registration_data.source,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=30),
                    maximum_attempts=5,
                    backoff_coefficient=2.0
                )
            )
            
            verification_token = token_result["token"]
            
            # Step 2: Create user in database with idempotency
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "creating_user"
            })
            
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
                correlation_id,  # For idempotency
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(minutes=1),
                    maximum_attempts=3,
                    backoff_coefficient=2.0,
                    non_retryable_error_types=["UserExistsError"]
                )
            )
            
            # Step 3: AI-optimized email delivery strategy
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "optimizing_email"
            })
            
            # AI determines optimal email delivery strategy
            email_strategy = await workflow.execute_activity(
                "optimize_email_delivery_strategy",
                {
                    "email": registration_data.email,
                    "fraud_score": fraud_score,
                    "user_agent": registration_data.user_agent,
                    "source": registration_data.source,
                    "risk_factors": risk_factors,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=2
                )
            )
            
            # Step 4: Send verification email with AI optimizations
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "sending_email"
            })
            
            email_sent = await workflow.execute_activity(
                "send_verification_email",
                {
                    "email": registration_data.email,
                    "token": verification_token,
                    "name": user_result.get("first_name") or user_result.get("username"),
                    "strategy": email_strategy,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=5),
                    maximum_interval=timedelta(minutes=1),
                    maximum_attempts=3,
                    backoff_coefficient=2.0
                )
            )
            
            if not email_sent:
                workflow.logger.warning(f"Failed to send verification email", extra={
                    "user_email": registration_data.email,
                    "correlation_id": correlation_id
                })
                
                # Trigger compensating action - queue for retry
                await workflow.execute_activity(
                    "queue_email_for_retry",
                    {
                        "email": registration_data.email,
                        "token": verification_token,
                        "correlation_id": correlation_id,
                        "retry_count": 1
                    },
                    start_to_close_timeout=timedelta(seconds=30)
                )
            
            # Step 5: AI-powered post-registration analysis and learning
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "analyzing_patterns"
            })
            
            pattern_analysis = await workflow.execute_activity(
                "analyze_registration_patterns",
                {
                    "user_id": user_result["user_id"],
                    "registration_data": registration_data.to_dict(),
                    "fraud_score": fraud_score,
                    "risk_factors": risk_factors,
                    "email_sent": email_sent,
                    "email_strategy": email_strategy,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "completed"
            })
            
            workflow.logger.info(f"AI-enhanced user registration workflow completed", extra={
                "user_email": registration_data.email,
                "user_id": user_result["user_id"],
                "fraud_score": fraud_score,
                "correlation_id": correlation_id,
                "pattern_insights": pattern_analysis.get("insights", {})
            })
            
            return {
                "success": True,
                "user_id": user_result["user_id"],
                "email": user_result["email"],
                "verification_email_sent": email_sent,
                "fraud_score": fraud_score,
                "correlation_id": correlation_id,
                "ai_insights": {
                    "risk_level": "low" if fraud_score < 0.3 else "medium" if fraud_score < 0.7 else "high",
                    "risk_factors": risk_factors,
                    "email_strategy": email_strategy.get("strategy", "standard"),
                    "recommended_verification_time": email_strategy.get("optimal_send_time", "immediate"),
                    "pattern_insights": pattern_analysis.get("insights", {}),
                    "anomaly_score": pattern_analysis.get("anomaly_score", 0.0)
                },
                "message": "Registration successful. Please check your email to verify your account."
            }
            
        except UserRegistrationError as e:
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "failed_business_logic"
            })
            workflow.logger.error(f"User registration business logic error", extra={
                "user_email": registration_data.email,
                "error": str(e),
                "correlation_id": correlation_id
            })
            return {
                "success": False,
                "error": str(e),
                "error_type": "business_logic",
                "correlation_id": correlation_id,
                "fraud_score": fraud_score,
                "message": "Registration failed due to policy violation."
            }
        except EmailDeliveryError as e:
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "failed_email"
            })
            workflow.logger.error(f"Email delivery error", extra={
                "user_email": registration_data.email,
                "error": str(e),
                "correlation_id": correlation_id
            })
            return {
                "success": False,
                "error": str(e),
                "error_type": "email_delivery",
                "correlation_id": correlation_id,
                "fraud_score": fraud_score,
                "message": "Registration completed but email delivery failed. Please contact support."
            }
        except Exception as e:
            workflow.upsert_search_attributes({
                WORKFLOW_STATUS_SEARCH_ATTRIBUTE: "failed_system"
            })
            workflow.logger.error(f"System error in registration workflow", extra={
                "user_email": registration_data.email,
                "error": str(e),
                "correlation_id": correlation_id
            })
            return {
                "success": False,
                "error": str(e),
                "error_type": "system",
                "correlation_id": correlation_id,
                "fraud_score": fraud_score,
                "message": "Registration failed due to system error. Please try again."
            }

@workflow.defn  
class EmailVerificationWorkflow:
    """AI-enhanced workflow for handling email verification"""
    
    @workflow.run
    async def run(self, verification_token: str) -> dict:
        """Execute email verification workflow with AI insights"""
        
        correlation_id = str(uuid.uuid4())
        
        try:
            # Step 1: Verify email using token
            verification_result = await workflow.execute_activity(
                "verify_user_email",
                verification_token,
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=30),
                    maximum_attempts=3
                )
            )
            
            # Step 2: AI-powered user behavior analysis
            behavior_analysis = await workflow.execute_activity(
                "analyze_verification_behavior",
                {
                    "user_id": verification_result["user_id"],
                    "verification_token": verification_token,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            # Step 3: Send personalized welcome email
            welcome_email_sent = await workflow.execute_activity(
                "send_personalized_welcome_email",
                {
                    "email": verification_result["email"],
                    "user_id": verification_result["user_id"],
                    "behavior_insights": behavior_analysis,
                    "correlation_id": correlation_id
                },
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(seconds=30),
                    maximum_attempts=3
                )
            )
            
            workflow.logger.info(f"Email verification workflow completed", extra={
                "user_id": verification_result['user_id'],
                "correlation_id": correlation_id
            })
            
            return {
                "success": True,
                "user_id": verification_result["user_id"],
                "email": verification_result["email"],
                "verified_at": verification_result["verified_at"],
                "welcome_email_sent": welcome_email_sent,
                "correlation_id": correlation_id,
                "ai_insights": {
                    "verification_speed": behavior_analysis.get("verification_speed", "normal"),
                    "engagement_score": behavior_analysis.get("engagement_score", 0.5),
                    "recommended_onboarding": behavior_analysis.get("recommended_onboarding", "standard")
                },
                "message": "Email verified successfully. Welcome!"
            }
            
        except Exception as e:
            workflow.logger.error(f"Email verification workflow failed", extra={
                "token": verification_token,
                "error": str(e),
                "correlation_id": correlation_id
            })
            return {
                "success": False,
                "error": str(e),
                "correlation_id": correlation_id,
                "message": "Email verification failed. Please try again or request a new verification email."
            }