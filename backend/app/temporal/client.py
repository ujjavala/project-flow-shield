from temporalio.client import Client
from temporalio.worker import Worker
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class TemporalClient:
    _instance = None
    _client = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    async def get_client(self) -> Client:
        """Get or create Temporal client"""
        if self._client is None:
            try:
                self._client = await Client.connect(
                    settings.TEMPORAL_HOST,
                    namespace=settings.TEMPORAL_NAMESPACE
                )
                logger.info(f"Connected to Temporal at {settings.TEMPORAL_HOST}")
            except Exception as e:
                logger.error(f"Failed to connect to Temporal: {e}")
                raise
        return self._client
    
    async def close(self):
        """Close Temporal client connection"""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Temporal client connection closed")

# Global instance
temporal_client = TemporalClient()

async def get_temporal_client() -> Client:
    """Dependency to get Temporal client"""
    return await temporal_client.get_client()

async def create_worker() -> Worker:
    """Create and configure Temporal worker"""
    from app.temporal.workflows.ping import PingWorkflow
    
    # Import email workflows and activities
    try:
        from app.temporal.workflows.email_workflow import (
            EmailDeliveryWorkflow,
            EmailVerificationWorkflow, 
            PasswordResetEmailWorkflow
        )
        from app.temporal.workflows.password_reset import (
            PasswordResetWorkflow,
            PasswordResetConfirmationWorkflow
        )
        from app.temporal.workflows.user_registration import (
            UserRegistrationWorkflow,
            EmailVerificationWorkflow as UserEmailVerificationWorkflow
        )
        from app.temporal.workflows.user_login import UserLoginWorkflow
        from app.temporal.activities.email_activities import email_activities
        from app.temporal.activities.user import UserActivities
        from app.temporal.activities.auth import AuthActivities
        from app.temporal.activities.ai_auth import AIAuthActivities
        from app.temporal.activities.email import EmailActivities
        
        email_workflows = [
            EmailDeliveryWorkflow,
            PasswordResetEmailWorkflow,
            PasswordResetWorkflow,
            PasswordResetConfirmationWorkflow,
            UserRegistrationWorkflow,
            UserEmailVerificationWorkflow,
            UserLoginWorkflow
        ]
        
        # Initialize activity instances
        user_activities = UserActivities()
        auth_activities = AuthActivities()  
        ai_auth_activities = AIAuthActivities()
        simple_email_activities = EmailActivities()
        
        email_activities_list = [
            # Email activities
            email_activities.send_smtp_email,
            email_activities.send_console_email,
            email_activities.log_verification_link,
            email_activities.check_password_reset_rate_limit,
            email_activities.record_email_metric,
            email_activities.record_security_event,
            # Simple email activities
            simple_email_activities.send_verification_email,
            simple_email_activities.send_password_reset_email,
            simple_email_activities.send_welcome_email,
            # User activities
            user_activities.create_user,
            user_activities.update_user,
            user_activities.verify_user_email,
            user_activities.set_password_reset_token,
            user_activities.reset_user_password,
            # Auth activities
            auth_activities.generate_verification_token,
            auth_activities.generate_password_reset_token,
            auth_activities.validate_password_reset_token,
            auth_activities.generate_oauth_authorization_code,
            auth_activities.exchange_authorization_code,
            auth_activities.revoke_access_token,
            auth_activities.authenticate_user,
            auth_activities.create_login_tokens,
            auth_activities.store_login_session,
            # AI Auth activities
            ai_auth_activities.analyze_registration_fraud_risk,
            ai_auth_activities.adaptive_authentication_challenge,
            ai_auth_activities.analyze_password_security_ai,
            ai_auth_activities.detect_account_takeover,
            ai_auth_activities.optimize_email_delivery_strategy,
            ai_auth_activities.analyze_verification_behavior
        ]
        logger.info("Email workflows and activities loaded")
    except ImportError as e:
        logger.warning(f"Email workflows not available: {e}")
        email_workflows = []
        email_activities_list = []
    
    # Import analytics workflows if available
    try:
        from app.temporal.workflows.analytics_workflow import (
            FraudAnalyticsWorkflow,
            FraudInvestigationWorkflow
        )
        from app.temporal.activities.analytics_activities import analytics_activities
        
        analytics_workflows = [FraudAnalyticsWorkflow, FraudInvestigationWorkflow]
        analytics_activities_list = [
            analytics_activities.aggregate_fraud_data,
            analytics_activities.aggregate_auth_data,
            analytics_activities.persist_analytics_aggregation,
            analytics_activities.analyze_fraud_patterns,
            analytics_activities.generate_investigation_report,
            analytics_activities.send_fraud_alert
        ]
        logger.info("Analytics workflows and activities loaded")
    except ImportError as e:
        logger.warning(f"Analytics workflows not available: {e}")
        analytics_workflows = []
        analytics_activities_list = []
    
    client = await get_temporal_client()
    
    # Combine all workflows and activities
    all_workflows = [PingWorkflow] + email_workflows + analytics_workflows
    all_activities = email_activities_list + analytics_activities_list
    
    # Create worker with all available workflows
    worker = Worker(
        client,
        task_queue=settings.TEMPORAL_TASK_QUEUE,
        workflows=all_workflows,
        activities=all_activities
    )
    
    logger.info(f"Temporal worker created for task queue: {settings.TEMPORAL_TASK_QUEUE}")
    logger.info(f"Loaded {len(all_workflows)} workflows and {len(all_activities)} activities")
    return worker