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
    from app.temporal.activities.email import EmailActivities
    from app.temporal.activities.user import UserActivities
    from app.temporal.activities.auth import AuthActivities
    from app.temporal.workflows.user_registration import UserRegistrationWorkflow
    from app.temporal.workflows.password_reset import PasswordResetWorkflow
    from app.temporal.workflows.user_registration import EmailVerificationWorkflow
    
    client = await get_temporal_client()
    
    # Initialize activities
    email_activities = EmailActivities()
    user_activities = UserActivities()
    auth_activities = AuthActivities()
    
    # Create worker
    worker = Worker(
        client,
        task_queue=settings.TEMPORAL_TASK_QUEUE,
        workflows=[
            UserRegistrationWorkflow,
            PasswordResetWorkflow,
            EmailVerificationWorkflow
        ],
        activities=[
            email_activities.send_verification_email,
            email_activities.send_password_reset_email,
            email_activities.send_welcome_email,
            user_activities.create_user,
            user_activities.update_user,
            user_activities.verify_user_email,
            auth_activities.generate_verification_token,
            auth_activities.generate_password_reset_token,
            auth_activities.validate_password_reset_token
        ]
    )
    
    logger.info(f"Temporal worker created for task queue: {settings.TEMPORAL_TASK_QUEUE}")
    return worker