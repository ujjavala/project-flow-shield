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


async def create_identity_operations_worker() -> Worker:
    """Create the worker for durable, non-secret identity operations."""
    from app.temporal.activities.privileged_access_advisory_activities import (
        review_privileged_access_advisor,
    )
    from app.temporal.activities.privileged_access_activities import (
        grant_privileged_access,
        mark_privileged_access_expired,
        persist_approval_decision,
        record_privileged_access_notification,
        revoke_privileged_access,
        validate_privileged_access,
    )
    from app.temporal.workflows.privileged_access import PrivilegedAccessWorkflow

    client = await get_temporal_client()
    return Worker(
        client,
        task_queue=settings.TEMPORAL_IDENTITY_OPS_TASK_QUEUE,
        workflows=[PrivilegedAccessWorkflow],
        activities=[
            validate_privileged_access,
            review_privileged_access_advisor,
            persist_approval_decision,
            mark_privileged_access_expired,
            grant_privileged_access,
            revoke_privileged_access,
            record_privileged_access_notification,
        ],
    )

async def create_worker() -> Worker:
    """Create the general worker from a history-safe allowlist.

    Credential, token, direct-identifier, behavioral, analytics, and rate-limit
    payloads are intentionally excluded from durable Temporal history.
    """
    from app.temporal.workflows.ping import PingWorkflow
    client = await get_temporal_client()
    worker = Worker(
        client,
        task_queue=settings.TEMPORAL_TASK_QUEUE,
        workflows=[PingWorkflow],
        activities=[],
    )
    logger.info(f"Temporal worker created for task queue: {settings.TEMPORAL_TASK_QUEUE}")
    logger.info("Loaded one history-safe general workflow")
    return worker