import asyncio
import logging
from app.utils.safe_logging import configure_safe_logging
import os
from app.temporal.client import create_identity_operations_worker, create_worker
from app.config import settings

configure_safe_logging()
logger = logging.getLogger(__name__)

async def main():
    """Run Temporal worker"""
    worker_mode = os.getenv("TEMPORAL_WORKER_MODE", "both").lower()
    if worker_mode not in {"general", "identity", "both"}:
        raise ValueError("TEMPORAL_WORKER_MODE must be general, identity, or both")
    logger.info("Starting Temporal worker in %s mode", worker_mode)
    
    try:
        workers = []
        if worker_mode in {"general", "both"}:
            workers.append(await create_worker())
            logger.info("Worker started on task queue: %s", settings.TEMPORAL_TASK_QUEUE)
        if worker_mode in {"identity", "both"}:
            workers.append(await create_identity_operations_worker())
            logger.info(
                "Identity operations worker started on task queue: %s",
                settings.TEMPORAL_IDENTITY_OPS_TASK_QUEUE,
            )

        await asyncio.gather(*(worker.run() for worker in workers))
        
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as exc:
        logger.error("Worker failed exception_type=%s", type(exc).__name__)
        raise
    finally:
        logger.info("Worker shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())