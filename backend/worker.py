import asyncio
import logging
from app.temporal.client import create_worker
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Run Temporal worker"""
    logger.info("Starting Temporal worker...")
    
    try:
        # Create worker
        worker = await create_worker()
        
        logger.info(f"Worker started on task queue: {settings.TEMPORAL_TASK_QUEUE}")
        
        # Run worker
        await worker.run()
        
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.error(f"Worker failed: {e}")
        raise
    finally:
        logger.info("Worker shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())