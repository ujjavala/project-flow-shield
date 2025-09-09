from temporalio import workflow
from datetime import timedelta
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class PingRequest:
    message: str

@workflow.defn
class PingWorkflow:
    """Simple ping workflow for testing Temporal connectivity"""
    
    @workflow.run
    async def run(self, request: PingRequest) -> dict:
        """Execute ping workflow"""
        
        try:
            # Simple workflow that just processes the message
            workflow.logger.info(f"Ping workflow received: {request.message}")
            
            # Sleep for a bit to show async behavior
            await workflow.asyncio.sleep(1)
            
            result_message = f"Pong! Received: {request.message}"
            
            return {
                "success": True,
                "message": result_message,
                "timestamp": workflow.now().isoformat()
            }
            
        except Exception as e:
            workflow.logger.error(f"Ping workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Ping workflow failed"
            }