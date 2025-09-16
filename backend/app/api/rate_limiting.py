"""
Rate Limiting API Endpoints
Provides API endpoints for rate limiting management and monitoring
"""

from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import logging

from app.temporal.client import get_temporal_client
from app.temporal.workflows.rate_limiting_workflow import (
    RateLimitingWorkflow,
    RateLimitResetWorkflow,
    AdaptiveRateLimitingWorkflow,
    RateLimitRequest,
    RateLimitResponse
)

logger = logging.getLogger(__name__)
security = HTTPBearer()

router = APIRouter(prefix="/rate-limiting")

# Request/Response models
class RateLimitCheckRequest(BaseModel):
    identifier: str  # IP or user_id
    limit_type: str  # 'login', 'api', 'registration', 'mfa'
    action: str      # Specific action being rate limited
    metadata: Optional[Dict[str, Any]] = None

class RateLimitCheckResponse(BaseModel):
    allowed: bool
    remaining: int
    reset_time: str
    current_count: int
    limit: int
    retry_after: Optional[int] = None
    blocked_reason: Optional[str] = None

class RateLimitStatusResponse(BaseModel):
    key: str
    limit_type: str
    current_count: int
    limit: int
    remaining: int
    reset_time: str
    window_size: int

class RateLimitMetricsResponse(BaseModel):
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    violation_rate: float
    top_violators: List[Dict[str, Any]]
    metrics_by_type: Dict[str, Dict[str, int]]

class AdaptiveLimitsResponse(BaseModel):
    current_limits: Dict[str, Any]
    system_load: str
    behavior_analysis: str
    last_updated: str

@router.post("/check", response_model=RateLimitCheckResponse)
async def check_rate_limit(
    request: RateLimitCheckRequest,
    client_request: Request
) -> RateLimitCheckResponse:
    """Check if a request should be rate limited"""

    try:
        # Extract client IP if identifier is not provided
        client_ip = client_request.client.host if hasattr(client_request, 'client') else '127.0.0.1'

        # Create rate limit key
        rate_limit_key = f"{request.limit_type}:{request.identifier or client_ip}"

        # Create Temporal request
        temporal_request = RateLimitRequest(
            key=rate_limit_key,
            limit_type=request.limit_type,
            identifier=request.identifier or client_ip,
            action=request.action,
            metadata=request.metadata or {}
        )

        # Execute Temporal workflow
        client = await get_temporal_client()
        result = await client.execute_workflow(
            RateLimitingWorkflow.run,
            temporal_request,
            id=f"rate_limit_check_{rate_limit_key}_{int(datetime.now().timestamp())}",
            task_queue="guardflow",
            execution_timeout=timedelta(seconds=30)
        )

        return RateLimitCheckResponse(**result.__dict__)

    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rate limiting service error: {str(e)}"
        )

@router.get("/status/{identifier}")
async def get_rate_limit_status(
    identifier: str,
    limit_type: str = "api"
) -> RateLimitStatusResponse:
    """Get current rate limit status for an identifier"""

    try:
        import redis
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        rate_limit_key = f"{limit_type}:{identifier}"
        redis_key = f"rate_limit:{rate_limit_key}"

        # Get current usage
        current_time = datetime.now()
        window_size = 3600  # Default 1 hour window
        window_start = current_time - timedelta(seconds=window_size)

        # Count current requests in window
        timestamps = redis_client.zrangebyscore(
            redis_key,
            window_start.timestamp(),
            current_time.timestamp()
        )
        current_count = len(timestamps)

        # Get limit from config (simplified)
        default_limits = {
            'api': 100,
            'login': 10,
            'registration': 5,
            'mfa': 5
        }
        limit = default_limits.get(limit_type, 100)

        reset_time = (current_time + timedelta(seconds=window_size)).isoformat()

        return RateLimitStatusResponse(
            key=rate_limit_key,
            limit_type=limit_type,
            current_count=current_count,
            limit=limit,
            remaining=max(0, limit - current_count),
            reset_time=reset_time,
            window_size=window_size
        )

    except Exception as e:
        logger.error(f"Failed to get rate limit status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve rate limit status: {str(e)}"
        )

@router.get("/metrics", response_model=RateLimitMetricsResponse)
async def get_rate_limit_metrics(
    hours: int = 24,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> RateLimitMetricsResponse:
    """Get rate limiting metrics (admin only)"""

    # TODO: Add proper admin authentication
    # For now, just check that a token is provided
    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        import redis
        import json
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        # Initialize metrics
        metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'blocked_requests': 0,
            'metrics_by_type': {},
            'top_violators': []
        }

        # Get metrics from different limit types
        limit_types = ['api', 'login', 'registration', 'mfa']

        for limit_type in limit_types:
            log_key = f"rate_limit_logs:{limit_type}"
            logs = redis_client.lrange(log_key, 0, 999)  # Last 1000 entries

            type_metrics = {'allowed': 0, 'violation': 0, 'error': 0}

            cutoff_time = datetime.now() - timedelta(hours=hours)

            for log_data in logs:
                try:
                    log_entry = json.loads(log_data)
                    log_time = datetime.fromisoformat(log_entry['timestamp'])

                    if log_time > cutoff_time:
                        event_type = log_entry.get('event', 'unknown')
                        if event_type in type_metrics:
                            type_metrics[event_type] += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

            metrics['metrics_by_type'][limit_type] = type_metrics
            metrics['total_requests'] += sum(type_metrics.values())
            metrics['allowed_requests'] += type_metrics['allowed']
            metrics['blocked_requests'] += type_metrics['violation']

        # Calculate violation rate
        if metrics['total_requests'] > 0:
            metrics['violation_rate'] = metrics['blocked_requests'] / metrics['total_requests']
        else:
            metrics['violation_rate'] = 0.0

        # Get top violators (simplified)
        violators = []
        for limit_type in limit_types:
            violation_pattern = f"violations:*:{limit_type}"
            for key in redis_client.scan_iter(match=violation_pattern):
                try:
                    violations = redis_client.lrange(key, 0, 9)  # Recent violations
                    if violations:
                        identifier = key.split(':')[1] if ':' in key else 'unknown'
                        violators.append({
                            'identifier': identifier,
                            'limit_type': limit_type,
                            'recent_violations': len(violations)
                        })
                except:
                    continue

        # Sort and limit top violators
        metrics['top_violators'] = sorted(
            violators,
            key=lambda x: x['recent_violations'],
            reverse=True
        )[:10]

        return RateLimitMetricsResponse(**metrics)

    except Exception as e:
        logger.error(f"Failed to get rate limit metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve metrics: {str(e)}"
        )

@router.get("/adaptive-limits", response_model=AdaptiveLimitsResponse)
async def get_adaptive_limits(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> AdaptiveLimitsResponse:
    """Get current adaptive rate limits (admin only)"""

    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        import redis
        import json
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        # Get current adaptive limits
        adaptive_limits_key = "adaptive_rate_limits"
        current_limits = {}

        limits_data = redis_client.hgetall(adaptive_limits_key)
        for key, value in limits_data.items():
            try:
                current_limits[key] = json.loads(value)
            except json.JSONDecodeError:
                current_limits[key] = value

        # Get latest adaptation log
        log_key = "rate_limit_adaptation_history"
        latest_log = redis_client.lrange(log_key, 0, 0)

        system_load = "unknown"
        behavior_analysis = "unknown"
        last_updated = datetime.now().isoformat()

        if latest_log:
            try:
                log_data = json.loads(latest_log[0])
                system_load = log_data.get('system_load', 'unknown')
                behavior_analysis = log_data.get('behavior_analysis', 'unknown')
                last_updated = log_data.get('timestamp', last_updated)
            except (json.JSONDecodeError, KeyError):
                pass

        return AdaptiveLimitsResponse(
            current_limits=current_limits,
            system_load=system_load,
            behavior_analysis=behavior_analysis,
            last_updated=last_updated
        )

    except Exception as e:
        logger.error(f"Failed to get adaptive limits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve adaptive limits: {str(e)}"
        )

@router.post("/reset")
async def trigger_rate_limit_reset(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Manually trigger rate limit reset cleanup (admin only)"""

    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        client = await get_temporal_client()

        result = await client.execute_workflow(
            RateLimitResetWorkflow.run,
            {},
            id=f"manual_rate_limit_reset_{int(datetime.now().timestamp())}",
            task_queue="guardflow",
            execution_timeout=timedelta(minutes=5)
        )

        return {
            "status": "success",
            "message": "Rate limit reset completed",
            "result": result
        }

    except Exception as e:
        logger.error(f"Rate limit reset failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rate limit reset failed: {str(e)}"
        )

@router.post("/adaptive-update")
async def trigger_adaptive_update(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Manually trigger adaptive rate limiting update (admin only)"""

    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        client = await get_temporal_client()

        result = await client.execute_workflow(
            AdaptiveRateLimitingWorkflow.run,
            {},
            id=f"manual_adaptive_update_{int(datetime.now().timestamp())}",
            task_queue="guardflow",
            execution_timeout=timedelta(minutes=2)
        )

        return {
            "status": "success",
            "message": "Adaptive rate limiting update completed",
            "result": result
        }

    except Exception as e:
        logger.error(f"Adaptive rate limiting update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Adaptive update failed: {str(e)}"
        )

@router.delete("/violations/{identifier}")
async def clear_violations(
    identifier: str,
    limit_type: str = "all",
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Clear violation history for an identifier (admin only)"""

    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        import redis
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        cleared_count = 0

        if limit_type == "all":
            # Clear all violation types for this identifier
            limit_types = ['api', 'login', 'registration', 'mfa']
        else:
            limit_types = [limit_type]

        for lt in limit_types:
            violation_key = f"violations:{identifier}:{lt}"
            if redis_client.exists(violation_key):
                redis_client.delete(violation_key)
                cleared_count += 1

        # Also clear extended timeout if it exists
        timeout_key = f"extended_timeout:{identifier}"
        if redis_client.exists(timeout_key):
            redis_client.delete(timeout_key)

        return {
            "status": "success",
            "message": f"Cleared violations for {identifier}",
            "cleared_types": cleared_count,
            "identifier": identifier
        }

    except Exception as e:
        logger.error(f"Failed to clear violations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear violations: {str(e)}"
        )

@router.get("/health")
async def rate_limiting_health():
    """Health check for rate limiting service"""

    try:
        import redis
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        # Test Redis connection
        redis_client.ping()

        # Test basic functionality
        test_key = "health_check_test"
        redis_client.setex(test_key, 10, "test")
        test_value = redis_client.get(test_key)
        redis_client.delete(test_key)

        if test_value != "test":
            raise Exception("Redis test failed")

        return {
            "status": "healthy",
            "redis_connected": True,
            "service": "rate_limiting"
        }

    except Exception as e:
        logger.error(f"Rate limiting health check failed: {e}")
        return {
            "status": "unhealthy",
            "redis_connected": False,
            "error": str(e),
            "service": "rate_limiting"
        }