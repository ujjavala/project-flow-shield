"""
GuardFlow Rate Limiting Workflow
Temporal-powered rate limiting and abuse prevention system
"""

import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import logging

from temporalio import workflow
from temporalio.common import RetryPolicy

logger = logging.getLogger(__name__)

@dataclass
class RateLimitRequest:
    key: str  # Rate limit key (IP, user_id, etc.)
    limit_type: str  # 'login', 'api', 'registration', 'mfa'
    identifier: str  # IP address, user ID, etc.
    action: str  # The action being rate limited
    metadata: Dict[str, Any] = None

@dataclass
class RateLimitResponse:
    allowed: bool
    remaining: int
    reset_time: str
    current_count: int
    limit: int
    retry_after: Optional[int] = None
    blocked_reason: Optional[str] = None

@workflow.defn
class RateLimitingWorkflow:
    """Rate limiting workflow with Temporal reliability"""
    
    def __init__(self) -> None:
        self.current_state: Dict[str, Any] = {}
        self.violations: List[Dict[str, Any]] = []
        
    @workflow.run
    async def run(self, request: RateLimitRequest) -> RateLimitResponse:
        """Main rate limiting workflow execution"""
        
        logger.info(f"Rate limiting check for {request.key} - {request.action}")
        
        try:
            # Step 1: Get rate limit configuration
            limit_config = await workflow.execute_activity(
                "get_rate_limit_config",
                {
                    "limit_type": request.limit_type,
                    "identifier": request.identifier,
                    "action": request.action
                },
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            # Step 2: Check current usage
            current_usage = await workflow.execute_activity(
                "check_rate_limit_usage",
                {
                    "key": request.key,
                    "window_size": limit_config["window_size"],
                    "limit": limit_config["limit"]
                },
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(maximum_attempts=3)
            )
            
            # Step 3: Determine if request should be allowed
            is_allowed = current_usage["count"] < limit_config["limit"]
            
            if is_allowed:
                # Step 4a: Increment counter for allowed request
                await workflow.execute_activity(
                    "increment_rate_limit_counter",
                    {
                        "key": request.key,
                        "window_size": limit_config["window_size"],
                        "metadata": request.metadata
                    },
                    start_to_close_timeout=timedelta(seconds=10)
                )
                
                # Log successful request
                await workflow.execute_activity(
                    "log_rate_limit_event",
                    {
                        "event": "allowed",
                        "key": request.key,
                        "limit_type": request.limit_type,
                        "count": current_usage["count"] + 1,
                        "limit": limit_config["limit"],
                        "identifier": request.identifier
                    },
                    start_to_close_timeout=timedelta(seconds=5)
                )
                
                return RateLimitResponse(
                    allowed=True,
                    remaining=limit_config["limit"] - (current_usage["count"] + 1),
                    reset_time=current_usage["reset_time"],
                    current_count=current_usage["count"] + 1,
                    limit=limit_config["limit"]
                )
                
            else:
                # Step 4b: Handle rate limit violation
                violation_response = await self._handle_rate_limit_violation(
                    request, current_usage, limit_config
                )
                
                return violation_response
                
        except Exception as e:
            logger.error(f"Rate limiting workflow failed for {request.key}: {e}")
            
            # Log error
            await workflow.execute_activity(
                "log_rate_limit_event",
                {
                    "event": "error",
                    "key": request.key,
                    "error": str(e),
                    "limit_type": request.limit_type
                },
                start_to_close_timeout=timedelta(seconds=5)
            )
            
            # Default to allowing request on error (fail open)
            return RateLimitResponse(
                allowed=True,
                remaining=0,
                reset_time=datetime.now().isoformat(),
                current_count=0,
                limit=1000,  # Default high limit
                blocked_reason="Rate limiting service error - request allowed"
            )
    
    async def _handle_rate_limit_violation(
        self, 
        request: RateLimitRequest,
        current_usage: Dict[str, Any],
        limit_config: Dict[str, Any]
    ) -> RateLimitResponse:
        """Handle rate limit violation"""
        
        # Check if this is a repeated violation
        violation_severity = await workflow.execute_activity(
            "assess_violation_severity",
            {
                "key": request.key,
                "limit_type": request.limit_type,
                "identifier": request.identifier,
                "current_count": current_usage["count"]
            },
            start_to_close_timeout=timedelta(seconds=10)
        )
        
        # Apply progressive penalties
        if violation_severity["is_repeat_offender"]:
            # Extended timeout for repeat offenders
            extended_timeout = await workflow.execute_activity(
                "apply_extended_timeout",
                {
                    "key": request.key,
                    "identifier": request.identifier,
                    "violation_count": violation_severity["violation_count"],
                    "base_timeout": limit_config["window_size"]
                },
                start_to_close_timeout=timedelta(seconds=10)
            )
            
            retry_after = extended_timeout["timeout_seconds"]
            blocked_reason = f"Rate limit exceeded. Extended timeout applied due to repeated violations."
        else:
            retry_after = max(0, int((datetime.fromisoformat(current_usage["reset_time"]) - datetime.now()).total_seconds()))
            blocked_reason = f"Rate limit exceeded. Try again in {retry_after} seconds."
        
        # Send notification if needed
        if violation_severity["should_notify"]:
            await workflow.execute_activity(
                "send_rate_limit_notification",
                {
                    "identifier": request.identifier,
                    "limit_type": request.limit_type,
                    "violation_severity": violation_severity["severity"],
                    "blocked_duration": retry_after
                },
                start_to_close_timeout=timedelta(seconds=30)
            )
        
        # Log violation
        await workflow.execute_activity(
            "log_rate_limit_event",
            {
                "event": "violation",
                "key": request.key,
                "limit_type": request.limit_type,
                "count": current_usage["count"],
                "limit": limit_config["limit"],
                "identifier": request.identifier,
                "severity": violation_severity["severity"],
                "retry_after": retry_after
            },
            start_to_close_timeout=timedelta(seconds=5)
        )
        
        return RateLimitResponse(
            allowed=False,
            remaining=0,
            reset_time=current_usage["reset_time"],
            current_count=current_usage["count"],
            limit=limit_config["limit"],
            retry_after=retry_after,
            blocked_reason=blocked_reason
        )
    
    @workflow.query
    def get_current_state(self) -> Dict[str, Any]:
        """Query current workflow state"""
        return {
            "state": self.current_state,
            "violation_count": len(self.violations),
            "last_updated": datetime.now().isoformat()
        }

@workflow.defn
class RateLimitResetWorkflow:
    """Workflow to reset rate limit counters"""
    
    @workflow.run
    async def run(self, reset_request: Dict[str, Any]) -> Dict[str, Any]:
        """Reset rate limit counters for expired windows"""
        
        logger.info("Running rate limit reset workflow")
        
        try:
            # Get all expired rate limit keys
            expired_keys = await workflow.execute_activity(
                "get_expired_rate_limit_keys",
                {},
                start_to_close_timeout=timedelta(seconds=30)
            )
            
            reset_count = 0
            for key_info in expired_keys:
                # Reset each expired key
                await workflow.execute_activity(
                    "reset_rate_limit_counter",
                    key_info,
                    start_to_close_timeout=timedelta(seconds=10)
                )
                reset_count += 1
            
            # Clean up old violation records
            await workflow.execute_activity(
                "cleanup_old_violations",
                {"max_age_hours": 24},
                start_to_close_timeout=timedelta(seconds=20)
            )
            
            logger.info(f"Reset {reset_count} rate limit counters")
            
            return {
                "success": True,
                "reset_count": reset_count,
                "completed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Rate limit reset workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "completed_at": datetime.now().isoformat()
            }

@workflow.defn 
class AdaptiveRateLimitingWorkflow:
    """Adaptive rate limiting that adjusts based on system load and user behavior"""
    
    def __init__(self) -> None:
        self.adaptive_limits: Dict[str, int] = {}
        
    @workflow.run
    async def run(self, adaptation_request: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt rate limits based on current conditions"""
        
        logger.info("Running adaptive rate limiting workflow")
        
        try:
            # Analyze system load
            system_metrics = await workflow.execute_activity(
                "analyze_system_load",
                {},
                start_to_close_timeout=timedelta(seconds=15)
            )
            
            # Analyze user behavior patterns
            behavior_analysis = await workflow.execute_activity(
                "analyze_user_behavior_patterns",
                {},
                start_to_close_timeout=timedelta(seconds=20)
            )
            
            # Calculate new adaptive limits
            new_limits = await workflow.execute_activity(
                "calculate_adaptive_limits",
                {
                    "system_metrics": system_metrics,
                    "behavior_analysis": behavior_analysis,
                    "current_limits": self.adaptive_limits
                },
                start_to_close_timeout=timedelta(seconds=10)
            )
            
            # Apply new limits
            if new_limits["should_update"]:
                await workflow.execute_activity(
                    "update_rate_limits",
                    new_limits,
                    start_to_close_timeout=timedelta(seconds=15)
                )
                
                self.adaptive_limits = new_limits["limits"]
                
                # Log adaptation
                await workflow.execute_activity(
                    "log_rate_limit_adaptation",
                    {
                        "previous_limits": self.adaptive_limits,
                        "new_limits": new_limits["limits"],
                        "reason": new_limits["reason"],
                        "system_load": system_metrics["load_level"]
                    },
                    start_to_close_timeout=timedelta(seconds=5)
                )
            
            # Schedule next adaptation check
            await workflow.execute_child_workflow(
                AdaptiveRateLimitingWorkflow.run,
                {},
                id=f"adaptive_rate_limit_{int(datetime.now().timestamp())}",
                task_queue="guardflow",
                execution_timeout=timedelta(hours=1)
            )
            
            return {
                "success": True,
                "limits_updated": new_limits["should_update"],
                "new_limits": new_limits.get("limits", {}),
                "next_check_at": (datetime.now() + timedelta(hours=1)).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Adaptive rate limiting workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "completed_at": datetime.now().isoformat()
            }