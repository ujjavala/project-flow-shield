"""
GuardFlow Rate Limiting Activities
Temporal activities for rate limiting and abuse prevention
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import redis
import hashlib

from temporalio import activity

# Configure logging
logger = logging.getLogger(__name__)

# Redis connection for rate limiting storage
redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)

# Rate limit configurations by type and user tier
DEFAULT_RATE_LIMITS = {
    'login': {
        'free': {'limit': 10, 'window_size': 300},  # 10 attempts per 5 minutes
        'premium': {'limit': 20, 'window_size': 300},
        'admin': {'limit': 50, 'window_size': 300}
    },
    'api': {
        'free': {'limit': 100, 'window_size': 3600},  # 100 requests per hour
        'premium': {'limit': 1000, 'window_size': 3600},
        'admin': {'limit': 5000, 'window_size': 3600}
    },
    'registration': {
        'default': {'limit': 5, 'window_size': 3600}  # 5 registrations per hour per IP
    },
    'mfa': {
        'default': {'limit': 5, 'window_size': 300}  # 5 MFA attempts per 5 minutes
    }
}

@activity.defn
async def get_rate_limit_config(request: Dict[str, Any]) -> Dict[str, Any]:
    """Get rate limit configuration for a specific limit type and user"""

    limit_type = request['limit_type']
    identifier = request['identifier']
    action = request['action']

    logger.info(f"Getting rate limit config for {limit_type} - {identifier}")

    try:
        # Determine user tier based on identifier
        user_tier = await _get_user_tier(identifier)

        # Get base configuration
        if limit_type in DEFAULT_RATE_LIMITS:
            if user_tier in DEFAULT_RATE_LIMITS[limit_type]:
                config = DEFAULT_RATE_LIMITS[limit_type][user_tier].copy()
            else:
                config = DEFAULT_RATE_LIMITS[limit_type].get('default',
                    DEFAULT_RATE_LIMITS[limit_type][list(DEFAULT_RATE_LIMITS[limit_type].keys())[0]]).copy()
        else:
            # Default fallback
            config = {'limit': 100, 'window_size': 3600}

        # Apply geographic adjustments
        geo_adjustment = await _get_geographic_adjustment(identifier)
        if geo_adjustment:
            config['limit'] = int(config['limit'] * geo_adjustment['multiplier'])

        # Apply time-of-day adjustments
        tod_adjustment = await _get_time_of_day_adjustment()
        if tod_adjustment:
            config['limit'] = int(config['limit'] * tod_adjustment['multiplier'])

        logger.info(f"Rate limit config: {config}")
        return config

    except Exception as e:
        logger.error(f"Error getting rate limit config: {e}")
        # Return safe defaults on error
        return {'limit': 10, 'window_size': 300}

@activity.defn
async def check_rate_limit_usage(request: Dict[str, Any]) -> Dict[str, Any]:
    """Check current usage against rate limits using sliding window"""

    key = request['key']
    window_size = request['window_size']
    limit = request['limit']

    logger.info(f"Checking rate limit usage for {key}")

    try:
        # Use sliding window counter
        current_time = datetime.now()
        window_start = current_time - timedelta(seconds=window_size)

        # Redis key for the sliding window
        redis_key = f"rate_limit:{key}"

        # Get all timestamps in the current window
        timestamps = redis_client.zrangebyscore(
            redis_key,
            window_start.timestamp(),
            current_time.timestamp()
        )

        current_count = len(timestamps)

        # Calculate reset time (end of current window)
        reset_time = (current_time + timedelta(seconds=window_size)).isoformat()

        # Clean up old entries
        redis_client.zremrangebyscore(redis_key, 0, window_start.timestamp())
        redis_client.expire(redis_key, window_size + 60)  # Extra buffer for cleanup

        return {
            'count': current_count,
            'limit': limit,
            'reset_time': reset_time,
            'window_start': window_start.isoformat(),
            'remaining': max(0, limit - current_count)
        }

    except Exception as e:
        logger.error(f"Error checking rate limit usage: {e}")
        return {
            'count': 0,
            'limit': limit,
            'reset_time': (datetime.now() + timedelta(seconds=window_size)).isoformat(),
            'window_start': datetime.now().isoformat(),
            'remaining': limit
        }

@activity.defn
async def increment_rate_limit_counter(request: Dict[str, Any]) -> Dict[str, Any]:
    """Increment the rate limit counter for a request"""

    key = request['key']
    window_size = request['window_size']
    metadata = request.get('metadata', {})

    logger.info(f"Incrementing rate limit counter for {key}")

    try:
        current_time = datetime.now()
        redis_key = f"rate_limit:{key}"

        # Add current timestamp to the sliding window
        redis_client.zadd(redis_key, {current_time.isoformat(): current_time.timestamp()})
        redis_client.expire(redis_key, window_size + 60)

        # Store metadata if provided
        if metadata:
            metadata_key = f"rate_limit_meta:{key}:{current_time.timestamp()}"
            redis_client.setex(metadata_key, window_size + 60, json.dumps(metadata))

        return {
            'success': True,
            'timestamp': current_time.isoformat(),
            'key': key
        }

    except Exception as e:
        logger.error(f"Error incrementing rate limit counter: {e}")
        return {
            'success': False,
            'error': str(e),
            'key': key
        }

@activity.defn
async def assess_violation_severity(request: Dict[str, Any]) -> Dict[str, Any]:
    """Assess the severity of a rate limit violation"""

    key = request['key']
    limit_type = request['limit_type']
    identifier = request['identifier']
    current_count = request['current_count']

    logger.info(f"Assessing violation severity for {key}")

    try:
        # Check violation history
        violation_key = f"violations:{identifier}:{limit_type}"
        violation_history = redis_client.lrange(violation_key, 0, -1)

        # Count recent violations (last 24 hours)
        recent_violations = 0
        cutoff_time = datetime.now() - timedelta(hours=24)

        for violation_data in violation_history:
            try:
                violation_info = json.loads(violation_data)
                if datetime.fromisoformat(violation_info['timestamp']) > cutoff_time:
                    recent_violations += 1
            except (json.JSONDecodeError, KeyError):
                continue

        # Determine severity
        if recent_violations >= 10:
            severity = "critical"
            is_repeat_offender = True
            should_notify = True
        elif recent_violations >= 5:
            severity = "high"
            is_repeat_offender = True
            should_notify = True
        elif recent_violations >= 2:
            severity = "medium"
            is_repeat_offender = True
            should_notify = False
        else:
            severity = "low"
            is_repeat_offender = False
            should_notify = False

        # Record this violation
        violation_record = {
            'timestamp': datetime.now().isoformat(),
            'key': key,
            'current_count': current_count,
            'severity': severity
        }

        redis_client.lpush(violation_key, json.dumps(violation_record))
        redis_client.ltrim(violation_key, 0, 99)  # Keep only last 100 violations
        redis_client.expire(violation_key, 86400 * 7)  # Expire after 7 days

        return {
            'severity': severity,
            'is_repeat_offender': is_repeat_offender,
            'should_notify': should_notify,
            'violation_count': recent_violations + 1,
            'total_violations': len(violation_history)
        }

    except Exception as e:
        logger.error(f"Error assessing violation severity: {e}")
        return {
            'severity': 'low',
            'is_repeat_offender': False,
            'should_notify': False,
            'violation_count': 1,
            'total_violations': 1
        }

@activity.defn
async def apply_extended_timeout(request: Dict[str, Any]) -> Dict[str, Any]:
    """Apply extended timeout for repeat offenders"""

    key = request['key']
    identifier = request['identifier']
    violation_count = request['violation_count']
    base_timeout = request['base_timeout']

    logger.info(f"Applying extended timeout for {key}")

    try:
        # Calculate progressive timeout based on violation count
        # Formula: base_timeout * (2 ^ min(violation_count - 1, 6))
        multiplier = 2 ** min(violation_count - 1, 6)  # Cap at 2^6 = 64x
        timeout_seconds = base_timeout * multiplier

        # Cap maximum timeout at 24 hours
        timeout_seconds = min(timeout_seconds, 86400)

        # Set extended timeout in Redis
        timeout_key = f"extended_timeout:{identifier}"
        timeout_until = datetime.now() + timedelta(seconds=timeout_seconds)

        redis_client.setex(
            timeout_key,
            int(timeout_seconds),
            timeout_until.isoformat()
        )

        logger.info(f"Applied {timeout_seconds}s extended timeout for {identifier}")

        return {
            'success': True,
            'timeout_seconds': int(timeout_seconds),
            'timeout_until': timeout_until.isoformat(),
            'multiplier': multiplier
        }

    except Exception as e:
        logger.error(f"Error applying extended timeout: {e}")
        return {
            'success': False,
            'timeout_seconds': base_timeout,
            'error': str(e)
        }

@activity.defn
async def send_rate_limit_notification(request: Dict[str, Any]) -> Dict[str, Any]:
    """Send notification for rate limit violation"""

    identifier = request['identifier']
    limit_type = request['limit_type']
    severity = request['violation_severity']
    blocked_duration = request['blocked_duration']

    logger.info(f"Sending rate limit notification for {identifier}")

    try:
        # Prepare notification content
        notification = {
            'type': 'rate_limit_violation',
            'identifier': identifier,
            'limit_type': limit_type,
            'severity': severity,
            'blocked_duration': blocked_duration,
            'timestamp': datetime.now().isoformat(),
            'message': f"Rate limit exceeded for {limit_type}. Blocked for {blocked_duration} seconds."
        }

        # Store notification for admin dashboard
        notification_key = f"notifications:rate_limit"
        redis_client.lpush(notification_key, json.dumps(notification))
        redis_client.ltrim(notification_key, 0, 999)  # Keep last 1000 notifications
        redis_client.expire(notification_key, 86400 * 30)  # Expire after 30 days

        # TODO: Add email/webhook notification for critical violations
        if severity == "critical":
            logger.warning(f"CRITICAL rate limit violation: {identifier} - {limit_type}")

        return {
            'success': True,
            'notification_sent': True,
            'severity': severity
        }

    except Exception as e:
        logger.error(f"Error sending rate limit notification: {e}")
        return {
            'success': False,
            'error': str(e)
        }

@activity.defn
async def log_rate_limit_event(request: Dict[str, Any]) -> Dict[str, Any]:
    """Log rate limiting events for monitoring and analytics"""

    event_type = request['event']
    key = request['key']
    limit_type = request['limit_type']

    logger.info(f"Logging rate limit event: {event_type} for {key}")

    try:
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event_type,
            'key': key,
            'limit_type': limit_type,
            **{k: v for k, v in request.items() if k not in ['event', 'key', 'limit_type']}
        }

        # Store in Redis for real-time monitoring
        log_key = f"rate_limit_logs:{limit_type}"
        redis_client.lpush(log_key, json.dumps(log_entry))
        redis_client.ltrim(log_key, 0, 9999)  # Keep last 10000 events
        redis_client.expire(log_key, 86400 * 7)  # Expire after 7 days

        # Store daily metrics
        date_key = datetime.now().strftime('%Y-%m-%d')
        metrics_key = f"rate_limit_metrics:{date_key}:{limit_type}"
        redis_client.hincrby(metrics_key, event_type, 1)
        redis_client.expire(metrics_key, 86400 * 30)  # Keep for 30 days

        return {
            'success': True,
            'logged': True,
            'event_type': event_type
        }

    except Exception as e:
        logger.error(f"Error logging rate limit event: {e}")
        return {
            'success': False,
            'error': str(e)
        }

@activity.defn
async def get_expired_rate_limit_keys(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get all expired rate limit keys for cleanup"""

    logger.info("Getting expired rate limit keys")

    try:
        expired_keys = []
        pattern = "rate_limit:*"

        # Use Redis SCAN to iterate through all rate limit keys
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor, match=pattern, count=100)

            for key in keys:
                try:
                    # Check if key has expired or should be cleaned
                    ttl = redis_client.ttl(key)
                    if ttl == -1:  # No expiration set
                        expired_keys.append({'key': key, 'reason': 'no_expiration'})
                    elif ttl < 60:  # Expires in less than 1 minute
                        expired_keys.append({'key': key, 'reason': 'expiring_soon'})
                except Exception:
                    continue

            if cursor == 0:
                break

        return expired_keys[:1000]  # Limit to 1000 keys per run

    except Exception as e:
        logger.error(f"Error getting expired rate limit keys: {e}")
        return []

@activity.defn
async def reset_rate_limit_counter(request: Dict[str, Any]) -> Dict[str, Any]:
    """Reset a specific rate limit counter"""

    key = request['key']
    reason = request.get('reason', 'cleanup')

    logger.info(f"Resetting rate limit counter: {key}")

    try:
        # Delete the rate limit key
        deleted = redis_client.delete(key)

        # Also clean up related metadata
        if key.startswith('rate_limit:'):
            base_key = key.replace('rate_limit:', '')
            metadata_pattern = f"rate_limit_meta:{base_key}:*"

            cursor = 0
            while True:
                cursor, meta_keys = redis_client.scan(cursor, match=metadata_pattern, count=50)
                if meta_keys:
                    redis_client.delete(*meta_keys)
                if cursor == 0:
                    break

        return {
            'success': True,
            'key': key,
            'deleted': bool(deleted),
            'reason': reason
        }

    except Exception as e:
        logger.error(f"Error resetting rate limit counter: {e}")
        return {
            'success': False,
            'key': key,
            'error': str(e)
        }

@activity.defn
async def cleanup_old_violations(request: Dict[str, Any]) -> Dict[str, Any]:
    """Clean up old violation records"""

    max_age_hours = request['max_age_hours']

    logger.info(f"Cleaning up violations older than {max_age_hours} hours")

    try:
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        cleaned_count = 0

        # Find all violation keys
        pattern = "violations:*"
        cursor = 0

        while True:
            cursor, keys = redis_client.scan(cursor, match=pattern, count=100)

            for key in keys:
                try:
                    # Get violations and filter out old ones
                    violations = redis_client.lrange(key, 0, -1)
                    cleaned_violations = []

                    for violation_data in violations:
                        try:
                            violation_info = json.loads(violation_data)
                            if datetime.fromisoformat(violation_info['timestamp']) > cutoff_time:
                                cleaned_violations.append(violation_data)
                        except (json.JSONDecodeError, KeyError):
                            continue

                    # Update the list if we removed any violations
                    if len(cleaned_violations) != len(violations):
                        redis_client.delete(key)
                        if cleaned_violations:
                            redis_client.lpush(key, *cleaned_violations)
                            redis_client.expire(key, 86400 * 7)
                        cleaned_count += len(violations) - len(cleaned_violations)

                except Exception:
                    continue

            if cursor == 0:
                break

        return {
            'success': True,
            'cleaned_count': cleaned_count,
            'cutoff_time': cutoff_time.isoformat()
        }

    except Exception as e:
        logger.error(f"Error cleaning up old violations: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# Adaptive rate limiting activities

@activity.defn
async def analyze_system_load(request: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze current system load for adaptive rate limiting"""

    logger.info("Analyzing system load")

    try:
        # Mock system metrics - in production, integrate with actual monitoring
        import psutil

        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        # Determine load level
        if cpu_percent > 80 or memory.percent > 85:
            load_level = "high"
            load_multiplier = 0.5  # Reduce limits by 50%
        elif cpu_percent > 60 or memory.percent > 70:
            load_level = "medium"
            load_multiplier = 0.75  # Reduce limits by 25%
        else:
            load_level = "low"
            load_multiplier = 1.0  # No reduction

        return {
            'load_level': load_level,
            'load_multiplier': load_multiplier,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error analyzing system load: {e}")
        return {
            'load_level': 'unknown',
            'load_multiplier': 1.0,
            'error': str(e)
        }

@activity.defn
async def analyze_user_behavior_patterns(request: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze user behavior patterns for adaptive rate limiting"""

    logger.info("Analyzing user behavior patterns")

    try:
        # Analyze recent rate limit events
        patterns = {}
        current_time = datetime.now()

        # Get rate limit logs from last hour
        for limit_type in ['login', 'api', 'registration', 'mfa']:
            log_key = f"rate_limit_logs:{limit_type}"
            recent_logs = redis_client.lrange(log_key, 0, 999)

            violations = 0
            allowed = 0

            for log_data in recent_logs:
                try:
                    log_entry = json.loads(log_data)
                    log_time = datetime.fromisoformat(log_entry['timestamp'])

                    # Only look at last hour
                    if current_time - log_time <= timedelta(hours=1):
                        if log_entry['event'] == 'violation':
                            violations += 1
                        elif log_entry['event'] == 'allowed':
                            allowed += 1
                except (json.JSONDecodeError, KeyError):
                    continue

            total_requests = violations + allowed
            violation_rate = violations / max(total_requests, 1)

            patterns[limit_type] = {
                'violation_rate': violation_rate,
                'total_requests': total_requests,
                'violations': violations
            }

        # Overall analysis
        overall_violation_rate = sum(p['violations'] for p in patterns.values()) / max(
            sum(p['total_requests'] for p in patterns.values()), 1
        )

        if overall_violation_rate > 0.3:
            behavior_level = "high_abuse"
            behavior_multiplier = 0.6
        elif overall_violation_rate > 0.1:
            behavior_level = "moderate_abuse"
            behavior_multiplier = 0.8
        else:
            behavior_level = "normal"
            behavior_multiplier = 1.0

        return {
            'behavior_level': behavior_level,
            'behavior_multiplier': behavior_multiplier,
            'overall_violation_rate': overall_violation_rate,
            'patterns_by_type': patterns,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error analyzing user behavior patterns: {e}")
        return {
            'behavior_level': 'unknown',
            'behavior_multiplier': 1.0,
            'error': str(e)
        }

@activity.defn
async def calculate_adaptive_limits(request: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate new adaptive limits based on system metrics and behavior"""

    system_metrics = request['system_metrics']
    behavior_analysis = request['behavior_analysis']
    current_limits = request['current_limits']

    logger.info("Calculating adaptive limits")

    try:
        should_update = False
        new_limits = current_limits.copy()

        # Calculate overall multiplier
        system_multiplier = system_metrics.get('load_multiplier', 1.0)
        behavior_multiplier = behavior_analysis.get('behavior_multiplier', 1.0)

        overall_multiplier = system_multiplier * behavior_multiplier

        # Update limits if multiplier differs significantly from 1.0
        if abs(overall_multiplier - 1.0) > 0.1:
            should_update = True

            for limit_type, config in DEFAULT_RATE_LIMITS.items():
                for user_type, limits in config.items():
                    key = f"{limit_type}_{user_type}"
                    new_limit = int(limits['limit'] * overall_multiplier)
                    new_limits[key] = {
                        'limit': new_limit,
                        'window_size': limits['window_size'],
                        'original_limit': limits['limit'],
                        'multiplier': overall_multiplier
                    }

        reason = f"System load: {system_metrics.get('load_level', 'unknown')}, " \
                f"Behavior: {behavior_analysis.get('behavior_level', 'unknown')}"

        return {
            'should_update': should_update,
            'limits': new_limits,
            'overall_multiplier': overall_multiplier,
            'system_multiplier': system_multiplier,
            'behavior_multiplier': behavior_multiplier,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error calculating adaptive limits: {e}")
        return {
            'should_update': False,
            'limits': current_limits,
            'error': str(e)
        }

@activity.defn
async def update_rate_limits(request: Dict[str, Any]) -> Dict[str, Any]:
    """Update rate limits with new adaptive values"""

    new_limits = request['limits']
    reason = request.get('reason', 'Adaptive adjustment')

    logger.info(f"Updating rate limits: {reason}")

    try:
        # Store new limits in Redis
        adaptive_limits_key = "adaptive_rate_limits"
        redis_client.hset(adaptive_limits_key, mapping={
            k: json.dumps(v) for k, v in new_limits.items()
        })
        redis_client.expire(adaptive_limits_key, 86400)  # Expire after 24 hours

        # Log the adaptation
        adaptation_log = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'limits_count': len(new_limits),
            'limits': new_limits
        }

        log_key = "rate_limit_adaptations"
        redis_client.lpush(log_key, json.dumps(adaptation_log))
        redis_client.ltrim(log_key, 0, 99)  # Keep last 100 adaptations
        redis_client.expire(log_key, 86400 * 30)  # Keep for 30 days

        return {
            'success': True,
            'updated_count': len(new_limits),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error updating rate limits: {e}")
        return {
            'success': False,
            'error': str(e)
        }

@activity.defn
async def log_rate_limit_adaptation(request: Dict[str, Any]) -> Dict[str, Any]:
    """Log rate limit adaptation events"""

    logger.info("Logging rate limit adaptation")

    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            **request
        }

        # Store adaptation log
        log_key = "rate_limit_adaptation_history"
        redis_client.lpush(log_key, json.dumps(log_entry))
        redis_client.ltrim(log_key, 0, 999)  # Keep last 1000 adaptations
        redis_client.expire(log_key, 86400 * 30)  # Keep for 30 days

        return {
            'success': True,
            'logged': True
        }

    except Exception as e:
        logger.error(f"Error logging adaptation: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# Helper functions

async def _get_user_tier(identifier: str) -> str:
    """Determine user tier based on identifier"""

    # Check if identifier is a user ID (numeric) or IP address
    if identifier.replace('.', '').replace(':', '').isdigit():
        # IP address - default to free tier
        return 'free'

    try:
        # Try to get user info from Redis cache
        user_key = f"user_tier:{identifier}"
        tier = redis_client.get(user_key)
        if tier:
            return tier

        # Default to free tier if not found
        return 'free'

    except Exception:
        return 'free'

async def _get_geographic_adjustment(identifier: str) -> Optional[Dict[str, Any]]:
    """Get geographic-based rate limit adjustments"""

    try:
        # Mock geographic detection - in production, use IP geolocation service
        if identifier.startswith('192.168.'):  # Local network
            return {'multiplier': 2.0, 'reason': 'trusted_network'}

        # Default: no adjustment
        return None

    except Exception:
        return None

async def _get_time_of_day_adjustment() -> Optional[Dict[str, Any]]:
    """Get time-of-day based rate limit adjustments"""

    try:
        current_hour = datetime.now().hour

        # Lower limits during typical business hours (9 AM - 5 PM)
        if 9 <= current_hour <= 17:
            return {'multiplier': 1.5, 'reason': 'business_hours'}

        # Reduce limits during off-hours to prevent abuse
        if current_hour < 6 or current_hour > 22:
            return {'multiplier': 0.7, 'reason': 'off_hours'}

        return None

    except Exception:
        return None