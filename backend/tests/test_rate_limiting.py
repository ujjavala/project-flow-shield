"""
Comprehensive tests for Rate Limiting functionality
Tests workflows, activities, APIs, and middleware integration
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import Dict, Any

# Import test client and dependencies
from fastapi.testclient import TestClient
from app.main import app

# Import rate limiting components
from app.temporal.workflows.rate_limiting_workflow import (
    RateLimitingWorkflow,
    RateLimitResetWorkflow,
    AdaptiveRateLimitingWorkflow,
    RateLimitRequest,
    RateLimitResponse
)

# Import activities (we'll mock Redis for testing)
from app.temporal.activities import rate_limiting_activities

# Create test client
client = TestClient(app)

class TestRateLimitingWorkflows:
    """Test the rate limiting Temporal workflows"""

    @pytest.fixture
    def sample_rate_limit_request(self):
        """Create a sample rate limit request"""
        return RateLimitRequest(
            key="test_key",
            limit_type="api",
            identifier="test_user",
            action="GET_/test",
            metadata={"user_agent": "pytest"}
        )

    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client for testing"""
        mock_redis = Mock()
        mock_redis.ping.return_value = True
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis.zrangebyscore.return_value = []
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        mock_redis.lrange.return_value = []
        mock_redis.lpush.return_value = 1
        mock_redis.ltrim.return_value = True
        mock_redis.hset.return_value = True
        mock_redis.hgetall.return_value = {}
        mock_redis.exists.return_value = False
        mock_redis.scan_iter.return_value = []
        mock_redis.scan.return_value = (0, [])
        return mock_redis

    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_rate_limiting_workflow_allowed(self, mock_redis, sample_rate_limit_request):
        """Test rate limiting workflow when request should be allowed"""
        mock_redis.zrangebyscore.return_value = []  # Empty list = no previous requests

        workflow = RateLimitingWorkflow()

        # Mock the workflow activities
        with patch.object(workflow, '_handle_rate_limit_violation') as mock_violation:
            # Since we're testing allowed requests, this shouldn't be called
            mock_violation.return_value = None

            # Mock activity execution
            with patch('temporalio.workflow.execute_activity') as mock_execute:
                # Mock get_rate_limit_config
                mock_execute.side_effect = [
                    {'limit': 100, 'window_size': 3600},  # config
                    {'count': 5, 'reset_time': '2023-01-01T12:00:00'},  # usage
                    {'success': True},  # increment
                    {'success': True}   # log
                ]

                result = await workflow.run(sample_rate_limit_request)

                assert isinstance(result, RateLimitResponse)
                assert result.allowed == True
                assert result.remaining == 94  # 100 - 5 - 1
                assert result.current_count == 6  # 5 + 1

    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_rate_limiting_workflow_blocked(self, mock_redis, sample_rate_limit_request):
        """Test rate limiting workflow when request should be blocked"""
        # Mock Redis to return high usage count
        mock_redis.zrangebyscore.return_value = ['req1', 'req2'] * 50  # 100 requests

        workflow = RateLimitingWorkflow()

        with patch('temporalio.workflow.execute_activity') as mock_execute:
            # Mock activities
            mock_execute.side_effect = [
                {'limit': 100, 'window_size': 3600},  # config
                {'count': 100, 'reset_time': '2023-01-01T12:00:00'},  # usage (at limit)
                # Violation handling activities
                {'severity': 'medium', 'is_repeat_offender': False, 'should_notify': True, 'violation_count': 1},
                {'success': True},  # notification
                {'success': True}   # log
            ]

            result = await workflow.run(sample_rate_limit_request)

            assert isinstance(result, RateLimitResponse)
            assert result.allowed == False
            assert result.remaining == 0
            assert result.retry_after is not None

class TestRateLimitingActivities:
    """Test rate limiting activities"""

    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client for testing"""
        mock_redis = Mock()
        mock_redis.ping.return_value = True
        mock_redis.zrangebyscore.return_value = []
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        mock_redis.setex.return_value = True
        mock_redis.get.return_value = None
        mock_redis.delete.return_value = 1
        return mock_redis

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_get_rate_limit_config(self, mock_redis):
        """Test getting rate limit configuration"""
        request = {
            'limit_type': 'api',
            'identifier': 'test_user',
            'action': 'GET_/test'
        }

        result = await rate_limiting_activities.get_rate_limit_config(request)

        assert 'limit' in result
        assert 'window_size' in result
        assert result['limit'] > 0
        assert result['window_size'] > 0

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_check_rate_limit_usage_empty(self, mock_redis):
        """Test checking rate limit usage with no previous requests"""
        mock_redis.zrangebyscore.return_value = []

        request = {
            'key': 'test_key',
            'window_size': 3600,
            'limit': 100
        }

        result = await rate_limiting_activities.check_rate_limit_usage(request)

        assert result['count'] == 0
        assert result['limit'] == 100
        assert result['remaining'] == 100

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_check_rate_limit_usage_with_requests(self, mock_redis):
        """Test checking rate limit usage with existing requests"""
        mock_redis.zrangebyscore.return_value = ['req1', 'req2', 'req3']

        request = {
            'key': 'test_key',
            'window_size': 3600,
            'limit': 100
        }

        result = await rate_limiting_activities.check_rate_limit_usage(request)

        assert result['count'] == 3
        assert result['limit'] == 100
        assert result['remaining'] == 97

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_increment_rate_limit_counter(self, mock_redis):
        """Test incrementing rate limit counter"""
        request = {
            'key': 'test_key',
            'window_size': 3600,
            'metadata': {'user_agent': 'pytest'}
        }

        result = await rate_limiting_activities.increment_rate_limit_counter(request)

        assert result['success'] == True
        assert result['key'] == 'test_key'
        mock_redis.zadd.assert_called_once()

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_assess_violation_severity_first_time(self, mock_redis):
        """Test assessing violation severity for first-time violation"""
        mock_redis.lrange.return_value = []  # No previous violations

        request = {
            'key': 'test_key',
            'limit_type': 'api',
            'identifier': 'test_user',
            'current_count': 101
        }

        result = await rate_limiting_activities.assess_violation_severity(request)

        assert result['severity'] == 'low'
        assert result['is_repeat_offender'] == False
        assert result['should_notify'] == False
        assert result['violation_count'] == 1

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_assess_violation_severity_repeat_offender(self, mock_redis):
        """Test assessing violation severity for repeat offender"""
        # Mock 10 recent violations
        violations = [
            json.dumps({'timestamp': datetime.now().isoformat()})
            for _ in range(10)
        ]
        mock_redis.lrange.return_value = violations

        request = {
            'key': 'test_key',
            'limit_type': 'api',
            'identifier': 'test_user',
            'current_count': 101
        }

        result = await rate_limiting_activities.assess_violation_severity(request)

        assert result['severity'] == 'critical'
        assert result['is_repeat_offender'] == True
        assert result['should_notify'] == True

class TestRateLimitingAPI:
    """Test rate limiting API endpoints"""

    def test_rate_limiting_health_check(self):
        """Test rate limiting service health check"""
        with patch('redis.Redis') as mock_redis_class:
            mock_redis = Mock()
            mock_redis.ping.return_value = True
            mock_redis.setex.return_value = True
            mock_redis.get.return_value = "test"
            mock_redis.delete.return_value = 1
            mock_redis_class.return_value = mock_redis

            response = client.get("/rate-limiting/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["redis_connected"] == True

    def test_rate_limiting_check_request(self):
        """Test rate limiting check endpoint"""
        with patch('app.temporal.client.get_temporal_client') as mock_client:
            mock_temporal = Mock()
            mock_workflow = Mock()
            mock_workflow.result.return_value = {
                'allowed': True,
                'remaining': 95,
                'reset_time': '2023-01-01T12:00:00',
                'current_count': 5,
                'limit': 100
            }
            mock_temporal.start_workflow.return_value = mock_workflow
            mock_client.return_value = mock_temporal

            request_data = {
                "identifier": "test_user",
                "limit_type": "api",
                "action": "GET_/test"
            }

            response = client.post("/rate-limiting/check", json=request_data)
            assert response.status_code == 200
            data = response.json()
            assert data["allowed"] == True
            assert data["remaining"] == 95

    def test_get_rate_limit_status(self):
        """Test get rate limit status endpoint"""
        with patch('redis.Redis') as mock_redis_class:
            mock_redis = Mock()
            mock_redis.zrangebyscore.return_value = ['req1', 'req2', 'req3']
            mock_redis_class.return_value = mock_redis

            response = client.get("/rate-limiting/status/test_user?limit_type=api")
            assert response.status_code == 200
            data = response.json()
            assert data["current_count"] == 3
            assert data["limit"] == 100
            assert data["remaining"] == 97

    def test_get_rate_limit_metrics_unauthorized(self):
        """Test rate limit metrics endpoint without authorization"""
        response = client.get("/rate-limiting/metrics")
        assert response.status_code == 422  # Unauthorized due to missing auth

    def test_get_rate_limit_metrics_authorized(self):
        """Test rate limit metrics endpoint with authorization"""
        with patch('redis.Redis') as mock_redis_class:
            mock_redis = Mock()
            mock_redis.lrange.return_value = [
                json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'allowed'
                }),
                json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'violation'
                })
            ]
            mock_redis.scan_iter.return_value = []
            mock_redis_class.return_value = mock_redis

            headers = {"Authorization": "Bearer test_token"}
            response = client.get("/rate-limiting/metrics", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert "total_requests" in data
            assert "violation_rate" in data

class TestRateLimitingMiddleware:
    """Test rate limiting middleware"""

    def test_middleware_bypass_health_check(self):
        """Test that health checks bypass rate limiting"""
        response = client.get("/health")
        assert response.status_code == 200
        # Should not have rate limit headers
        assert "X-RateLimit-Limit" not in response.headers

    def test_middleware_bypass_docs(self):
        """Test that docs endpoints bypass rate limiting"""
        response = client.get("/docs")
        assert response.status_code == 200
        # Should not have rate limit headers
        assert "X-RateLimit-Limit" not in response.headers

    @patch('app.middleware.security.RateLimitingMiddleware._check_rate_limit')
    def test_middleware_allows_request(self, mock_check):
        """Test middleware allows request when rate limit check passes"""
        mock_check.return_value = {
            'allowed': True,
            'remaining': 95,
            'reset_time': '2023-01-01T12:00:00',
            'current_count': 5,
            'limit': 100
        }

        response = client.get("/user/profile")
        # Should have rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    @patch('app.middleware.security.RateLimitingMiddleware._check_rate_limit')
    def test_middleware_blocks_request(self, mock_check):
        """Test middleware blocks request when rate limit is exceeded"""
        mock_check.return_value = {
            'allowed': False,
            'remaining': 0,
            'reset_time': '2023-01-01T12:00:00',
            'current_count': 100,
            'limit': 100,
            'retry_after': 60,
            'blocked_reason': 'Rate limit exceeded'
        }

        response = client.get("/user/profile")
        assert response.status_code == 429
        data = response.json()
        assert data["error"] == "rate_limit_exceeded"
        assert "retry_after" in data

class TestRateLimitingIntegration:
    """Integration tests for rate limiting system"""

    @patch('app.temporal.client.get_temporal_client')
    @patch('redis.Redis')
    def test_end_to_end_rate_limiting(self, mock_redis_class, mock_temporal_client):
        """Test complete rate limiting flow end-to-end"""
        # Setup mocks
        mock_redis = Mock()
        mock_redis.ping.return_value = True
        mock_redis.zrangebyscore.return_value = []
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        mock_redis_class.return_value = mock_redis

        mock_temporal = Mock()
        mock_workflow = Mock()
        mock_workflow.result.return_value = RateLimitResponse(
            allowed=True,
            remaining=99,
            reset_time='2023-01-01T12:00:00',
            current_count=1,
            limit=100
        )
        mock_temporal.start_workflow.return_value = mock_workflow
        mock_temporal_client.return_value = mock_temporal

        # Make request that should be allowed
        response = client.get("/user/profile")

        # Should pass through with rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    def test_rate_limiting_configuration_loading(self):
        """Test that rate limiting configurations load correctly"""
        from app.temporal.activities.rate_limiting_activities import DEFAULT_RATE_LIMITS

        assert 'login' in DEFAULT_RATE_LIMITS
        assert 'api' in DEFAULT_RATE_LIMITS
        assert 'registration' in DEFAULT_RATE_LIMITS
        assert 'mfa' in DEFAULT_RATE_LIMITS

        # Check configuration structure
        for limit_type, configs in DEFAULT_RATE_LIMITS.items():
            for user_type, config in configs.items():
                assert 'limit' in config
                assert 'window_size' in config
                assert isinstance(config['limit'], int)
                assert isinstance(config['window_size'], int)

    def test_admin_dashboard_rate_limiting_endpoints(self):
        """Test admin dashboard rate limiting endpoints"""
        # Test rate limiting metrics endpoint (will fail auth but should exist)
        response = client.get("/admin/rate-limiting")
        assert response.status_code == 200  # Should return fallback data

        # Test rate limiting actions endpoint
        action_data = {
            "action": "reset_counters",
            "target": "all",
            "parameters": {}
        }
        response = client.post("/admin/rate-limiting/actions", json=action_data)
        # Should handle the request (may fail due to missing auth but endpoint exists)
        assert response.status_code in [200, 401, 500]

class TestRateLimitingErrorHandling:
    """Test error handling in rate limiting system"""

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_redis_connection_failure(self, mock_redis):
        """Test handling of Redis connection failures"""
        mock_redis.ping.side_effect = Exception("Connection failed")

        request = {
            'key': 'test_key',
            'window_size': 3600,
            'limit': 100
        }

        # Should return safe defaults on error
        result = await rate_limiting_activities.check_rate_limit_usage(request)
        assert result['count'] == 0
        assert result['limit'] == 100

    @patch('app.middleware.security.RateLimitingMiddleware._check_rate_limit')
    def test_middleware_error_handling(self, mock_check):
        """Test middleware error handling (fail open policy)"""
        mock_check.side_effect = Exception("Temporal connection failed")

        # Request should still be allowed when rate limiting fails
        response = client.get("/user/profile")
        assert response.status_code != 429  # Should not be rate limited due to error

    def test_api_error_handling(self):
        """Test API error handling"""
        # Test with invalid request data
        invalid_data = {
            "limit_type": "invalid_type",
            "action": "test"
            # Missing required identifier field
        }

        response = client.post("/rate-limiting/check", json=invalid_data)
        assert response.status_code == 422  # Validation error

    def test_temporal_workflow_error_handling(self):
        """Test Temporal workflow error handling"""
        # This would test the workflow's ability to handle activity failures
        # and return appropriate error responses
        pass

@pytest.mark.asyncio
class TestRateLimitingPerformance:
    """Performance tests for rate limiting system"""

    @pytest.mark.asyncio
    @patch('app.temporal.activities.rate_limiting_activities.redis_client')
    async def test_rate_limit_check_performance(self, mock_redis):
        """Test that rate limit checks complete quickly"""
        import time

        mock_redis.zrangebyscore.return_value = []

        request = {
            'key': 'test_key',
            'window_size': 3600,
            'limit': 100
        }

        start_time = time.time()
        result = await rate_limiting_activities.check_rate_limit_usage(request)
        end_time = time.time()

        # Should complete in under 100ms
        assert end_time - start_time < 0.1
        assert result['count'] == 0

    def test_middleware_performance(self):
        """Test middleware performance impact"""
        import time

        start_time = time.time()
        response = client.get("/health")  # Bypassed endpoint
        end_time = time.time()

        # Should complete quickly for bypassed endpoints
        assert end_time - start_time < 0.5
        assert response.status_code == 200

# Test fixtures and utilities
@pytest.fixture
def rate_limit_test_data():
    """Provide test data for rate limiting tests"""
    return {
        "valid_request": {
            "identifier": "test_user",
            "limit_type": "api",
            "action": "GET_/test"
        },
        "invalid_request": {
            "limit_type": "invalid"
        },
        "high_usage_scenario": {
            "current_count": 95,
            "limit": 100
        },
        "violation_scenario": {
            "current_count": 101,
            "limit": 100
        }
    }

if __name__ == "__main__":
    pytest.main([__file__, "-v"])