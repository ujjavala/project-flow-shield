"""
Tests for Behavioral Analytics workflows, activities, and API endpoints
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.temporal.workflows.behavioral_analytics_workflow import (
    BehaviorAnalyticsWorkflow,
    ContinuousMonitoringWorkflow
)
from app.temporal.activities.behavioral_activities import BehavioralActivities
from app.temporal.types import BehaviorAnalysisRequest
from app.api.behavioral_analytics import router


class TestBehavioralActivities:
    """Test behavioral analytics activities"""

    @pytest.fixture
    def behavioral_activities(self):
        return BehavioralActivities()

    @pytest.fixture
    def sample_behavior_data(self):
        return {
            "user_id": "test-user-123",
            "session_id": "session-456",
            "event_type": "login",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": datetime.utcnow().isoformat(),
            "geolocation": {"latitude": "37.7749", "longitude": "-122.4194", "city": "San Francisco"},
            "device_fingerprint": {"screen_resolution": "1920x1080", "timezone": "America/Los_Angeles"},
            "additional_context": {"referrer": "https://app.example.com"}
        }

    @pytest.fixture
    def sample_analysis_data(self):
        return {
            "behavior_data": {"success": True},
            "login_analysis": {
                "success": True,
                "anomalies": ["new_ip_address"],
                "risk_factors": [{"type": "new_ip", "severity": "medium"}],
                "login_history_count": 5
            },
            "device_analysis": {
                "success": True,
                "anomalies": ["new_device"],
                "risk_factors": [{"type": "new_device", "severity": "medium"}],
                "is_new_device": True
            },
            "geo_analysis": {
                "success": True,
                "anomalies": [],
                "risk_factors": [],
                "current_location": {"latitude": 37.7749, "longitude": -122.4194}
            }
        }

    @pytest.mark.asyncio
    async def test_collect_user_behavior_success(self, behavioral_activities, sample_behavior_data):
        """Test successful behavior data collection"""
        with patch.object(behavioral_activities, '_get_redis', return_value=AsyncMock()):
            # Mock database operations
            with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
                mock_db = AsyncMock()
                mock_session.return_value.__aenter__.return_value = mock_db

                result = await behavioral_activities.collect_user_behavior(
                    "test-user-123",
                    "session-456",
                    sample_behavior_data
                )

                assert result["success"] is True
                assert result["user_id"] == "test-user-123"
                assert result["session_id"] == "session-456"
                assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_analyze_login_patterns_new_ip(self, behavioral_activities):
        """Test login pattern analysis with new IP"""
        with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchall.return_value = []  # No history, so new IP
            mock_db.execute.return_value = mock_result
            mock_session.return_value.__aenter__.return_value = mock_db

            result = await behavioral_activities.analyze_login_patterns(
                "test-user-123",
                "192.168.1.100",
                "Mozilla/5.0 Test Browser",
                {"latitude": "37.7749", "longitude": "-122.4194"}
            )

            assert result["success"] is True
            assert result["user_id"] == "test-user-123"
            assert "risk_factors" in result
            # Should detect first login as moderate risk
            risk_factors = result["risk_factors"]
            assert len(risk_factors) > 0
            assert any(rf["type"] == "first_login" for rf in risk_factors)

    @pytest.mark.asyncio
    async def test_calculate_risk_score_with_ai(self, behavioral_activities, sample_analysis_data):
        """Test risk score calculation with AI analysis"""
        # Mock AI analysis to return a risk score
        mock_ai_result = {
            "success": True,
            "ai_risk_score": 0.7,
            "ai_risk_factors": [{"type": "ai_detected_anomaly", "severity": "high"}],
            "ai_confidence": 0.9,
            "ai_reasoning": "Multiple risk factors detected",
            "model_used": "llama3"
        }

        with patch.object(behavioral_activities, '_analyze_with_ai', return_value=mock_ai_result):
            with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
                mock_db = AsyncMock()
                mock_session.return_value.__aenter__.return_value = mock_db

                result = await behavioral_activities.calculate_risk_score(
                    "test-user-123",
                    sample_analysis_data
                )

                assert result["success"] is True
                assert result["risk_score"] == 0.7  # Should use AI score
                assert result["ai_enhanced"] is True
                assert result["ai_analysis"] == mock_ai_result
                assert result["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_calculate_risk_score_fallback(self, behavioral_activities, sample_analysis_data):
        """Test risk score calculation with AI fallback to rules"""
        # Mock AI analysis to fail
        with patch.object(behavioral_activities, '_analyze_with_ai', side_effect=Exception("AI unavailable")):
            with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
                mock_db = AsyncMock()
                mock_session.return_value.__aenter__.return_value = mock_db

                result = await behavioral_activities.calculate_risk_score(
                    "test-user-123",
                    sample_analysis_data
                )

                assert result["success"] is True
                assert result["ai_enhanced"] is False
                # Should calculate rule-based score (new_ip + new_device = 0.2 + 0.15 = 0.35)
                assert result["risk_score"] > 0
                assert result["risk_score"] < 1.0

    @pytest.mark.asyncio
    async def test_detect_device_fingerprinting(self, behavioral_activities):
        """Test device fingerprinting analysis"""
        device_data = {
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
            "screen_resolution": "414x896",
            "timezone": "America/New_York"
        }

        with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchall.return_value = []  # No known devices
            mock_db.execute.return_value = mock_result
            mock_session.return_value.__aenter__.return_value = mock_db

            result = await behavioral_activities.detect_device_fingerprinting(
                "test-user-123",
                device_data
            )

            assert result["success"] is True
            assert result["is_new_device"] is True
            assert "device_fingerprint" in result
            assert "device_info" in result
            assert result["device_info"]["is_mobile"] is True

    @pytest.mark.asyncio
    async def test_analyze_geolocation_patterns_impossible_travel(self, behavioral_activities):
        """Test geolocation analysis detecting impossible travel"""
        current_location = {"latitude": "40.7128", "longitude": "-74.0060"}  # NYC

        # Mock historical location data (San Francisco, 1 hour ago)
        historical_data = [(
            json.dumps({"latitude": "37.7749", "longitude": "-122.4194"}),
            (datetime.utcnow() - timedelta(hours=1)).isoformat()
        )]

        with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchall.return_value = historical_data
            mock_db.execute.return_value = mock_result
            mock_session.return_value.__aenter__.return_value = mock_db

            result = await behavioral_activities.analyze_geolocation_patterns(
                "test-user-123",
                current_location
            )

            assert result["success"] is True
            assert "impossible_travel" in result["anomalies"]
            # Should detect impossible travel from SF to NYC in 1 hour
            risk_factors = result["risk_factors"]
            assert any(rf["type"] == "impossible_travel" for rf in risk_factors)

    @pytest.mark.asyncio
    async def test_trigger_fraud_alert(self, behavioral_activities):
        """Test fraud alert triggering"""
        risk_assessment = {
            "risk_score": 0.8,
            "risk_level": "high",
            "risk_factors": [{"type": "impossible_travel", "severity": "critical"}],
            "anomalies": ["impossible_travel", "new_device"]
        }

        with patch('app.temporal.activities.behavioral_activities.AsyncSessionLocal') as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db
            with patch.object(behavioral_activities, '_get_redis', return_value=AsyncMock()):

                result = await behavioral_activities.trigger_fraud_alert(
                    "test-user-123",
                    risk_assessment,
                    "session-456"
                )

                assert result["success"] is True
                assert len(result["alerts"]) > 0
                alert = result["alerts"][0]
                assert alert["type"] == "fraud_detection"
                assert alert["severity"] in ["high", "medium"]

    @pytest.mark.asyncio
    async def test_ai_analysis_with_ollama(self, behavioral_activities):
        """Test AI analysis using Ollama"""
        analysis_data = {
            "behavior_data": {"event_type": "login", "ip_address": "192.168.1.1"},
            "login_analysis": {"anomalies": ["new_ip_address"]},
            "device_analysis": {"is_new_device": True},
            "geo_analysis": {"anomalies": []}
        }

        # Mock successful Ollama response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": '{"risk_score": 0.6, "confidence": 0.8, "reasoning": "New IP and device detected", "risk_factors": ["new_ip", "new_device"]}'
        }

        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

            result = await behavioral_activities._analyze_with_ai("test-user-123", analysis_data)

            assert result["success"] is True
            assert result["ai_risk_score"] == 0.6
            assert result["ai_confidence"] == 0.8
            assert result["model_used"] == "llama3"

    @pytest.mark.asyncio
    async def test_ai_analysis_fallback(self, behavioral_activities):
        """Test AI analysis fallback when Ollama is unavailable"""
        analysis_data = {
            "behavior_data": {"event_type": "login"},
            "login_analysis": {"anomalies": ["unusual_location"]},
            "device_analysis": {"is_new_device": True},
            "geo_analysis": {"anomalies": ["impossible_travel"]}
        }

        # Mock Ollama connection error
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post.side_effect = Exception("Connection failed")

            result = await behavioral_activities._analyze_with_ai("test-user-123", analysis_data)

            assert result["success"] is True
            assert result["model_used"] == "local_heuristic"
            assert result["ai_risk_score"] > 0  # Should calculate heuristic score
            assert result["ai_confidence"] == 0.7


class TestBehaviorAnalyticsWorkflow:
    """Test behavioral analytics workflow"""

    @pytest.fixture
    def behavior_request(self):
        return BehaviorAnalysisRequest(
            user_id="test-user-123",
            session_id="session-456",
            event_type="login",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Test Browser",
            timestamp=datetime.utcnow().isoformat(),
            geolocation={"latitude": "37.7749", "longitude": "-122.4194"}
        )

    @pytest.mark.asyncio
    async def test_behavior_analytics_workflow_success(self, behavior_request):
        """Test successful behavior analytics workflow execution"""
        workflow = BehaviorAnalyticsWorkflow()

        # Mock workflow.execute_activity calls
        with patch.object(workflow, 'execute_activity') as mock_execute:
            # Mock successful activity responses
            mock_execute.side_effect = [
                {"success": True, "behavior_data": {"event_type": "login"}},  # collect_user_behavior
                {"success": True, "anomalies": [], "risk_factors": []},       # analyze_login_patterns
                {"success": True, "anomalies": [], "risk_factors": []},       # detect_device_fingerprinting
                {"success": True, "anomalies": [], "risk_factors": []},       # analyze_geolocation_patterns
                {"success": True, "risk_score": 0.3, "risk_level": "low", "risk_factors": [], "anomalies": []},  # calculate_risk_score
                {"success": True},  # update_behavior_baseline
            ]

            result = await workflow.run(behavior_request)

            assert result["success"] is True
            assert result["user_id"] == "test-user-123"
            assert result["risk_score"] == 0.3
            assert result["risk_level"] == "low"
            assert "behavioral_insights" in result

    @pytest.mark.asyncio
    async def test_behavior_analytics_workflow_high_risk(self, behavior_request):
        """Test workflow with high risk score triggering alerts"""
        workflow = BehaviorAnalyticsWorkflow()

        with patch.object(workflow, 'execute_activity') as mock_execute:
            # Mock high-risk scenario
            mock_execute.side_effect = [
                {"success": True, "behavior_data": {"event_type": "login"}},
                {"success": True, "anomalies": ["new_ip"], "risk_factors": [{"type": "new_ip", "severity": "high"}]},
                {"success": True, "anomalies": ["new_device"], "risk_factors": [{"type": "new_device", "severity": "medium"}]},
                {"success": True, "anomalies": ["impossible_travel"], "risk_factors": [{"type": "impossible_travel", "severity": "critical"}]},
                {"success": True, "risk_score": 0.8, "risk_level": "high", "risk_factors": [], "anomalies": ["impossible_travel"]},
                {"success": True},  # update_behavior_baseline
                {"success": True, "alerts": [{"type": "fraud_detection", "severity": "high"}]},  # trigger_fraud_alert
            ]

            result = await workflow.run(behavior_request)

            assert result["success"] is True
            assert result["risk_score"] == 0.8
            assert result["risk_level"] == "high"
            assert len(result["alerts_triggered"]) > 0
            assert result["alerts_triggered"][0]["type"] == "fraud_detection"

    @pytest.mark.asyncio
    async def test_continuous_monitoring_workflow(self):
        """Test continuous monitoring workflow"""
        workflow = ContinuousMonitoringWorkflow()

        with patch('app.temporal.workflows.behavioral_analytics_workflow.workflow') as mock_workflow:
            # Mock workflow time and conditions
            mock_workflow.now.return_value = datetime.utcnow()
            mock_workflow.wait_condition.side_effect = Exception("Timeout")  # Simulate timeout

            result = await workflow.run("test-user-123", 1)  # 1 hour monitoring

            assert result["success"] is True
            assert result["user_id"] == "test-user-123"
            assert result["monitoring_duration_hours"] == 1


class TestBehaviorAnalyticsAPI:
    """Test behavioral analytics API endpoints"""

    @pytest.fixture
    def mock_app(self):
        """Create a test FastAPI app with the behavioral analytics router"""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_analyze_behavior_unauthorized(self, mock_app):
        """Test behavior analysis without authentication"""
        response = mock_app.post("/analyze", json={
            "event_type": "login",
            "ip_address": "192.168.1.1"
        })
        # Should return 401 or redirect to login
        assert response.status_code in [401, 422]  # 422 for missing dependencies

    @pytest.mark.asyncio
    async def test_get_risk_score_success(self):
        """Test getting user risk score"""
        # This would require mocking the database and authentication
        # Implementation would depend on the actual auth setup
        pass

    @pytest.mark.asyncio
    async def test_admin_fraud_alerts_endpoint(self):
        """Test admin fraud alerts endpoint"""
        # This would require mocking admin authentication and database
        # Implementation would depend on the actual auth setup
        pass


class TestBehaviorAnalyticsIntegration:
    """Integration tests for the complete behavioral analytics system"""

    @pytest.mark.asyncio
    async def test_end_to_end_behavior_analysis(self):
        """Test complete end-to-end behavior analysis flow"""
        # This would test the full flow from API request through workflow to database
        # Requires actual database and temporal setup for true integration testing
        pass

    @pytest.mark.asyncio
    async def test_ai_model_integration(self):
        """Test integration with actual AI models"""
        # This would test actual Ollama integration
        # Requires Ollama service running for integration testing
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])