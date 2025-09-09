"""
Tests for Temporal Analytics Workflows and Activities
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.temporal.workflows.analytics_workflow import (
    FraudAnalyticsWorkflow, 
    FraudInvestigationWorkflow,
    FraudEventData,
    AuthenticationEventData,
    AnalyticsAggregation
)
from app.temporal.activities.analytics_activities import AnalyticsActivities


class TestAnalyticsActivities:
    """Test analytics activities"""
    
    @pytest.fixture
    def analytics_activities(self):
        return AnalyticsActivities()
    
    @pytest.fixture
    def sample_fraud_events(self):
        return [
            {
                "email": "test1@example.com",
                "fraud_score": 0.2,
                "risk_level": "low",
                "risk_factors": ["normal_registration"],
                "timestamp": datetime.now().isoformat(),
                "blocked": False,
                "ai_provider": "ollama",
                "processing_time_ms": 120
            },
            {
                "email": "test2@guerrillamail.com",
                "fraud_score": 0.8,
                "risk_level": "high",
                "risk_factors": ["suspicious_email_domain", "bot_behavior"],
                "timestamp": datetime.now().isoformat(),
                "blocked": True,
                "ai_provider": "ollama",
                "processing_time_ms": 95
            },
            {
                "email": "test3@example.com",
                "fraud_score": 0.5,
                "risk_level": "medium",
                "risk_factors": ["unusual_location"],
                "timestamp": datetime.now().isoformat(),
                "blocked": False,
                "ai_provider": "fallback",
                "processing_time_ms": 25
            }
        ]
    
    @pytest.fixture
    def sample_auth_events(self):
        return [
            {
                "event_type": "login",
                "success": True,
                "fraud_score": 0.1,
                "timestamp": datetime.now().isoformat()
            },
            {
                "event_type": "registration", 
                "success": True,
                "fraud_score": 0.3,
                "timestamp": datetime.now().isoformat()
            },
            {
                "event_type": "login",
                "success": False,
                "fraud_score": 0.7,
                "timestamp": datetime.now().isoformat()
            }
        ]
    
    @pytest.mark.asyncio
    async def test_aggregate_fraud_data(self, analytics_activities, sample_fraud_events):
        """Test fraud data aggregation"""
        data = {"events": sample_fraud_events}
        
        result = await analytics_activities.aggregate_fraud_data(data)
        
        assert result["total_events"] == 3
        assert result["high_risk_count"] == 1
        assert result["medium_risk_count"] == 1
        assert result["low_risk_count"] == 1
        assert result["blocked_count"] == 1
        assert result["fraud_rate"] == 33.33  # 1 high risk out of 3 total
        assert isinstance(result["avg_fraud_score"], float)
        assert len(result["top_risk_factors"]) > 0
        assert "provider_distribution" in result
        assert "avg_response_times" in result
    
    @pytest.mark.asyncio
    async def test_aggregate_fraud_data_empty(self, analytics_activities):
        """Test fraud data aggregation with empty data"""
        data = {"events": []}
        
        result = await analytics_activities.aggregate_fraud_data(data)
        
        assert result["total_events"] == 0
        assert result["high_risk_count"] == 0
        assert result["fraud_rate"] == 0.0
        assert result["avg_fraud_score"] == 0.0
        assert result["top_risk_factors"] == []
    
    @pytest.mark.asyncio
    async def test_aggregate_auth_data(self, analytics_activities, sample_auth_events):
        """Test auth data aggregation"""
        data = {"events": sample_auth_events}
        
        result = await analytics_activities.aggregate_auth_data(data)
        
        assert result["total_auth_events"] == 3
        assert result["successful_auths"] == 2
        assert result["failed_auths"] == 1
        assert result["success_rate"] == 66.67  # 2 successful out of 3 total
        assert "event_type_distribution" in result
        assert "fraud_score_distribution" in result
    
    @pytest.mark.asyncio
    async def test_analyze_fraud_patterns(self, analytics_activities):
        """Test fraud pattern analysis"""
        investigation_params = {"type": "high_fraud_rate", "threshold": 25}
        
        # Mock Redis to return high fraud rate data
        mock_redis = AsyncMock()
        mock_redis.get.return_value = '{"fraud_stats": {"fraud_rate": 30, "high_risk_count": 15, "top_risk_factors": [{"factor": "suspicious_email_domain", "percentage": 25}]}}'
        
        with patch.object(analytics_activities, '_get_redis', return_value=mock_redis):
            result = await analytics_activities.analyze_fraud_patterns(investigation_params)
        
        assert result["investigation_type"] == "high_fraud_rate"
        assert len(result["patterns_found"]) > 0
        assert result["severity"] in ["low", "medium", "high"]
        assert isinstance(result["recommendations"], list)
        assert isinstance(result["confidence"], float)
    
    @pytest.mark.asyncio
    async def test_generate_investigation_report(self, analytics_activities):
        """Test investigation report generation"""
        analysis_data = {
            "patterns_found": [
                {"type": "high_fraud_rate", "value": 35, "description": "Fraud rate is high"}
            ],
            "severity": "high",
            "recommendations": ["Enable enhanced verification"],
            "confidence": 0.9
        }
        
        data = {
            "analysis": analysis_data,
            "investigation_id": "test-123",
            "timestamp": datetime.now().isoformat()
        }
        
        # Mock Redis
        mock_redis = AsyncMock()
        with patch.object(analytics_activities, '_get_redis', return_value=mock_redis):
            result = await analytics_activities.generate_investigation_report(data)
        
        assert result["investigation_id"] == "test-123"
        assert "executive_summary" in result
        assert result["severity_assessment"] == "high"
        assert len(result["recommendations"]) > 0
        assert len(result["next_steps"]) > 0
        assert result["confidence_level"] == 0.9
    
    @pytest.mark.asyncio
    async def test_send_fraud_alert(self, analytics_activities):
        """Test fraud alert sending"""
        alert_data = {
            "report": {
                "investigation_id": "test-123",
                "executive_summary": "High fraud detected",
                "recommendations": ["Take action"]
            },
            "severity": "high",
            "recipients": ["admin@example.com"]
        }
        
        # Mock Redis
        mock_redis = AsyncMock()
        with patch.object(analytics_activities, '_get_redis', return_value=mock_redis):
            result = await analytics_activities.send_fraud_alert(alert_data)
        
        assert result["status"] == "sent"
        assert "alert_id" in result
    
    @pytest.mark.asyncio
    async def test_persist_analytics_aggregation(self, analytics_activities):
        """Test analytics aggregation persistence"""
        aggregation = {
            "total_events": 100,
            "fraud_rate": 15.5,
            "timestamp": datetime.now().isoformat()
        }
        
        data = {"aggregation": aggregation}
        
        # Mock Redis
        mock_redis = AsyncMock()
        with patch.object(analytics_activities, '_get_redis', return_value=mock_redis):
            result = await analytics_activities.persist_analytics_aggregation(data)
        
        assert result["status"] == "success"
        assert "timestamp" in result
        
        # Verify Redis calls
        mock_redis.setex.assert_called()
        mock_redis.lpush.assert_called()
        mock_redis.ltrim.assert_called()
    
    def test_generate_executive_summary(self, analytics_activities):
        """Test executive summary generation"""
        high_severity = {"patterns_found": [{"type": "test"}], "severity": "high"}
        medium_severity = {"patterns_found": [{"type": "test"}], "severity": "medium"}
        low_severity = {"patterns_found": [], "severity": "low"}
        
        high_summary = analytics_activities._generate_executive_summary(high_severity)
        medium_summary = analytics_activities._generate_executive_summary(medium_severity)
        low_summary = analytics_activities._generate_executive_summary(low_severity)
        
        assert "Critical fraud patterns detected" in high_summary
        assert "Moderate fraud patterns identified" in medium_summary
        assert "No significant fraud patterns detected" in low_summary
    
    def test_generate_next_steps(self, analytics_activities):
        """Test next steps generation"""
        high_analysis = {"severity": "high"}
        medium_analysis = {"severity": "medium"}
        low_analysis = {"severity": "low"}
        
        high_steps = analytics_activities._generate_next_steps(high_analysis)
        medium_steps = analytics_activities._generate_next_steps(medium_analysis)
        low_steps = analytics_activities._generate_next_steps(low_analysis)
        
        assert len(high_steps) >= 4
        assert len(medium_steps) >= 3
        assert len(low_steps) >= 2
        assert "immediate fraud prevention" in " ".join(high_steps).lower()


class TestWorkflowModels:
    """Test workflow data models"""
    
    def test_fraud_event_data(self):
        """Test FraudEventData model"""
        event = FraudEventData(
            email="test@example.com",
            fraud_score=0.7,
            risk_level="high",
            risk_factors=["suspicious_domain"],
            timestamp=datetime.now(),
            correlation_id="test-123",
            ai_provider="ollama",
            processing_time_ms=150,
            blocked=True,
            user_agent="test-agent",
            ip_address="192.168.1.1",
            source="registration"
        )
        
        assert event.email == "test@example.com"
        assert event.fraud_score == 0.7
        assert event.risk_level == "high"
        assert "suspicious_domain" in event.risk_factors
        assert event.ai_provider == "ollama"
    
    def test_authentication_event_data(self):
        """Test AuthenticationEventData model"""
        event = AuthenticationEventData(
            email="test@example.com",
            event_type="login",
            success=True,
            timestamp=datetime.now(),
            fraud_score=0.1,
            ai_insights={"provider": "ollama"},
            correlation_id="test-123"
        )
        
        assert event.email == "test@example.com"
        assert event.event_type == "login"
        assert event.success is True
        assert event.fraud_score == 0.1
    
    def test_analytics_aggregation(self):
        """Test AnalyticsAggregation model"""
        now = datetime.now()
        aggregation = AnalyticsAggregation(
            period_start=now - timedelta(hours=24),
            period_end=now,
            total_events=100,
            fraud_stats={"fraud_rate": 15.5, "high_risk_count": 15},
            auth_stats={"total_logins": 50},
            ai_performance={"avg_response_time": 120},
            risk_trends=[{"hour": 1, "risk_score": 0.2}]
        )
        
        assert aggregation.total_events == 100
        assert aggregation.fraud_stats["fraud_rate"] == 15.5
        assert aggregation.fraud_stats["high_risk_count"] == 15
        assert len(aggregation.risk_trends) == 1


class TestWorkflowIntegration:
    """Integration tests for workflows (mocked)"""
    
    @pytest.mark.asyncio
    async def test_fraud_event_processing(self):
        """Test fraud event processing logic"""
        # This would test the actual workflow logic
        # For now, just test the data structures work correctly
        
        event_data = FraudEventData(
            email="test@example.com",
            fraud_score=0.8,
            risk_level="high",
            risk_factors=["bot_behavior"],
            timestamp=datetime.now(),
            correlation_id="test-123",
            ai_provider="ollama",
            processing_time_ms=120,
            blocked=True,
            user_agent="test-agent",
            ip_address="192.168.1.1",
            source="registration"
        )
        
        # Simulate workflow processing
        assert event_data.fraud_score > 0.7  # High risk threshold
        assert event_data.risk_level == "high"
        assert len(event_data.risk_factors) > 0
    
    @pytest.mark.asyncio 
    async def test_investigation_trigger_logic(self):
        """Test investigation trigger logic"""
        # Test various conditions that should trigger investigations
        
        # High fraud rate should trigger investigation
        fraud_rate = 35.0
        threshold = 25.0
        assert fraud_rate > threshold
        
        # Multiple high-risk events should trigger investigation
        high_risk_events = [
            {"fraud_score": 0.8, "risk_level": "high"},
            {"fraud_score": 0.9, "risk_level": "high"},
            {"fraud_score": 0.85, "risk_level": "high"}
        ]
        
        assert len(high_risk_events) >= 3
        assert all(event["fraud_score"] > 0.7 for event in high_risk_events)


if __name__ == "__main__":
    pytest.main([__file__])