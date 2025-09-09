"""
Temporal-Powered Analytics Workflows for Fraud Detection Observability

This module leverages Temporal's powerful workflow capabilities to:
- Aggregate authentication and fraud data across time periods
- Monitor AI model performance with workflow resilience
- Generate real-time analytics dashboards with durability
- Track fraud patterns using Temporal's search attributes
- Create audit trails for compliance and investigation
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json

from temporalio import workflow, activity
from temporalio.common import RetryPolicy
# WorkflowHandle import not needed for this workflow

# Data classes for analytics
@dataclass
class FraudEventData:
    email: str
    fraud_score: float
    risk_level: str
    risk_factors: List[str]
    timestamp: datetime
    correlation_id: str
    ai_provider: str
    processing_time_ms: int
    blocked: bool
    user_agent: str
    ip_address: str
    source: str

@dataclass
class AuthenticationEventData:
    email: str
    event_type: str  # registration, login, verification, password_reset
    success: bool
    timestamp: datetime
    fraud_score: Optional[float]
    ai_insights: Dict[str, Any]
    correlation_id: str

@dataclass
class AnalyticsAggregation:
    period_start: datetime
    period_end: datetime
    total_events: int
    fraud_stats: Dict[str, Any]
    auth_stats: Dict[str, Any]
    ai_performance: Dict[str, Any]
    risk_trends: List[Dict[str, Any]]

# Temporal Workflow for Analytics Processing
@workflow.defn
class FraudAnalyticsWorkflow:
    """
    Long-running workflow that continuously processes fraud events and maintains analytics
    Uses Temporal's durability to ensure no analytics data is lost
    """
    
    def __init__(self):
        self.fraud_events: List[FraudEventData] = []
        self.auth_events: List[AuthenticationEventData] = []
        self.current_aggregation: Optional[AnalyticsAggregation] = None
        self.last_aggregation_time = datetime.now()
    
    @workflow.run
    async def run(self) -> None:
        """
        Main analytics workflow that runs continuously
        """
        workflow.logger.info("Starting Fraud Analytics Workflow")
        
        # Set search attributes for analytics workflow discoverability
        await workflow.upsert_search_attributes({
            "WorkflowType": "FraudAnalytics",
            "AnalyticsVersion": "v2.0",
            "IsActive": True
        })
        
        # Start continuous analytics processing
        while True:
            try:
                # Process analytics every 5 minutes
                await workflow.sleep(300)  # 5 minutes
                
                # Aggregate recent events
                await self._process_analytics_cycle()
                
                # Continue-as-new every 24 hours to prevent workflow history bloat
                if workflow.now() - workflow.start_time() > timedelta(hours=24):
                    workflow.logger.info("Continuing analytics workflow as new")
                    await workflow.continue_as_new()
                    
            except Exception as e:
                workflow.logger.error(f"Analytics cycle failed: {e}")
                # Retry after 1 minute on error
                await workflow.sleep(60)
    
    @workflow.signal
    async def record_fraud_event(self, event_data: Dict[str, Any]) -> None:
        """
        Signal to record a new fraud event
        """
        try:
            fraud_event = FraudEventData(
                email=event_data["email"],
                fraud_score=event_data["fraud_score"],
                risk_level=event_data["risk_level"],
                risk_factors=event_data["risk_factors"],
                timestamp=datetime.fromisoformat(event_data["timestamp"]),
                correlation_id=event_data["correlation_id"],
                ai_provider=event_data.get("ai_provider", "unknown"),
                processing_time_ms=event_data.get("processing_time_ms", 0),
                blocked=event_data.get("blocked", False),
                user_agent=event_data.get("user_agent", ""),
                ip_address=event_data.get("ip_address", ""),
                source=event_data.get("source", "web")
            )
            
            self.fraud_events.append(fraud_event)
            
            # Update search attributes with latest fraud metrics
            await self._update_search_attributes()
            
            workflow.logger.info(f"Recorded fraud event for {event_data['email'][:3]}*** with score {event_data['fraud_score']}")
            
        except Exception as e:
            workflow.logger.error(f"Failed to record fraud event: {e}")
    
    @workflow.signal
    async def record_auth_event(self, event_data: Dict[str, Any]) -> None:
        """
        Signal to record an authentication event
        """
        try:
            auth_event = AuthenticationEventData(
                email=event_data["email"],
                event_type=event_data["event_type"],
                success=event_data["success"],
                timestamp=datetime.fromisoformat(event_data["timestamp"]),
                fraud_score=event_data.get("fraud_score"),
                ai_insights=event_data.get("ai_insights", {}),
                correlation_id=event_data["correlation_id"]
            )
            
            self.auth_events.append(auth_event)
            workflow.logger.info(f"Recorded auth event: {event_data['event_type']} for {event_data['email'][:3]}***")
            
        except Exception as e:
            workflow.logger.error(f"Failed to record auth event: {e}")
    
    @workflow.query
    def get_current_analytics(self) -> Dict[str, Any]:
        """
        Query to get current analytics aggregation
        """
        if not self.current_aggregation:
            return {"message": "No aggregation available yet"}
        
        return {
            "period_start": self.current_aggregation.period_start.isoformat(),
            "period_end": self.current_aggregation.period_end.isoformat(),
            "total_events": self.current_aggregation.total_events,
            "fraud_stats": self.current_aggregation.fraud_stats,
            "auth_stats": self.current_aggregation.auth_stats,
            "ai_performance": self.current_aggregation.ai_performance,
            "risk_trends": self.current_aggregation.risk_trends,
            "last_updated": datetime.now().isoformat()
        }
    
    @workflow.query
    def get_recent_events(self, limit: int = 50) -> Dict[str, Any]:
        """
        Query to get recent fraud events
        """
        recent_fraud = sorted(self.fraud_events, key=lambda x: x.timestamp, reverse=True)[:limit]
        recent_auth = sorted(self.auth_events, key=lambda x: x.timestamp, reverse=True)[:limit]
        
        return {
            "recent_fraud_events": [
                {
                    "email": event.email[:3] + "***@" + event.email.split("@")[1],
                    "fraud_score": event.fraud_score,
                    "risk_level": event.risk_level,
                    "risk_factors": event.risk_factors,
                    "timestamp": event.timestamp.isoformat(),
                    "ai_provider": event.ai_provider,
                    "blocked": event.blocked
                }
                for event in recent_fraud
            ],
            "recent_auth_events": [
                {
                    "email": event.email[:3] + "***@" + event.email.split("@")[1],
                    "event_type": event.event_type,
                    "success": event.success,
                    "timestamp": event.timestamp.isoformat(),
                    "fraud_score": event.fraud_score
                }
                for event in recent_auth
            ],
            "total_fraud_events": len(self.fraud_events),
            "total_auth_events": len(self.auth_events)
        }
    
    async def _process_analytics_cycle(self) -> None:
        """
        Process analytics aggregation using Temporal activities
        """
        try:
            # Aggregate fraud data
            fraud_aggregation = await workflow.execute_activity(
                "aggregate_fraud_data",
                {
                    "events": [
                        {
                            "email": e.email,
                            "fraud_score": e.fraud_score,
                            "risk_level": e.risk_level,
                            "risk_factors": e.risk_factors,
                            "timestamp": e.timestamp.isoformat(),
                            "ai_provider": e.ai_provider,
                            "processing_time_ms": e.processing_time_ms,
                            "blocked": e.blocked
                        }
                        for e in self.fraud_events
                    ]
                },
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3
                ),
                schedule_to_close_timeout=timedelta(minutes=5)
            )
            
            # Aggregate authentication data
            auth_aggregation = await workflow.execute_activity(
                "aggregate_auth_data",
                {
                    "events": [
                        {
                            "email": e.email,
                            "event_type": e.event_type,
                            "success": e.success,
                            "timestamp": e.timestamp.isoformat(),
                            "fraud_score": e.fraud_score
                        }
                        for e in self.auth_events
                    ]
                },
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3
                ),
                schedule_to_close_timeout=timedelta(minutes=5)
            )
            
            # Store aggregation results
            self.current_aggregation = AnalyticsAggregation(
                period_start=self.last_aggregation_time,
                period_end=datetime.now(),
                total_events=len(self.fraud_events) + len(self.auth_events),
                fraud_stats=fraud_aggregation,
                auth_stats=auth_aggregation,
                ai_performance=await self._calculate_ai_performance(),
                risk_trends=await self._calculate_risk_trends()
            )
            
            self.last_aggregation_time = datetime.now()
            
            # Persist aggregation to database
            await workflow.execute_activity(
                "persist_analytics_aggregation",
                {
                    "aggregation": {
                        "period_start": self.current_aggregation.period_start.isoformat(),
                        "period_end": self.current_aggregation.period_end.isoformat(),
                        "total_events": self.current_aggregation.total_events,
                        "fraud_stats": self.current_aggregation.fraud_stats,
                        "auth_stats": self.current_aggregation.auth_stats,
                        "ai_performance": self.current_aggregation.ai_performance,
                        "risk_trends": self.current_aggregation.risk_trends
                    }
                },
                schedule_to_close_timeout=timedelta(minutes=2)
            )
            
            workflow.logger.info(f"Analytics cycle completed: {len(self.fraud_events)} fraud events, {len(self.auth_events)} auth events")
            
        except Exception as e:
            workflow.logger.error(f"Analytics processing failed: {e}")
    
    async def _update_search_attributes(self) -> None:
        """
        Update search attributes with current metrics for discoverability
        """
        try:
            recent_events = [e for e in self.fraud_events if e.timestamp > datetime.now() - timedelta(hours=1)]
            high_risk_count = len([e for e in recent_events if e.risk_level == "high"])
            avg_fraud_score = sum([e.fraud_score for e in recent_events]) / len(recent_events) if recent_events else 0
            
            await workflow.upsert_search_attributes({
                "TotalEvents": len(self.fraud_events),
                "HighRiskEvents1h": high_risk_count,
                "AvgFraudScore1h": round(avg_fraud_score, 3),
                "LastEventTime": datetime.now().isoformat(),
                "EventsLast24h": len([e for e in self.fraud_events if e.timestamp > datetime.now() - timedelta(hours=24)])
            })
            
        except Exception as e:
            workflow.logger.error(f"Failed to update search attributes: {e}")
    
    async def _calculate_ai_performance(self) -> Dict[str, Any]:
        """Calculate AI performance metrics"""
        if not self.fraud_events:
            return {"no_data": True}
        
        ollama_events = [e for e in self.fraud_events if e.ai_provider == "ollama"]
        fallback_events = [e for e in self.fraud_events if e.ai_provider != "ollama"]
        
        return {
            "total_requests": len(self.fraud_events),
            "ollama_requests": len(ollama_events),
            "fallback_requests": len(fallback_events),
            "avg_ollama_response_time": sum([e.processing_time_ms for e in ollama_events]) / len(ollama_events) if ollama_events else 0,
            "ollama_success_rate": len([e for e in ollama_events if e.processing_time_ms > 0]) / len(ollama_events) * 100 if ollama_events else 0
        }
    
    async def _calculate_risk_trends(self) -> List[Dict[str, Any]]:
        """Calculate risk trends over time"""
        if not self.fraud_events:
            return []
        
        # Group events by hour for trend analysis
        hourly_scores = {}
        for event in self.fraud_events:
            hour = event.timestamp.replace(minute=0, second=0, microsecond=0)
            if hour not in hourly_scores:
                hourly_scores[hour] = []
            hourly_scores[hour].append(event.fraud_score)
        
        trends = []
        for hour, scores in sorted(hourly_scores.items()):
            avg_score = sum(scores) / len(scores)
            high_risk_count = len([s for s in scores if s > 0.7])
            
            trends.append({
                "timestamp": hour.isoformat(),
                "avg_fraud_score": round(avg_score, 3),
                "event_count": len(scores),
                "high_risk_count": high_risk_count,
                "trend": "increasing" if len(trends) > 0 and avg_score > trends[-1]["avg_fraud_score"] else "stable"
            })
        
        return trends[-24:]  # Last 24 hours

# Child workflow for investigating specific fraud patterns
@workflow.defn
class FraudInvestigationWorkflow:
    """
    Child workflow for deep investigation of fraud patterns
    Triggered when fraud rates exceed thresholds
    """
    
    @workflow.run
    async def run(self, investigation_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run fraud pattern investigation
        """
        workflow.logger.info(f"Starting fraud investigation: {investigation_params}")
        
        # Set search attributes for investigation tracking
        await workflow.upsert_search_attributes({
            "WorkflowType": "FraudInvestigation",
            "InvestigationType": investigation_params.get("type", "general"),
            "TriggerThreshold": investigation_params.get("threshold", 0.0),
            "Priority": investigation_params.get("priority", "medium")
        })
        
        # Analyze fraud patterns
        pattern_analysis = await workflow.execute_activity(
            "analyze_fraud_patterns",
            investigation_params,
            schedule_to_close_timeout=timedelta(minutes=10)
        )
        
        # Generate investigation report
        investigation_report = await workflow.execute_activity(
            "generate_investigation_report",
            {
                "analysis": pattern_analysis,
                "investigation_id": workflow.info().workflow_id,
                "timestamp": datetime.now().isoformat()
            },
            schedule_to_close_timeout=timedelta(minutes=5)
        )
        
        # Send alerts if critical patterns found
        if pattern_analysis.get("severity") == "critical":
            await workflow.execute_activity(
                "send_fraud_alert",
                {
                    "report": investigation_report,
                    "severity": "critical",
                    "recipients": ["admin@company.com", "security@company.com"]
                },
                schedule_to_close_timeout=timedelta(minutes=2)
            )
        
        return {
            "investigation_id": workflow.info().workflow_id,
            "status": "completed",
            "findings": pattern_analysis,
            "report": investigation_report,
            "completed_at": datetime.now().isoformat()
        }