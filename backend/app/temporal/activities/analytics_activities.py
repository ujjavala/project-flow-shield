"""
Temporal Activities for Analytics and Fraud Investigation
Provides durable, reliable analytics processing using Temporal's activity framework
"""

import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, Counter

from temporalio import activity
import redis.asyncio as redis

logger = logging.getLogger(__name__)

class AnalyticsActivities:
    """Analytics activities for Temporal workflows"""
    
    def __init__(self):
        self.redis_client = None
    
    async def _get_redis(self):
        """Get Redis client for caching"""
        if self.redis_client is None:
            try:
                redis_host = "redis"  # Docker service name
                redis_port = 6379
                self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
                await self.redis_client.ping()
                logger.info("Analytics Redis connected successfully")
            except Exception as e:
                logger.warning(f"Analytics Redis connection failed: {e}")
                self.redis_client = None
        return self.redis_client

    @activity.defn(name="aggregate_fraud_data")
    async def aggregate_fraud_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aggregate fraud event data for analytics
        """
        activity.logger.info("Aggregating fraud data")
        
        try:
            events = data.get("events", [])
            
            if not events:
                return {
                    "total_events": 0,
                    "high_risk_count": 0,
                    "medium_risk_count": 0,
                    "low_risk_count": 0,
                    "blocked_count": 0,
                    "avg_fraud_score": 0.0,
                    "fraud_rate": 0.0,
                    "top_risk_factors": [],
                    "provider_distribution": {}
                }
            
            # Basic counts
            total_events = len(events)
            high_risk_count = len([e for e in events if e["risk_level"] == "high"])
            medium_risk_count = len([e for e in events if e["risk_level"] == "medium"])
            low_risk_count = len([e for e in events if e["risk_level"] == "low"])
            blocked_count = len([e for e in events if e.get("blocked", False)])
            
            # Calculate averages
            fraud_scores = [e["fraud_score"] for e in events if e.get("fraud_score") is not None]
            avg_fraud_score = sum(fraud_scores) / len(fraud_scores) if fraud_scores else 0.0
            fraud_rate = (high_risk_count / total_events) * 100 if total_events > 0 else 0.0
            
            # Risk factor analysis
            risk_factor_counts = Counter()
            for event in events:
                risk_factors = event.get("risk_factors", [])
                for factor in risk_factors:
                    risk_factor_counts[factor] += 1
            
            top_risk_factors = [
                {
                    "factor": factor,
                    "count": count,
                    "percentage": round((count / total_events) * 100, 1)
                }
                for factor, count in risk_factor_counts.most_common(10)
            ]
            
            # Provider distribution
            provider_counts = Counter([e.get("ai_provider", "unknown") for e in events])
            provider_distribution = dict(provider_counts)
            
            # Response time analysis by provider
            response_times_by_provider = defaultdict(list)
            for event in events:
                provider = event.get("ai_provider", "unknown")
                response_time = event.get("processing_time_ms", 0)
                if response_time > 0:
                    response_times_by_provider[provider].append(response_time)
            
            avg_response_times = {}
            for provider, times in response_times_by_provider.items():
                avg_response_times[provider] = sum(times) / len(times) if times else 0
            
            aggregation = {
                "total_events": total_events,
                "high_risk_count": high_risk_count,
                "medium_risk_count": medium_risk_count,
                "low_risk_count": low_risk_count,
                "blocked_count": blocked_count,
                "avg_fraud_score": round(avg_fraud_score, 3),
                "fraud_rate": round(fraud_rate, 2),
                "top_risk_factors": top_risk_factors,
                "provider_distribution": provider_distribution,
                "avg_response_times": avg_response_times,
                "timestamp": datetime.now().isoformat()
            }
            
            # Cache the aggregation
            redis_client = await self._get_redis()
            if redis_client:
                cache_key = f"fraud_aggregation:{datetime.now().strftime('%Y-%m-%d-%H')}"
                await redis_client.setex(cache_key, 3600, json.dumps(aggregation))
            
            activity.logger.info(f"Fraud aggregation completed: {total_events} events, {fraud_rate:.1f}% fraud rate")
            return aggregation
            
        except Exception as e:
            activity.logger.error(f"Fraud aggregation failed: {e}")
            raise

    @activity.defn(name="aggregate_auth_data")
    async def aggregate_auth_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aggregate authentication event data for analytics
        """
        activity.logger.info("Aggregating authentication data")
        
        try:
            events = data.get("events", [])
            
            if not events:
                return {
                    "total_auth_events": 0,
                    "successful_auths": 0,
                    "failed_auths": 0,
                    "success_rate": 0.0,
                    "event_type_distribution": {},
                    "fraud_score_distribution": {}
                }
            
            # Basic counts
            total_auth_events = len(events)
            successful_auths = len([e for e in events if e.get("success", False)])
            failed_auths = total_auth_events - successful_auths
            success_rate = (successful_auths / total_auth_events) * 100 if total_auth_events > 0 else 0.0
            
            # Event type distribution
            event_type_counts = Counter([e.get("event_type", "unknown") for e in events])
            event_type_distribution = dict(event_type_counts)
            
            # Fraud score distribution for auth events
            fraud_scores = [e["fraud_score"] for e in events if e.get("fraud_score") is not None]
            fraud_score_ranges = {
                "low (0.0-0.3)": len([s for s in fraud_scores if 0.0 <= s <= 0.3]),
                "medium (0.3-0.7)": len([s for s in fraud_scores if 0.3 < s <= 0.7]),
                "high (0.7-1.0)": len([s for s in fraud_scores if 0.7 < s <= 1.0])
            }
            
            aggregation = {
                "total_auth_events": total_auth_events,
                "successful_auths": successful_auths,
                "failed_auths": failed_auths,
                "success_rate": round(success_rate, 2),
                "event_type_distribution": event_type_distribution,
                "fraud_score_distribution": fraud_score_ranges,
                "avg_fraud_score": round(sum(fraud_scores) / len(fraud_scores), 3) if fraud_scores else 0.0,
                "timestamp": datetime.now().isoformat()
            }
            
            activity.logger.info(f"Auth aggregation completed: {total_auth_events} events, {success_rate:.1f}% success rate")
            return aggregation
            
        except Exception as e:
            activity.logger.error(f"Auth aggregation failed: {e}")
            raise

    @activity.defn(name="persist_analytics_aggregation")
    async def persist_analytics_aggregation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Persist analytics aggregation to Redis for dashboard consumption
        """
        activity.logger.info("Persisting analytics aggregation")
        
        try:
            aggregation = data.get("aggregation", {})
            
            redis_client = await self._get_redis()
            if redis_client:
                # Store current aggregation
                await redis_client.setex("current_analytics", 3600, json.dumps(aggregation))
                
                # Store historical aggregation
                timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M')
                historical_key = f"analytics_history:{timestamp}"
                await redis_client.setex(historical_key, 86400 * 7, json.dumps(aggregation))  # Keep for 7 days
                
                # Update analytics index
                await redis_client.lpush("analytics_index", historical_key)
                await redis_client.ltrim("analytics_index", 0, 167)  # Keep last week (24*7 entries)
                
                activity.logger.info("Analytics aggregation persisted successfully")
                return {"status": "success", "timestamp": datetime.now().isoformat()}
            else:
                activity.logger.warning("Redis not available, skipping persistence")
                return {"status": "skipped", "reason": "redis_unavailable"}
                
        except Exception as e:
            activity.logger.error(f"Analytics persistence failed: {e}")
            raise

    @activity.defn(name="analyze_fraud_patterns")
    async def analyze_fraud_patterns(self, investigation_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep analysis of fraud patterns for investigation workflow
        """
        activity.logger.info(f"Analyzing fraud patterns: {investigation_params}")
        
        try:
            # Get recent fraud data from Redis
            redis_client = await self._get_redis()
            pattern_analysis = {
                "investigation_type": investigation_params.get("type", "general"),
                "patterns_found": [],
                "severity": "low",
                "recommendations": [],
                "confidence": 0.8
            }
            
            if redis_client:
                # Get recent analytics data
                current_analytics = await redis_client.get("current_analytics")
                if current_analytics:
                    analytics_data = json.loads(current_analytics)
                    fraud_stats = analytics_data.get("fraud_stats", {})
                    
                    # Pattern detection logic
                    fraud_rate = fraud_stats.get("fraud_rate", 0)
                    high_risk_count = fraud_stats.get("high_risk_count", 0)
                    top_risk_factors = fraud_stats.get("top_risk_factors", [])
                    
                    # High fraud rate pattern
                    if fraud_rate > 25:
                        pattern_analysis["patterns_found"].append({
                            "type": "high_fraud_rate",
                            "value": fraud_rate,
                            "description": f"Fraud rate ({fraud_rate}%) is significantly above normal threshold (15%)"
                        })
                        pattern_analysis["severity"] = "high"
                    
                    # Suspicious risk factors
                    suspicious_factors = ["suspicious_email_domain", "bot_like_behavior", "automated_source"]
                    for factor_data in top_risk_factors:
                        if factor_data["factor"] in suspicious_factors and factor_data["percentage"] > 20:
                            pattern_analysis["patterns_found"].append({
                                "type": "dominant_risk_factor",
                                "factor": factor_data["factor"],
                                "percentage": factor_data["percentage"],
                                "description": f"Risk factor '{factor_data['factor']}' appears in {factor_data['percentage']}% of cases"
                            })
                            if pattern_analysis["severity"] != "high":
                                pattern_analysis["severity"] = "medium"
                    
                    # Generate recommendations
                    if fraud_rate > 30:
                        pattern_analysis["recommendations"].extend([
                            "Enable enhanced verification for new registrations",
                            "Implement additional fraud detection rules",
                            "Review and update AI model thresholds"
                        ])
                    elif fraud_rate > 15:
                        pattern_analysis["recommendations"].extend([
                            "Monitor fraud patterns closely",
                            "Consider adjusting risk thresholds"
                        ])
            
            # Default patterns if no Redis data
            if not pattern_analysis["patterns_found"]:
                pattern_analysis["patterns_found"].append({
                    "type": "baseline_analysis",
                    "description": "No significant fraud patterns detected in current data"
                })
            
            activity.logger.info(f"Fraud pattern analysis completed: {len(pattern_analysis['patterns_found'])} patterns found")
            return pattern_analysis
            
        except Exception as e:
            activity.logger.error(f"Fraud pattern analysis failed: {e}")
            raise

    @activity.defn(name="generate_investigation_report")
    async def generate_investigation_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive investigation report
        """
        activity.logger.info("Generating investigation report")
        
        try:
            analysis = data.get("analysis", {})
            investigation_id = data.get("investigation_id", "unknown")
            timestamp = data.get("timestamp", datetime.now().isoformat())
            
            report = {
                "investigation_id": investigation_id,
                "generated_at": timestamp,
                "executive_summary": self._generate_executive_summary(analysis),
                "detailed_findings": analysis.get("patterns_found", []),
                "severity_assessment": analysis.get("severity", "low"),
                "recommendations": analysis.get("recommendations", []),
                "next_steps": self._generate_next_steps(analysis),
                "confidence_level": analysis.get("confidence", 0.8),
                "report_version": "1.0"
            }
            
            # Store report in Redis
            redis_client = await self._get_redis()
            if redis_client:
                report_key = f"investigation_report:{investigation_id}"
                await redis_client.setex(report_key, 86400 * 30, json.dumps(report))  # Keep for 30 days
                
                # Add to reports index
                await redis_client.lpush("investigation_reports", report_key)
                await redis_client.ltrim("investigation_reports", 0, 99)  # Keep last 100 reports
            
            activity.logger.info(f"Investigation report generated: {investigation_id}")
            return report
            
        except Exception as e:
            activity.logger.error(f"Investigation report generation failed: {e}")
            raise

    @activity.defn(name="send_fraud_alert")
    async def send_fraud_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send fraud alert notifications
        """
        activity.logger.info("Sending fraud alert")
        
        try:
            report = alert_data.get("report", {})
            severity = alert_data.get("severity", "medium")
            recipients = alert_data.get("recipients", [])
            
            # In a real implementation, this would send emails/slack notifications
            # For now, we'll log and store the alert
            
            alert = {
                "alert_id": f"fraud_alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "severity": severity,
                "investigation_id": report.get("investigation_id", "unknown"),
                "message": f"Fraud investigation completed with {severity} severity",
                "recipients": recipients,
                "sent_at": datetime.now().isoformat(),
                "executive_summary": report.get("executive_summary", ""),
                "recommendations": report.get("recommendations", [])
            }
            
            # Store alert in Redis
            redis_client = await self._get_redis()
            if redis_client:
                alert_key = f"fraud_alert:{alert['alert_id']}"
                await redis_client.setex(alert_key, 86400 * 30, json.dumps(alert))  # Keep for 30 days
                
                # Add to alerts index
                await redis_client.lpush("fraud_alerts", alert_key)
                await redis_client.ltrim("fraud_alerts", 0, 49)  # Keep last 50 alerts
            
            activity.logger.info(f"Fraud alert sent: {alert['alert_id']} to {len(recipients)} recipients")
            return {"status": "sent", "alert_id": alert["alert_id"]}
            
        except Exception as e:
            activity.logger.error(f"Fraud alert sending failed: {e}")
            raise

    def _generate_executive_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate executive summary for investigation report"""
        patterns = analysis.get("patterns_found", [])
        severity = analysis.get("severity", "low")
        
        if severity == "high":
            return f"Critical fraud patterns detected. {len(patterns)} significant issues require immediate attention."
        elif severity == "medium":
            return f"Moderate fraud patterns identified. {len(patterns)} issues should be monitored closely."
        else:
            return f"No significant fraud patterns detected. System operating within normal parameters."
    
    def _generate_next_steps(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate next steps based on analysis"""
        severity = analysis.get("severity", "low")
        
        if severity == "high":
            return [
                "Implement immediate fraud prevention measures",
                "Review and update AI model parameters",
                "Conduct manual review of flagged accounts",
                "Schedule follow-up investigation in 24 hours"
            ]
        elif severity == "medium":
            return [
                "Monitor fraud rates closely",
                "Review risk factor thresholds",
                "Schedule follow-up investigation in 72 hours"
            ]
        else:
            return [
                "Continue normal monitoring",
                "Schedule routine review in 1 week"
            ]

# Global instance
analytics_activities = AnalyticsActivities()