from temporalio import workflow
from temporalio.common import RetryPolicy
from datetime import timedelta
from typing import Optional, Dict, Any, List
import logging

from app.temporal.types import BehaviorAnalysisRequest, RiskAssessmentRequest

logger = logging.getLogger(__name__)

@workflow.defn
class BehaviorAnalyticsWorkflow:
    """Workflow for continuous behavioral analytics and fraud detection"""

    @workflow.run
    async def run(self, analysis_request: BehaviorAnalysisRequest) -> Dict[str, Any]:
        """Execute behavioral analysis workflow"""

        try:
            logger.info(f"Starting behavioral analysis for user {analysis_request.user_id}")

            # Step 1: Collect and store behavior data
            behavior_result = await workflow.execute_activity(
                "collect_user_behavior",
                args=[analysis_request.user_id, analysis_request.session_id, {
                    "event_type": analysis_request.event_type,
                    "ip_address": analysis_request.ip_address,
                    "user_agent": analysis_request.user_agent,
                    "timestamp": analysis_request.timestamp,
                    "geolocation": analysis_request.geolocation,
                    "device_fingerprint": analysis_request.device_fingerprint,
                    "additional_context": analysis_request.additional_context
                }],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )

            if not behavior_result["success"]:
                return {
                    "success": False,
                    "error": "Failed to collect behavior data",
                    "risk_score": 0.0
                }

            # Step 2: Analyze login patterns if this is a login event
            login_analysis = {}
            if analysis_request.event_type == "login":
                login_analysis = await workflow.execute_activity(
                    "analyze_login_patterns",
                    args=[analysis_request.user_id, analysis_request.ip_address,
                          analysis_request.user_agent, analysis_request.geolocation],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=1),
                        maximum_interval=timedelta(seconds=5),
                        maximum_attempts=3
                    )
                )

            # Step 3: Device fingerprinting analysis
            device_analysis = await workflow.execute_activity(
                "detect_device_fingerprinting",
                args=[analysis_request.user_id, analysis_request.device_fingerprint or {}],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )

            # Step 4: Geolocation pattern analysis
            geo_analysis = await workflow.execute_activity(
                "analyze_geolocation_patterns",
                args=[analysis_request.user_id, analysis_request.geolocation or {}],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )

            # Step 5: Calculate comprehensive risk score
            risk_assessment = await workflow.execute_activity(
                "calculate_risk_score",
                args=[analysis_request.user_id, {
                    "behavior_data": behavior_result,
                    "login_analysis": login_analysis,
                    "device_analysis": device_analysis,
                    "geo_analysis": geo_analysis,
                    "event_context": {
                        "event_type": analysis_request.event_type,
                        "timestamp": analysis_request.timestamp
                    }
                }],
                start_to_close_timeout=timedelta(seconds=45),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3
                )
            )

            # Step 6: Update user's behavioral baseline
            baseline_update = await workflow.execute_activity(
                "update_behavior_baseline",
                args=[analysis_request.user_id, behavior_result["behavior_data"]],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=3
                )
            )

            # Step 7: Trigger alerts if risk score is high
            alert_result = {}
            if risk_assessment["risk_score"] > 0.7:  # High risk threshold
                alert_result = await workflow.execute_activity(
                    "trigger_fraud_alert",
                    args=[analysis_request.user_id, risk_assessment, analysis_request.session_id],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=1),
                        maximum_interval=timedelta(seconds=5),
                        maximum_attempts=3
                    )
                )

            logger.info(f"Behavioral analysis completed for user {analysis_request.user_id} with risk score: {risk_assessment['risk_score']}")

            return {
                "success": True,
                "user_id": analysis_request.user_id,
                "session_id": analysis_request.session_id,
                "risk_score": risk_assessment["risk_score"],
                "risk_factors": risk_assessment.get("risk_factors", []),
                "anomalies_detected": risk_assessment.get("anomalies", []),
                "behavioral_insights": {
                    "login_analysis": login_analysis,
                    "device_analysis": device_analysis,
                    "geo_analysis": geo_analysis
                },
                "alerts_triggered": alert_result.get("alerts", []),
                "baseline_updated": baseline_update.get("success", False),
                "analysis_timestamp": analysis_request.timestamp,
                "method": "temporal_workflow"
            }

        except Exception as e:
            logger.error(f"Behavioral analysis workflow failed for user {analysis_request.user_id}: {str(e)}")
            return {
                "success": False,
                "error": f"Behavioral analysis failed: {str(e)}",
                "risk_score": 0.0,
                "user_id": analysis_request.user_id,
                "method": "temporal_workflow"
            }

@workflow.defn
class ContinuousMonitoringWorkflow:
    """Long-running workflow for continuous behavioral monitoring"""

    @workflow.run
    async def run(self, user_id: str, monitoring_duration_hours: int = 24) -> Dict[str, Any]:
        """Execute continuous monitoring for a user"""

        monitoring_end = workflow.now() + timedelta(hours=monitoring_duration_hours)
        anomalies_detected = []
        total_events_processed = 0

        try:
            logger.info(f"Starting continuous monitoring for user {user_id} for {monitoring_duration_hours} hours")

            while workflow.now() < monitoring_end:
                # Wait for behavior events or timeout after 30 minutes
                try:
                    # Use workflow signal to receive behavior events
                    behavior_event = await workflow.wait_condition(
                        lambda: hasattr(workflow.info(), 'signals_received'),
                        timeout=timedelta(minutes=30)
                    )

                    if behavior_event:
                        # Process the received behavior event
                        analysis_result = await workflow.execute_child_workflow(
                            BehaviorAnalyticsWorkflow.run,
                            behavior_event,
                            id=f"behavior-analysis-{user_id}-{workflow.now().timestamp()}",
                            task_queue="oauth2-task-queue"
                        )

                        total_events_processed += 1

                        if analysis_result.get("risk_score", 0) > 0.5:
                            anomalies_detected.append({
                                "timestamp": workflow.now().isoformat(),
                                "risk_score": analysis_result["risk_score"],
                                "anomalies": analysis_result.get("anomalies_detected", [])
                            })

                except Exception as e:
                    logger.warning(f"Error in continuous monitoring for user {user_id}: {str(e)}")
                    # Continue monitoring despite individual errors
                    continue

            logger.info(f"Continuous monitoring completed for user {user_id}. Events processed: {total_events_processed}, Anomalies: {len(anomalies_detected)}")

            return {
                "success": True,
                "user_id": user_id,
                "monitoring_duration_hours": monitoring_duration_hours,
                "total_events_processed": total_events_processed,
                "anomalies_detected": anomalies_detected,
                "monitoring_completed_at": workflow.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Continuous monitoring workflow failed for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": f"Continuous monitoring failed: {str(e)}",
                "user_id": user_id
            }

    @workflow.signal
    async def receive_behavior_event(self, behavior_data: Dict[str, Any]) -> None:
        """Signal to receive behavior events for processing"""
        # Store the behavior event for processing
        if not hasattr(self, '_behavior_events'):
            self._behavior_events = []
        self._behavior_events.append(behavior_data)

        # Set signal received flag
        workflow.info().signals_received = True