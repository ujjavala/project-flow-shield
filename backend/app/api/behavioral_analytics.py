"""
Behavioral Analytics API Router
Provides behavioral analytics and fraud detection endpoints for both admin and user access
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Literal
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
import json

from app.database.connection import get_db
from app.models.user import User
from app.api.user_dashboard import get_current_user as get_current_active_user
from app.utils.admin_auth import get_admin_user, get_super_admin_user
from app.services.risk_policy_service import (
    build_login_features,
    evaluate_and_persist,
    ollama_shadow_advisor,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models for API requests/responses
class BehaviorAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["login", "action", "navigation"] = Field(
        ..., description="Bounded event category"
    )

class RiskScoreResponse(BaseModel):
    user_id: str
    risk_score: float
    risk_level: str
    risk_factors: List[Dict[str, Any]]
    anomalies: List[str]
    timestamp: str

class BehaviorAnalyticsResponse(BaseModel):
    user_id: str
    session_id: str
    risk_score: float
    risk_level: str
    anomalies_detected: List[str]
    behavioral_insights: Dict[str, Any]
    alerts_triggered: List[Dict[str, Any]]

class FraudAlertResponse(BaseModel):
    id: str
    user_id: str
    alert_type: str
    risk_score: float
    risk_level: str
    severity: str
    status: str
    created_at: str

class UserBehaviorSummaryResponse(BaseModel):
    user_id: str
    total_events: int
    risk_score_history: List[Dict[str, Any]]
    recent_anomalies: List[str]
    device_count: int
    location_count: int
    last_analysis: Optional[str]

# User Endpoints
@router.post("/analyze", response_model=BehaviorAnalyticsResponse)
async def analyze_user_behavior(
    analysis_data: BehaviorAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Analyze user behavior and calculate risk score"""
    try:
        # Extract request information
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")

        # Generate a correlation/session identifier without retaining raw request context.
        import uuid
        session_id = str(uuid.uuid4())
        features = await build_login_features(db, current_user.id, client_ip, user_agent)
        decision = await evaluate_and_persist(
            db,
            correlation_id=f"behavior-{session_id}",
            context=f"behavior_{analysis_data.event_type}",
            features=features,
            user_id=current_user.id,
            ai_advisor=ollama_shadow_advisor,
        )

        return BehaviorAnalyticsResponse(
            user_id=current_user.id,
            session_id=session_id,
            risk_score=decision.score / 100,
            risk_level=decision.outcome,
            anomalies_detected=decision.reason_codes,
            behavioral_insights={
                "policy": decision.policy_name,
                "policy_version": decision.policy_version,
                "enforced_by": "deterministic_policy",
            },
            alerts_triggered=[],
        )

    except Exception as e:
        logger.error(f"Error analyzing behavior for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to analyze behavior"
        )

@router.get("/my-risk-score", response_model=RiskScoreResponse)
async def get_my_risk_score(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's latest risk score"""
    try:
        result = await db.execute(
            text("""
                SELECT risk_score, risk_level, risk_factors, anomalies, created_at
                FROM risk_scores
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": current_user.id}
        )

        risk_data = result.fetchone()

        if not risk_data:
            return RiskScoreResponse(
                user_id=current_user.id,
                risk_score=0.0,
                risk_level="unknown",
                risk_factors=[],
                anomalies=[],
                timestamp=datetime.utcnow().isoformat()
            )

        return RiskScoreResponse(
            user_id=current_user.id,
            risk_score=float(risk_data[0]),
            risk_level=risk_data[1],
            risk_factors=json.loads(risk_data[2]) if risk_data[2] else [],
            anomalies=json.loads(risk_data[3]) if risk_data[3] else [],
            timestamp=risk_data[4].isoformat()
        )

    except Exception as e:
        logger.error(f"Error getting risk score for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve risk score"
        )

@router.get("/my-behavior-summary", response_model=UserBehaviorSummaryResponse)
async def get_my_behavior_summary(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's behavior summary"""
    try:
        # Get total events count
        events_result = await db.execute(
            text("""
                SELECT COUNT(*) as total_events,
                       COUNT(DISTINCT ip_address) as unique_ips,
                       COUNT(DISTINCT device_fingerprint) as unique_devices
                FROM behavior_analytics
                WHERE user_id = :user_id
                AND created_at >= :since
            """),
            {
                "user_id": current_user.id,
                "since": datetime.utcnow() - timedelta(days=30)
            }
        )

        stats = events_result.fetchone()
        total_events = stats[0] if stats else 0
        unique_ips = stats[1] if stats else 0
        unique_devices = stats[2] if stats else 0

        # Get recent risk scores
        risk_result = await db.execute(
            text("""
                SELECT risk_score, risk_level, created_at
                FROM risk_scores
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                LIMIT 10
            """),
            {"user_id": current_user.id}
        )

        risk_history = [
            {
                "risk_score": float(row[0]),
                "risk_level": row[1],
                "timestamp": row[2].isoformat()
            }
            for row in risk_result.fetchall()
        ]

        # Get recent anomalies
        anomalies_result = await db.execute(
            text("""
                SELECT DISTINCT anomalies
                FROM risk_scores
                WHERE user_id = :user_id
                AND created_at >= :since
                AND anomalies IS NOT NULL
            """),
            {
                "user_id": current_user.id,
                "since": datetime.utcnow() - timedelta(days=7)
            }
        )

        recent_anomalies = []
        for row in anomalies_result.fetchall():
            if row[0]:
                anomalies = json.loads(row[0])
                recent_anomalies.extend(anomalies)

        # Remove duplicates
        recent_anomalies = list(set(recent_anomalies))

        # Get last analysis timestamp
        last_analysis = None
        if risk_history:
            last_analysis = risk_history[0]["timestamp"]

        return UserBehaviorSummaryResponse(
            user_id=current_user.id,
            total_events=total_events,
            risk_score_history=risk_history,
            recent_anomalies=recent_anomalies,
            device_count=unique_devices,
            location_count=unique_ips,  # Using unique IPs as proxy for locations
            last_analysis=last_analysis
        )

    except Exception as e:
        logger.error(f"Error getting behavior summary for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve behavior summary"
        )

# Admin Endpoints
@router.get("/admin/users/{user_id}/risk-score", response_model=RiskScoreResponse)
async def get_user_risk_score(
    user_id: str,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin endpoint to get any user's risk score"""
    try:
        result = await db.execute(
            text("""
                SELECT risk_score, risk_level, risk_factors, anomalies, created_at
                FROM risk_scores
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": user_id}
        )

        risk_data = result.fetchone()

        if not risk_data:
            raise HTTPException(
                status_code=404,
                detail="No risk data found for user"
            )

        return RiskScoreResponse(
            user_id=user_id,
            risk_score=float(risk_data[0]),
            risk_level=risk_data[1],
            risk_factors=json.loads(risk_data[2]) if risk_data[2] else [],
            anomalies=json.loads(risk_data[3]) if risk_data[3] else [],
            timestamp=risk_data[4].isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting risk score for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve risk score"
        )

@router.get("/admin/fraud-alerts", response_model=List[FraudAlertResponse])
async def get_fraud_alerts(
    status: Optional[str] = Query(None, description="Filter by status (active, resolved)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    limit: int = Query(50, description="Maximum number of alerts to return"),
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin endpoint to get fraud alerts"""
    try:
        query = """
            SELECT id, user_id, alert_type, risk_score, risk_level, severity, status, created_at
            FROM fraud_alerts
            WHERE 1=1
        """
        params = {}

        if status:
            query += " AND status = :status"
            params["status"] = status

        if severity:
            query += " AND severity = :severity"
            params["severity"] = severity

        query += " ORDER BY created_at DESC LIMIT :limit"
        params["limit"] = limit

        result = await db.execute(text(query), params)

        alerts = []
        for row in result.fetchall():
            alerts.append(FraudAlertResponse(
                id=row[0],
                user_id=row[1],
                alert_type=row[2],
                risk_score=float(row[3]) if row[3] else 0.0,
                risk_level=row[4] or "unknown",
                severity=row[5] or "medium",
                status=row[6] or "active",
                created_at=row[7].isoformat()
            ))

        return alerts

    except Exception as e:
        logger.error(f"Error getting fraud alerts: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve fraud alerts"
        )

@router.post("/admin/fraud-alerts/{alert_id}/resolve")
async def resolve_fraud_alert(
    alert_id: str,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin endpoint to resolve a fraud alert"""
    try:
        result = await db.execute(
            text("""
                UPDATE fraud_alerts
                SET status = 'resolved', resolved_at = :resolved_at, resolved_by = :resolved_by
                WHERE id = :alert_id
            """),
            {
                "alert_id": alert_id,
                "resolved_at": datetime.utcnow(),
                "resolved_by": admin_user.id
            }
        )

        if result.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Fraud alert not found"
            )

        await db.commit()

        return {"success": True, "message": "Fraud alert resolved successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving fraud alert {alert_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to resolve fraud alert"
        )

@router.get("/admin/behavior-analytics/dashboard")
async def get_behavior_analytics_dashboard(
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin endpoint to get behavioral analytics dashboard data"""
    try:
        # Get overall statistics
        stats_result = await db.execute(
            text("""
                SELECT
                    COUNT(DISTINCT user_id) as total_users_monitored,
                    COUNT(*) as total_events,
                    AVG(risk_score) as avg_risk_score
                FROM behavior_analytics ba
                LEFT JOIN risk_scores rs ON ba.user_id = rs.user_id
                WHERE ba.created_at >= :since
            """),
            {"since": datetime.utcnow() - timedelta(days=30)}
        )

        stats = stats_result.fetchone()

        # Get high-risk users
        high_risk_result = await db.execute(
            text("""
                SELECT DISTINCT rs.user_id, u.email, rs.risk_score, rs.risk_level, rs.created_at
                FROM risk_scores rs
                JOIN users u ON rs.user_id = u.id
                WHERE rs.risk_score > 0.7
                AND rs.created_at >= :since
                ORDER BY rs.risk_score DESC, rs.created_at DESC
                LIMIT 10
            """),
            {"since": datetime.utcnow() - timedelta(days=7)}
        )

        high_risk_users = [
            {
                "user_id": row[0],
                "email": row[1],
                "risk_score": float(row[2]),
                "risk_level": row[3],
                "timestamp": row[4].isoformat()
            }
            for row in high_risk_result.fetchall()
        ]

        # Get alert statistics
        alert_stats_result = await db.execute(
            text("""
                SELECT status, severity, COUNT(*) as count
                FROM fraud_alerts
                WHERE created_at >= :since
                GROUP BY status, severity
                ORDER BY status, severity
            """),
            {"since": datetime.utcnow() - timedelta(days=30)}
        )

        alert_stats = {}
        for row in alert_stats_result.fetchall():
            status = row[0]
            severity = row[1]
            count = row[2]

            if status not in alert_stats:
                alert_stats[status] = {}
            alert_stats[status][severity] = count

        return {
            "overview": {
                "total_users_monitored": stats[0] if stats else 0,
                "total_events": stats[1] if stats else 0,
                "average_risk_score": float(stats[2]) if stats and stats[2] else 0.0,
                "period_days": 30
            },
            "high_risk_users": high_risk_users,
            "alert_statistics": alert_stats,
            "generated_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting behavior analytics dashboard: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve dashboard data"
        )