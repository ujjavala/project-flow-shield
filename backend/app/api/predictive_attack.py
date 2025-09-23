"""
Predictive Attack Simulation API
Revolutionary self-defending system API endpoints
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
import json

from app.database.connection import get_db
from app.models.user import User
from app.utils.admin_auth import get_admin_user, get_super_admin_user
from app.temporal.client import get_temporal_client
from app.temporal.workflows.predictive_attack_workflow import (
    PredictiveAttackSimulationWorkflow,
    AttackSimulationRequest,
    ContinuousAttackMonitoringWorkflow
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic Models for API
class AttackSimulationRequestModel(BaseModel):
    target_system: str = Field(..., description="Target system identifier")
    simulation_type: str = Field(default="standard", description="Type of simulation (standard, deep, targeted)")
    attack_vectors: Optional[List[str]] = Field(default=None, description="Specific attack vectors to simulate")
    severity_threshold: float = Field(default=0.7, ge=0.0, le=1.0, description="Minimum severity threshold")
    max_simulations: int = Field(default=10, ge=1, le=50, description="Maximum number of simulations")
    safety_mode: bool = Field(default=True, description="Enable safety mode")
    auto_remediation: bool = Field(default=False, description="Enable automatic remediation")

class AttackSimulationResponse(BaseModel):
    simulation_id: str
    target_system: str
    predictions_analyzed: int
    simulations_executed: int
    vulnerabilities_discovered: int
    critical_vulnerabilities: int
    overall_security_score: float
    recommendations: List[str]
    execution_time_minutes: float
    status: str

class AttackPredictionModel(BaseModel):
    id: str
    attack_type: str
    likelihood: float
    confidence: float
    target_component: str
    reasoning: str
    created_at: str

class SimulationResultModel(BaseModel):
    id: str
    simulation_name: str
    target_system: str
    status: str
    vulnerabilities_found: int
    security_impact_score: float
    duration_seconds: int
    created_at: str
    completed_at: Optional[str]

class SecurityDashboardModel(BaseModel):
    overview: Dict[str, Any]
    recent_simulations: List[SimulationResultModel]
    high_risk_predictions: List[AttackPredictionModel]
    security_metrics: Dict[str, Any]
    top_vulnerabilities: List[Dict[str, Any]]

class ContinuousMonitoringRequest(BaseModel):
    target_system: str
    monitoring_duration_hours: int = Field(default=24, ge=1, le=168)  # Max 1 week

# API Endpoints

@router.post("/simulate", response_model=AttackSimulationResponse)
async def start_attack_simulation(
    request: AttackSimulationRequestModel,
    background_tasks: BackgroundTasks,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Start predictive attack simulation for a target system"""
    try:
        # Convert to workflow request
        simulation_request = AttackSimulationRequest(
            target_system=request.target_system,
            simulation_type=request.simulation_type,
            attack_vectors=request.attack_vectors,
            severity_threshold=request.severity_threshold,
            max_simulations=request.max_simulations,
            safety_mode=request.safety_mode,
            requester_id=admin_user.id,
            metadata={
                "auto_remediation": request.auto_remediation,
                "initiated_by": admin_user.email,
                "api_version": "v1"
            }
        )

        # Start Temporal workflow
        temporal_client = await get_temporal_client()
        simulation_id = f"attack-sim-{request.target_system}-{datetime.utcnow().timestamp()}"

        workflow_handle = await temporal_client.start_workflow(
            PredictiveAttackSimulationWorkflow.run,
            simulation_request,
            id=simulation_id,
            task_queue="oauth2-task-queue",
            execution_timeout=timedelta(hours=2)
        )

        # Return immediate response with simulation ID
        return AttackSimulationResponse(
            simulation_id=simulation_id,
            target_system=request.target_system,
            predictions_analyzed=0,
            simulations_executed=0,
            vulnerabilities_discovered=0,
            critical_vulnerabilities=0,
            overall_security_score=0.0,
            recommendations=[],
            execution_time_minutes=0.0,
            status="started"
        )

    except Exception as e:
        logger.error(f"Failed to start attack simulation: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start attack simulation: {str(e)}"
        )

@router.get("/simulation/{simulation_id}/status")
async def get_simulation_status(
    simulation_id: str,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Get status of a running simulation"""
    try:
        # Check Temporal workflow status
        temporal_client = await get_temporal_client()

        try:
            workflow_handle = temporal_client.get_workflow_handle(simulation_id)
            workflow_result = await workflow_handle.result()

            return {
                "simulation_id": simulation_id,
                "status": "completed" if workflow_result.get("success") else "failed",
                "result": workflow_result
            }
        except Exception:
            # Check if workflow is still running
            return {
                "simulation_id": simulation_id,
                "status": "running",
                "message": "Simulation in progress"
            }

    except Exception as e:
        logger.error(f"Failed to get simulation status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get simulation status"
        )

@router.get("/simulations", response_model=List[SimulationResultModel])
async def list_simulations(
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    target_system: Optional[str] = Query(None),
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """List recent attack simulations"""
    try:
        query = """
            SELECT id, simulation_name, target_system, status,
                   COALESCE((vulnerabilities_found->>'count')::int, 0) as vuln_count,
                   COALESCE(security_impact_score, 0.0) as impact_score,
                   COALESCE(duration_seconds, 0) as duration,
                   created_at, completed_at
            FROM attack_simulations
            WHERE 1=1
        """
        params = {}

        if status:
            query += " AND status = :status"
            params["status"] = status

        if target_system:
            query += " AND target_system = :target_system"
            params["target_system"] = target_system

        query += " ORDER BY created_at DESC LIMIT :limit"
        params["limit"] = limit

        result = await db.execute(text(query), params)
        simulations = []

        for row in result.fetchall():
            simulations.append(SimulationResultModel(
                id=row[0],
                simulation_name=row[1] or f"Simulation {row[0][:8]}",
                target_system=row[2] or "unknown",
                status=row[3] or "pending",
                vulnerabilities_found=row[4],
                security_impact_score=float(row[5]),
                duration_seconds=row[6],
                created_at=row[7].isoformat() if row[7] else datetime.utcnow().isoformat(),
                completed_at=row[8].isoformat() if row[8] else None
            ))

        return simulations

    except Exception as e:
        logger.error(f"Failed to list simulations: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve simulations"
        )

@router.get("/predictions", response_model=List[AttackPredictionModel])
async def list_attack_predictions(
    limit: int = Query(20, ge=1, le=100),
    likelihood_threshold: float = Query(0.5, ge=0.0, le=1.0),
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """List recent attack predictions"""
    try:
        result = await db.execute(
            text("""
                SELECT id, prediction_type, predicted_likelihood, confidence_score,
                       target_component, ai_reasoning, created_at
                FROM attack_predictions
                WHERE predicted_likelihood >= :threshold
                AND expires_at > NOW()
                ORDER BY predicted_likelihood DESC, created_at DESC
                LIMIT :limit
            """),
            {
                "threshold": likelihood_threshold,
                "limit": limit
            }
        )

        predictions = []
        for row in result.fetchall():
            predictions.append(AttackPredictionModel(
                id=row[0],
                attack_type=row[1],
                likelihood=float(row[2]),
                confidence=float(row[3]),
                target_component=row[4],
                reasoning=row[5] or "No reasoning provided",
                created_at=row[6].isoformat() if row[6] else datetime.utcnow().isoformat()
            ))

        return predictions

    except Exception as e:
        logger.error(f"Failed to list predictions: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve predictions"
        )

@router.get("/dashboard", response_model=SecurityDashboardModel)
async def get_security_dashboard(
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Get comprehensive security dashboard data"""
    try:
        # Get overview statistics
        overview_result = await db.execute(
            text("""
                SELECT
                    COUNT(DISTINCT target_system) as systems_monitored,
                    COUNT(*) as total_simulations,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_simulations,
                    AVG(COALESCE(security_impact_score, 0)) as avg_security_score,
                    COUNT(CASE WHEN created_at >= NOW() - INTERVAL '24 hours' THEN 1 END) as simulations_24h
                FROM attack_simulations
                WHERE created_at >= NOW() - INTERVAL '30 days'
            """)
        )
        overview_stats = overview_result.fetchone()

        # Get recent simulations
        recent_sims_result = await db.execute(
            text("""
                SELECT id, simulation_name, target_system, status,
                       COALESCE((vulnerabilities_found->>'count')::int, 0) as vuln_count,
                       COALESCE(security_impact_score, 0.0) as impact_score,
                       COALESCE(duration_seconds, 0) as duration,
                       created_at, completed_at
                FROM attack_simulations
                ORDER BY created_at DESC
                LIMIT 10
            """)
        )

        recent_simulations = []
        for row in recent_sims_result.fetchall():
            recent_simulations.append(SimulationResultModel(
                id=row[0],
                simulation_name=row[1] or f"Simulation {row[0][:8]}",
                target_system=row[2] or "unknown",
                status=row[3] or "pending",
                vulnerabilities_found=row[4],
                security_impact_score=float(row[5]),
                duration_seconds=row[6],
                created_at=row[7].isoformat() if row[7] else datetime.utcnow().isoformat(),
                completed_at=row[8].isoformat() if row[8] else None
            ))

        # Get high-risk predictions
        high_risk_result = await db.execute(
            text("""
                SELECT id, prediction_type, predicted_likelihood, confidence_score,
                       target_component, ai_reasoning, created_at
                FROM attack_predictions
                WHERE predicted_likelihood >= 0.7
                AND expires_at > NOW()
                ORDER BY predicted_likelihood DESC
                LIMIT 10
            """)
        )

        high_risk_predictions = []
        for row in high_risk_result.fetchall():
            high_risk_predictions.append(AttackPredictionModel(
                id=row[0],
                attack_type=row[1],
                likelihood=float(row[2]),
                confidence=float(row[3]),
                target_component=row[4],
                reasoning=row[5] or "No reasoning provided",
                created_at=row[6].isoformat() if row[6] else datetime.utcnow().isoformat()
            ))

        # Get security metrics
        metrics_result = await db.execute(
            text("""
                SELECT
                    COALESCE(AVG(prediction_accuracy), 0.8) as prediction_accuracy,
                    COALESCE(AVG(false_positive_rate), 0.1) as false_positive_rate,
                    COALESCE(AVG(security_posture_score), 75.0) as security_posture,
                    COUNT(*) as days_with_metrics
                FROM predictive_attack_metrics
                WHERE metric_date >= CURRENT_DATE - INTERVAL '7 days'
            """)
        )
        metrics_stats = metrics_result.fetchone()

        # Get top vulnerabilities
        vulns_result = await db.execute(
            text("""
                SELECT
                    vuln->>'type' as vuln_type,
                    COUNT(*) as count,
                    AVG((vuln->>'severity_score')::float) as avg_severity
                FROM attack_simulations,
                     JSON_ARRAY_ELEMENTS(vulnerabilities_found) as vuln
                WHERE created_at >= NOW() - INTERVAL '7 days'
                AND vulnerabilities_found IS NOT NULL
                GROUP BY vuln->>'type'
                ORDER BY count DESC
                LIMIT 5
            """)
        )

        top_vulnerabilities = []
        for row in vulns_result.fetchall():
            top_vulnerabilities.append({
                "vulnerability_type": row[0] or "unknown",
                "occurrence_count": row[1],
                "average_severity": float(row[2]) if row[2] else 0.0
            })

        return SecurityDashboardModel(
            overview={
                "systems_monitored": overview_stats[0] if overview_stats else 0,
                "total_simulations": overview_stats[1] if overview_stats else 0,
                "completed_simulations": overview_stats[2] if overview_stats else 0,
                "average_security_score": float(overview_stats[3]) if overview_stats and overview_stats[3] else 0.0,
                "simulations_24h": overview_stats[4] if overview_stats else 0,
                "last_updated": datetime.utcnow().isoformat()
            },
            recent_simulations=recent_simulations,
            high_risk_predictions=high_risk_predictions,
            security_metrics={
                "prediction_accuracy": float(metrics_stats[0]) if metrics_stats else 0.8,
                "false_positive_rate": float(metrics_stats[1]) if metrics_stats else 0.1,
                "security_posture_score": float(metrics_stats[2]) if metrics_stats else 75.0,
                "days_with_data": metrics_stats[3] if metrics_stats else 0
            },
            top_vulnerabilities=top_vulnerabilities
        )

    except Exception as e:
        logger.error(f"Failed to get security dashboard: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve dashboard data"
        )

@router.post("/continuous-monitoring/start")
async def start_continuous_monitoring(
    request: ContinuousMonitoringRequest,
    admin_user: User = Depends(get_super_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Start continuous attack monitoring for a system"""
    try:
        temporal_client = await get_temporal_client()
        monitoring_id = f"continuous-monitor-{request.target_system}-{datetime.utcnow().timestamp()}"

        workflow_handle = await temporal_client.start_workflow(
            ContinuousAttackMonitoringWorkflow.run,
            request.target_system,
            request.monitoring_duration_hours,
            id=monitoring_id,
            task_queue="oauth2-task-queue",
            execution_timeout=timedelta(hours=request.monitoring_duration_hours + 1)
        )

        return {
            "monitoring_id": monitoring_id,
            "target_system": request.target_system,
            "duration_hours": request.monitoring_duration_hours,
            "status": "started",
            "started_by": admin_user.email,
            "started_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to start continuous monitoring: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to start continuous monitoring"
        )

@router.post("/continuous-monitoring/{monitoring_id}/stop")
async def stop_continuous_monitoring(
    monitoring_id: str,
    admin_user: User = Depends(get_super_admin_user)
):
    """Stop continuous monitoring"""
    try:
        temporal_client = await get_temporal_client()
        workflow_handle = temporal_client.get_workflow_handle(monitoring_id)

        await workflow_handle.terminate("Stopped by admin request")

        return {
            "monitoring_id": monitoring_id,
            "status": "terminated",
            "stopped_by": admin_user.email,
            "stopped_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to stop monitoring: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to stop continuous monitoring"
        )

@router.get("/attack-surface/{system_id}")
async def get_attack_surface_analysis(
    system_id: str,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Get attack surface analysis for a system"""
    try:
        result = await db.execute(
            text("""
                SELECT * FROM attack_surfaces
                WHERE system_component = :system_id
                ORDER BY last_analyzed_at DESC
                LIMIT 1
            """),
            {"system_id": system_id}
        )

        analysis = result.fetchone()
        if not analysis:
            raise HTTPException(
                status_code=404,
                detail="No attack surface analysis found for this system"
            )

        return {
            "system_id": system_id,
            "component_type": analysis[2],
            "vulnerability_score": float(analysis[3]),
            "exposure_level": analysis[4],
            "attack_vectors": json.loads(analysis[5]) if analysis[5] else [],
            "security_controls": json.loads(analysis[6]) if analysis[6] else [],
            "last_analyzed": analysis[8].isoformat() if analysis[8] else None,
            "metadata": json.loads(analysis[7]) if analysis[7] else {}
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get attack surface analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve attack surface analysis"
        )

@router.delete("/simulation/{simulation_id}")
async def delete_simulation(
    simulation_id: str,
    admin_user: User = Depends(get_super_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a simulation record"""
    try:
        result = await db.execute(
            text("DELETE FROM attack_simulations WHERE id = :sim_id"),
            {"sim_id": simulation_id}
        )

        if result.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Simulation not found"
            )

        await db.commit()

        return {
            "simulation_id": simulation_id,
            "status": "deleted",
            "deleted_by": admin_user.email,
            "deleted_at": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete simulation: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to delete simulation"
        )