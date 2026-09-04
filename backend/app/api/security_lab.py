"""Admin-only API for bounded FlowShield security simulations and their evidence."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.connection import get_db
from app.models.security_lab import SecuritySimulationRun
from app.models.user import User
from app.services.security_lab_service import (
    SecurityLabDisabled,
    UnsafeSimulationTarget,
    list_scenarios,
    run_scenario,
)
from app.utils.admin_auth import get_admin_user

router = APIRouter(prefix="/admin/security-lab", tags=["security-lab"])


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seed: int = Field(default=0, ge=0, le=2_147_483_647)


def _run_response(run: SecuritySimulationRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "scenario_id": run.scenario_id,
        "status": run.status,
        "seed": run.seed,
        "target_origin": run.target_origin,
        "evidence": run.evidence,
        "evidence_digest": run.evidence_digest,
        "requested_by": run.requested_by,
        "created_at": run.created_at,
    }


@router.get("/scenarios")
async def scenarios(_admin_user: User = Depends(get_admin_user)):
    return {"enabled": settings.SECURITY_LAB_ENABLED, "scenarios": list_scenarios()}


@router.post("/scenarios/{scenario_id}/runs", status_code=status.HTTP_201_CREATED)
async def execute_scenario(
    scenario_id: str,
    body: RunRequest,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = run_scenario(scenario_id, body.seed)
    except SecurityLabDisabled as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UnsafeSimulationTarget as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown security simulation scenario") from exc

    run = SecuritySimulationRun(
        scenario_id=scenario_id,
        status="passed" if result["passed"] else "failed",
        seed=body.seed,
        target_origin=result["target_origin"],
        evidence=result,
        evidence_digest=result["evidence_digest"],
        requested_by=admin_user.id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return _run_response(run)


@router.get("/runs")
async def list_runs(
    limit: int = Query(default=50, ge=1, le=200),
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SecuritySimulationRun).order_by(SecuritySimulationRun.created_at.desc()).limit(limit)
    )
    return [_run_response(run) for run in result.scalars().all()]


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    run = await db.get(SecuritySimulationRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security simulation run not found")
    return _run_response(run)