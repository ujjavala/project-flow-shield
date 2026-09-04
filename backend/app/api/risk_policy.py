"""Administrative API for versioned policies and explainable risk decisions."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.models.risk_policy import RiskDecision, RiskPolicy
from app.models.user import User
from app.services.risk_policy_service import (
    RiskFeatures,
    activate_policy,
    canonical_policy_checksum,
    evaluate_and_persist,
    ollama_shadow_advisor,
    validate_policy_document,
)
from app.utils.admin_auth import get_admin_user, get_super_admin_user

router = APIRouter(prefix="/risk", tags=["risk-policy"])


class PolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: int = Field(ge=1)
    description: str | None = Field(default=None, max_length=1000)
    policy_document: dict[str, Any]
    activate: bool = False


class RiskEvaluationRequest(BaseModel):
    correlation_id: str | None = Field(default=None, min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=255)
    context: str = Field(default="admin_simulation", min_length=1, max_length=50)
    source_ip_blocked: bool = False
    known_network: bool = True
    known_device: bool = True
    user_agent_present: bool = True
    account_disabled: bool = False
    credential_compromise_suspected: bool = False
    impossible_travel: bool = False
    recent_failed_attempts: int = Field(default=0, ge=0, le=100)
    behavioral_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class DecisionResponse(BaseModel):
    id: str
    correlation_id: str
    user_id: str | None = None
    context: str
    outcome: Literal["allow", "step_up", "deny", "review"]
    score: int
    policy_name: str
    policy_version: int
    policy_checksum: str
    input_features: dict[str, Any]
    contributions: list[dict[str, Any]]
    reason_codes: list[str]
    ai_shadow: dict[str, Any] | None
    ai_shadow_enabled: bool
    enforced_by: str
    created_at: Any


def _policy_response(policy: RiskPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "version": policy.version,
        "status": policy.status,
        "description": policy.description,
        "policy_document": policy.policy_document,
        "checksum": policy.checksum,
        "created_by": policy.created_by,
        "created_at": policy.created_at,
        "activated_at": policy.activated_at,
    }


def _decision_response(decision: RiskDecision) -> DecisionResponse:
    return DecisionResponse(
        id=decision.id,
        correlation_id=decision.correlation_id,
        user_id=decision.user_id,
        context=decision.context,
        outcome=decision.outcome,
        score=decision.score,
        policy_name=decision.policy_name,
        policy_version=decision.policy_version,
        policy_checksum=decision.policy_checksum,
        input_features=decision.input_features,
        contributions=decision.contributions,
        reason_codes=decision.reason_codes,
        ai_shadow=decision.ai_shadow,
        ai_shadow_enabled=decision.ai_shadow_enabled,
        enforced_by=decision.enforced_by,
        created_at=decision.created_at,
    )


@router.get("/policies")
async def list_policies(
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(RiskPolicy).order_by(RiskPolicy.name, RiskPolicy.version.desc()))
    return [_policy_response(policy) for policy in result.scalars().all()]


@router.post("/policies", status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreateRequest,
    admin_user: User = Depends(get_super_admin_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        validate_policy_document(body.policy_document)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    policy = RiskPolicy(
        name=body.name,
        version=body.version,
        status="draft",
        description=body.description,
        policy_document=body.policy_document,
        checksum=canonical_policy_checksum(body.policy_document),
        created_by=admin_user.id,
    )
    db.add(policy)
    try:
        await db.commit()
        await db.refresh(policy)
        if body.activate:
            policy = await activate_policy(db, policy)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Policy name and version already exist") from exc
    return _policy_response(policy)


@router.post("/policies/{policy_id}/activate")
async def activate_policy_version(
    policy_id: str,
    _admin_user: User = Depends(get_super_admin_user),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(RiskPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk policy not found")
    return _policy_response(await activate_policy(db, policy))


@router.post("/decisions/evaluate", response_model=DecisionResponse)
async def evaluate_risk(
    body: RiskEvaluationRequest,
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    persisted = await evaluate_and_persist(
        db,
        correlation_id=body.correlation_id or str(uuid.uuid4()),
        user_id=body.user_id,
        context=body.context,
        features=RiskFeatures(
            source_ip_blocked=body.source_ip_blocked,
            known_network=body.known_network,
            known_device=body.known_device,
            user_agent_present=body.user_agent_present,
            account_disabled=body.account_disabled,
            credential_compromise_suspected=body.credential_compromise_suspected,
            impossible_travel=body.impossible_travel,
            recent_failed_attempts=body.recent_failed_attempts,
            behavioral_risk_score=body.behavioral_risk_score,
        ),
        ai_advisor=ollama_shadow_advisor,
    )
    decision = await db.get(RiskDecision, persisted.id)
    return _decision_response(decision)


@router.get("/decisions", response_model=list[DecisionResponse])
async def list_decisions(
    limit: int = Query(default=50, ge=1, le=200),
    outcome: Literal["allow", "step_up", "deny", "review"] | None = None,
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    statement = select(RiskDecision)
    if outcome is not None:
        statement = statement.where(RiskDecision.outcome == outcome)
    result = await db.execute(statement.order_by(RiskDecision.created_at.desc()).limit(limit))
    return [_decision_response(decision) for decision in result.scalars().all()]


@router.get("/decisions/{decision_id}", response_model=DecisionResponse)
async def get_decision(
    decision_id: str,
    _admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    decision = await db.get(RiskDecision, decision_id)
    if decision is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk decision not found")
    return _decision_response(decision)
