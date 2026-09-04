"""Read-only multi-agent advisors for privileged-access workflows."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from temporalio import activity

from app.database.connection import AsyncSessionLocal
from app.models.iam import (
    IAMOperationEffect,
    IAMPermission,
    IAMRole,
    IAMRoleRequest,
    IAMScope,
    role_permissions_table,
)
from app.models.user import User
from app.models.auth_security import PasskeyCredential
from app.services.privileged_access_advisory_service import review_privileged_access


def _bucket_duration(seconds: int) -> str:
    if seconds <= 3600:
        return "short"
    if seconds <= 28_800:
        return "medium"
    return "long"


def _bucket_justification(value: str | None) -> str:
    length = len(value or "")
    if length < 40:
        return "brief"
    if length < 240:
        return "normal"
    return "long"


def _priority_bucket(priority: int) -> str:
    if priority >= 90:
        return "critical"
    if priority >= 60:
        return "high"
    if priority >= 30:
        return "medium"
    return "low"


async def _load_sanitized_evidence(request_id: str) -> tuple[IAMRoleRequest, dict[str, Any]]:
    async with AsyncSessionLocal() as db:
        request = await db.get(IAMRoleRequest, request_id)
        if request is None:
            raise ValueError("Privileged-access request not found")
        role = await db.get(IAMRole, request.role_id)
        target = await db.get(User, request.target_user_id)
        scope = await db.get(IAMScope, request.scope_id) if request.scope_id else None
        if role is None or target is None:
            raise ValueError("Privileged-access evidence is unavailable")

        permission_rows = await db.execute(
            select(IAMPermission.risk_level).join(
                role_permissions_table,
                role_permissions_table.c.permission_id == IAMPermission.id,
            ).where(role_permissions_table.c.role_id == role.id)
        )
        permission_values = permission_rows.scalars().all()
        passkey_rows = await db.execute(
            select(PasskeyCredential.id).where(PasskeyCredential.user_id == target.id).limit(1)
        )
        has_passkey = passkey_rows.scalar_one_or_none() is not None
        permission_risks = sorted({str(value or "low") for value in permission_values})
        evidence = {
            "permission_count": len(permission_values),
            "permission_risk_levels": permission_risks,
            "role_priority_bucket": _priority_bucket(role.priority or 0),
            "scope_type": scope.scope_type if scope else "global",
            "duration_bucket": _bucket_duration(request.duration_seconds or 0),
            "target_account_active": bool(target.is_active),
            "strong_auth_configured": bool(target.totp_enabled or has_passkey),
            "justification_length_bucket": _bucket_justification(request.justification),
        }
        return request, evidence


@activity.defn(name="review_privileged_access_advisor")
async def review_privileged_access_advisor(data: tuple[str, str]) -> dict[str, Any]:
    """Run one bounded advisor and persist its non-enforcing result."""
    request_id, agent_role = data
    if agent_role not in {"least_privilege", "security_context"}:
        raise ValueError("Unsupported privileged-access advisor role")

    effect_id = f"{request_id}:advisory:{agent_role}:v1"
    async with AsyncSessionLocal() as db:
        existing = await db.get(IAMOperationEffect, effect_id)
        if existing is not None:
            return existing.details

    request, evidence = await _load_sanitized_evidence(request_id)
    result = await review_privileged_access(agent_role, evidence)
    output_digest = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    persisted_result = {**result, "output_digest": output_digest}

    async with AsyncSessionLocal() as db:
        if await db.get(IAMOperationEffect, effect_id) is None:
            db.add(IAMOperationEffect(
                effect_id=effect_id,
                request_id=request_id,
                effect_type="agent_advisory",
                actor_id=request.requester_id,
                details=persisted_result,
            ))
            await db.commit()
    return persisted_result
