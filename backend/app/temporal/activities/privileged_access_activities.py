"""Activities for durable, approval-based privileged access."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, select, update
from temporalio import activity

from app.database.connection import AsyncSessionLocal
from app.models.iam import (
    IAMOperationEffect,
    IAMRole,
    IAMRoleRequest,
    IAMScope,
    IAMAuditLog,
    role_scope_table,
    user_roles_table,
)
from app.models.user import User
from app.temporal.privileged_access_types import ApprovalDecision, PrivilegedAccessRequest


def _now() -> datetime:
    return datetime.now(timezone.utc)


@activity.defn
async def validate_privileged_access(request: PrivilegedAccessRequest) -> dict[str, Any]:
    async with AsyncSessionLocal() as db:
        target = await db.get(User, request.target_user_id)
        role = await db.get(IAMRole, request.role_id)
        scope = await db.get(IAMScope, request.scope_id) if request.scope_id else None
        valid = bool(
            target
            and target.is_active
            and role
            and role.is_active
            and (not request.scope_id or (scope and scope.is_active))
        )
        return {"valid": valid, "reason": None if valid else "inactive_or_missing_subject_role_scope"}


@activity.defn
async def persist_approval_decision(data: tuple[str, ApprovalDecision]) -> None:
    request_id, decision = data
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(IAMRoleRequest)
            .where(IAMRoleRequest.id == request_id)
            .values(
                status="approved" if decision.approved else "denied",
                approved_by=decision.approver_id,
                approved_at=_now(),
            )
        )
        await db.commit()


@activity.defn
async def mark_privileged_access_expired(request_id: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(IAMRoleRequest)
            .where(IAMRoleRequest.id == request_id, IAMRoleRequest.status == "pending")
            .values(status="expired")
        )
        await db.commit()


@activity.defn
async def grant_privileged_access(request: PrivilegedAccessRequest) -> str:
    effect_id = f"{request.request_id}:grant:v1"
    async with AsyncSessionLocal() as db:
        if await db.get(IAMOperationEffect, effect_id):
            return effect_id

        assignment = await db.execute(
            select(user_roles_table).where(
                and_(
                    user_roles_table.c.user_id == request.target_user_id,
                    user_roles_table.c.role_id == request.role_id,
                )
            )
        )
        expires_at = _now().timestamp() + request.duration_seconds
        expires = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        if assignment.first():
            await db.execute(
                update(user_roles_table)
                .where(
                    user_roles_table.c.user_id == request.target_user_id,
                    user_roles_table.c.role_id == request.role_id,
                )
                .values(is_active=True, granted_by=request.requester_id, granted_at=_now(), expires_at=expires)
            )
        else:
            await db.execute(
                user_roles_table.insert().values(
                    user_id=request.target_user_id,
                    role_id=request.role_id,
                    granted_by=request.requester_id,
                    granted_at=_now(),
                    expires_at=expires,
                    is_active=True,
                )
            )

        if request.scope_id:
            scoped = await db.execute(
                select(role_scope_table).where(
                    role_scope_table.c.user_id == request.target_user_id,
                    role_scope_table.c.role_id == request.role_id,
                    role_scope_table.c.scope_id == request.scope_id,
                )
            )
            if scoped.first():
                await db.execute(
                    update(role_scope_table)
                    .where(
                        role_scope_table.c.user_id == request.target_user_id,
                        role_scope_table.c.role_id == request.role_id,
                        role_scope_table.c.scope_id == request.scope_id,
                    )
                    .values(is_active=True, granted_by=request.requester_id, granted_at=_now())
                )
            else:
                await db.execute(
                    role_scope_table.insert().values(
                        user_id=request.target_user_id,
                        role_id=request.role_id,
                        scope_id=request.scope_id,
                        granted_by=request.requester_id,
                        granted_at=_now(),
                        is_active=True,
                    )
                )

        db.add(IAMOperationEffect(
            effect_id=effect_id,
            request_id=request.request_id,
            effect_type="role_granted",
            actor_id=request.requester_id,
            details={
                "target_user_id": request.target_user_id,
                "role_id": request.role_id,
                "scope_id": request.scope_id,
                "expires_at": expires.isoformat(),
            },
        ))
        db.add(IAMAuditLog(
            actor_id=request.requester_id,
            action="privileged_access_granted",
            target_type="user_role",
            target_id=f"{request.target_user_id}:{request.role_id}",
            result="success",
            details={"request_id": request.request_id, "effect_id": effect_id},
        ))
        await db.execute(
            update(IAMRoleRequest).where(IAMRoleRequest.id == request.request_id).values(status="active")
        )
        await db.commit()
        return effect_id


@activity.defn
async def revoke_privileged_access(request: PrivilegedAccessRequest) -> str:
    effect_id = f"{request.request_id}:revoke:v1"
    async with AsyncSessionLocal() as db:
        if await db.get(IAMOperationEffect, effect_id):
            return effect_id
        await db.execute(
            update(user_roles_table)
            .where(
                user_roles_table.c.user_id == request.target_user_id,
                user_roles_table.c.role_id == request.role_id,
            )
            .values(is_active=False)
        )
        if request.scope_id:
            await db.execute(
                update(role_scope_table)
                .where(
                    role_scope_table.c.user_id == request.target_user_id,
                    role_scope_table.c.role_id == request.role_id,
                    role_scope_table.c.scope_id == request.scope_id,
                )
                .values(is_active=False)
            )
        db.add(IAMOperationEffect(
            effect_id=effect_id,
            request_id=request.request_id,
            effect_type="role_revoked",
            actor_id=None,
            details={
                "target_user_id": request.target_user_id,
                "role_id": request.role_id,
                "scope_id": request.scope_id,
                "reason": "duration_elapsed",
            },
        ))
        db.add(IAMAuditLog(
            actor_id=request.requester_id,
            action="privileged_access_revoked",
            target_type="user_role",
            target_id=f"{request.target_user_id}:{request.role_id}",
            result="success",
            details={"request_id": request.request_id, "effect_id": effect_id},
        ))
        await db.execute(
            update(IAMRoleRequest).where(IAMRoleRequest.id == request.request_id).values(status="revoked")
        )
        await db.commit()
        return effect_id


@activity.defn
async def record_privileged_access_notification(data: tuple[str, str]) -> None:
    """Record a notification reference without putting message contents in history."""
    request_id, event_type = data
    effect_id = f"{request_id}:notification:{event_type}:v1"
    async with AsyncSessionLocal() as db:
        if await db.get(IAMOperationEffect, effect_id):
            return
        request = await db.get(IAMRoleRequest, request_id)
        if request is None:
            return
        db.add(IAMOperationEffect(
            effect_id=effect_id,
            request_id=request_id,
            effect_type="notification_requested",
            actor_id=request.requester_id,
            details={"template_key": f"privileged_access_{event_type}", "request_id": request_id},
        ))
        await db.commit()
