"""Durable human-approved, time-bound privileged-access workflow."""

import asyncio
from datetime import timedelta
from typing import Optional

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from app.temporal.privileged_access_types import (
        ApprovalDecision,
        PrivilegedAccessRequest,
        PrivilegedAccessStatus,
        is_valid_privileged_access_transition,
    )


_ACTIVITY_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=8,
)


@workflow.defn
class PrivilegedAccessWorkflow:
    """Wait for a real decision, grant access, then revoke it after a durable timer."""

    def __init__(self) -> None:
        self._request_id = ""
        self._state = "initializing"
        self._decision: Optional[ApprovalDecision] = None
        self._grant_effect_id: Optional[str] = None
        self._denial_reason: Optional[str] = None
        self._advisories: tuple[dict, ...] = ()

    def _transition(self, next_state: str) -> None:
        if not is_valid_privileged_access_transition(self._state, next_state):
            raise RuntimeError(f"Invalid privileged-access transition: {self._state} -> {next_state}")
        self._state = next_state

    @workflow.signal
    async def decide(self, decision: ApprovalDecision) -> None:
        if self._decision is None and self._state in {"initializing", "pending_approval"}:
            self._decision = decision

    @workflow.query
    def status(self) -> PrivilegedAccessStatus:
        return PrivilegedAccessStatus(
            request_id=self._request_id,
            state=self._state,
            approver_id=self._decision.approver_id if self._decision else None,
            grant_effect_id=self._grant_effect_id,
            denial_reason=self._denial_reason,
            advisories=self._advisories,
        )

    @workflow.run
    async def run(self, request: PrivilegedAccessRequest) -> PrivilegedAccessStatus:
        self._request_id = request.request_id
        validation = await workflow.execute_activity(
            "validate_privileged_access",
            request,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )
        if not validation["valid"]:
            self._transition("invalid")
            self._denial_reason = validation["reason"]
            return self.status()

        async def advisory(role: str) -> dict:
            try:
                return await workflow.execute_activity(
                    "review_privileged_access_advisor",
                    (request.request_id, role),
                    start_to_close_timeout=timedelta(seconds=15),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )
            except Exception:
                workflow.logger.warning("Non-enforcing %s advisor unavailable", role)
                return {
                    "schema_version": "1",
                    "prompt_version": "privileged-access-v1",
                    "policy_version": "privileged-access-policy-v1",
                    "agent_role": role,
                    "recommendation": "inconclusive",
                    "reason_codes": ["ADVISOR_UNAVAILABLE"],
                    "evidence_refs": [],
                    "provider": "unavailable",
                    "model": None,
                    "fallback_reason": "activity_failure",
                    "enforcing": False,
                }

        reviews = await asyncio.gather(
            advisory("least_privilege"),
            advisory("security_context"),
        )
        self._advisories = tuple(reviews)

        self._transition("pending_approval")
        await workflow.execute_activity(
            "record_privileged_access_notification",
            (request.request_id, "approval_requested"),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )

        try:
            await workflow.wait_condition(
                lambda: self._decision is not None,
                timeout=timedelta(seconds=request.approval_timeout_seconds),
            )
        except TimeoutError:
            self._transition("expired")
            self._denial_reason = "approval_timeout"
            await workflow.execute_activity(
                "mark_privileged_access_expired",
                request.request_id,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_ACTIVITY_RETRY,
            )
            return self.status()

        decision = self._decision
        if decision is None:
            raise RuntimeError("approval decision was not recorded")
        await workflow.execute_activity(
            "persist_approval_decision",
            (request.request_id, decision),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )
        if not decision.approved:
            self._transition("denied")
            self._denial_reason = "denied_by_approver"
            await workflow.execute_activity(
                "record_privileged_access_notification",
                (request.request_id, "denied"),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_ACTIVITY_RETRY,
            )
            return self.status()

        self._grant_effect_id = await workflow.execute_activity(
            "grant_privileged_access",
            request,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )
        self._transition("active")
        await workflow.execute_activity(
            "record_privileged_access_notification",
            (request.request_id, "granted"),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )

        await workflow.sleep(timedelta(seconds=request.duration_seconds))
        self._transition("revoking")
        await workflow.execute_activity(
            "revoke_privileged_access",
            request,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )
        self._transition("revoked")
        await workflow.execute_activity(
            "record_privileged_access_notification",
            (request.request_id, "revoked"),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_ACTIVITY_RETRY,
        )
        return self.status()
