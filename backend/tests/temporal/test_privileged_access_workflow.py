from dataclasses import asdict
from datetime import timedelta

import pytest
import pytest_asyncio
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from app.temporal.privileged_access_types import ApprovalDecision, PrivilegedAccessRequest
from app.temporal.workflows.privileged_access import PrivilegedAccessWorkflow


@pytest_asyncio.fixture
async def temporal_environment():
    environment = await WorkflowEnvironment.start_time_skipping()
    try:
        yield environment
    finally:
        await environment.shutdown()


def make_request(**overrides):
    values = {
        "request_id": "request-1",
        "requester_id": "requester-1",
        "target_user_id": "target-1",
        "role_id": "admin-role",
        "scope_id": "project-1",
        "duration_seconds": 3600,
        "approval_timeout_seconds": 1800,
    }
    values.update(overrides)
    return PrivilegedAccessRequest(**values)


def activity_set(events, failed_advisor=None):
    @activity.defn(name="validate_privileged_access")
    async def validate(request):
        events.append("validated")
        return {"valid": True, "reason": None}

    @activity.defn(name="persist_approval_decision")
    async def persist(data):
        events.append("approved" if data[1]["approved"] else "denied")

    @activity.defn(name="mark_privileged_access_expired")
    async def expire(request_id):
        events.append("approval_expired")

    @activity.defn(name="grant_privileged_access")
    async def grant(request):
        events.append("grant_activity")
        return f"{request['request_id']}:grant:v1"

    @activity.defn(name="revoke_privileged_access")
    async def revoke(request):
        events.append("revoke_activity")
        return f"{request['request_id']}:revoke:v1"

    @activity.defn(name="record_privileged_access_notification")
    async def notify(data):
        events.append(f"notification:{data[1]}")

    @activity.defn(name="review_privileged_access_advisor")
    async def review(data):
        events.append(f"reviewed:{data[1]}")
        if data[1] == failed_advisor:
            raise RuntimeError("advisor unavailable")
        return {
            "agent_role": data[1],
            "recommendation": "support",
            "reason_codes": ["BOUNDED_SCOPE"],
            "evidence_refs": ["scope_type"],
            "provider": "deterministic_fallback",
            "enforcing": False,
        }

    return [validate, persist, expire, grant, revoke, notify, review]


@pytest.mark.asyncio
async def test_approved_access_is_automatically_revoked(temporal_environment):
    events = []
    async with Worker(
        temporal_environment.client,
        task_queue="privileged-access-test",
        workflows=[PrivilegedAccessWorkflow],
        activities=activity_set(events),
    ):
        handle = await temporal_environment.client.start_workflow(
            PrivilegedAccessWorkflow.run,
            make_request(),
            id="privileged-access-approved",
            task_queue="privileged-access-test",
        )
        await handle.signal(
            PrivilegedAccessWorkflow.decide,
            ApprovalDecision(approved=True, approver_id="approver-1"),
        )
        result = await handle.result()

    assert result.state == "revoked"
    assert result.approver_id == "approver-1"
    assert result.grant_effect_id == "request-1:grant:v1"
    assert {review["agent_role"] for review in result.advisories} == {
        "least_privilege",
        "security_context",
    }
    assert "grant_activity" in events
    assert "revoke_activity" in events


@pytest.mark.asyncio
async def test_denied_access_is_never_granted(temporal_environment):
    events = []
    async with Worker(
        temporal_environment.client,
        task_queue="privileged-access-denied-test",
        workflows=[PrivilegedAccessWorkflow],
        activities=activity_set(events),
    ):
        handle = await temporal_environment.client.start_workflow(
            PrivilegedAccessWorkflow.run,
            make_request(request_id="request-2"),
            id="privileged-access-denied",
            task_queue="privileged-access-denied-test",
        )
        await handle.signal(
            PrivilegedAccessWorkflow.decide,
            ApprovalDecision(approved=False, approver_id="approver-1"),
        )
        result = await handle.result()

    assert result.state == "denied"
    assert result.denial_reason == "denied_by_approver"
    assert "grant_activity" not in events


def test_approval_signal_contract_excludes_free_text_reason():
    decision = ApprovalDecision(approved=False, approver_id="approver-1")

    assert asdict(decision) == {"approved": False, "approver_id": "approver-1"}


@pytest.mark.asyncio
async def test_unapproved_request_expires(temporal_environment):
    events = []
    async with Worker(
        temporal_environment.client,
        task_queue="privileged-access-expiry-test",
        workflows=[PrivilegedAccessWorkflow],
        activities=activity_set(events),
    ):
        result = await temporal_environment.client.execute_workflow(
            PrivilegedAccessWorkflow.run,
            make_request(request_id="request-3", approval_timeout_seconds=60),
            id="privileged-access-expired",
            task_queue="privileged-access-expiry-test",
            execution_timeout=timedelta(minutes=5),
        )

    assert result.state == "expired"
    assert result.denial_reason == "approval_timeout"
    assert "approval_expired" in events
    assert "grant_activity" not in events


@pytest.mark.asyncio
async def test_advisor_failure_cannot_block_human_approval(temporal_environment):
    events = []
    async with Worker(
        temporal_environment.client,
        task_queue="privileged-access-advisor-failure-test",
        workflows=[PrivilegedAccessWorkflow],
        activities=activity_set(events, failed_advisor="security_context"),
    ):
        handle = await temporal_environment.client.start_workflow(
            PrivilegedAccessWorkflow.run,
            make_request(request_id="request-4"),
            id="privileged-access-advisor-failure",
            task_queue="privileged-access-advisor-failure-test",
        )
        await handle.signal(
            PrivilegedAccessWorkflow.decide,
            ApprovalDecision(approved=True, approver_id="approver-1"),
        )
        result = await handle.result()

    unavailable = next(
        review for review in result.advisories if review["agent_role"] == "security_context"
    )
    assert unavailable["recommendation"] == "inconclusive"
    assert unavailable["enforcing"] is False
    assert result.state == "revoked"
    assert events.count("grant_activity") == 1
    assert events.count("revoke_activity") == 1
