import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from app.services.privileged_access_advisory_service import (
    ADVISORY_POLICY_VERSION,
    ADVISORY_PROMPT_VERSION,
    ADVISORY_SCHEMA_VERSION,
    deterministic_review,
    evidence_digest,
    review_privileged_access,
    validate_agent_output,
    validate_evidence,
)


DATASET = Path(__file__).parents[2] / "evals" / "datasets" / "privileged-access-advisors-golden.v1.json"
ADVISOR_ROLES = ("least_privilege", "security_context")
EVIDENCE_KEYS = {
    "permission_count",
    "permission_risk_levels",
    "role_priority_bucket",
    "scope_type",
    "duration_bucket",
    "target_account_active",
    "strong_auth_configured",
    "justification_length_bucket",
}
NORMALIZED_OUTPUT_KEYS = {
    "schema_version",
    "prompt_version",
    "policy_version",
    "agent_role",
    "recommendation",
    "reason_codes",
    "evidence_refs",
    "provider",
    "model",
    "enforcing",
    "evidence_digest",
}
PROHIBITED_EVIDENCE_FIELDS = (
    "password",
    "access_token",
    "refresh_token",
    "recovery_code",
    "email",
    "name",
    "ip_address",
    "user_agent",
    "justification",
)


def load_dataset() -> dict[str, Any]:
    return json.loads(DATASET.read_text(encoding="utf-8"))


def baseline_evidence() -> dict[str, Any]:
    return deepcopy(load_dataset()["cases"][0]["evidence"])


def assert_versioned_non_enforcing_output(result: dict[str, Any], role: str, evidence: dict[str, Any]) -> None:
    assert result["schema_version"] == ADVISORY_SCHEMA_VERSION
    assert result["prompt_version"] == ADVISORY_PROMPT_VERSION
    assert result["policy_version"] == ADVISORY_POLICY_VERSION
    assert result["agent_role"] == role
    assert result["enforcing"] is False
    assert result["evidence_digest"] == evidence_digest(evidence)


def test_dataset_contract_is_versioned_unique_and_privacy_bounded():
    dataset = load_dataset()

    assert dataset["schema_version"] == ADVISORY_SCHEMA_VERSION
    assert dataset["prompt_version"] == ADVISORY_PROMPT_VERSION
    assert dataset["policy_version"] == ADVISORY_POLICY_VERSION
    assert dataset["cases"]
    assert len({case["id"] for case in dataset["cases"]}) == len(dataset["cases"])

    for case in dataset["cases"]:
        assert set(case) == {"id", "evidence", "expected"}
        assert set(case["evidence"]) == EVIDENCE_KEYS
        assert set(case["expected"]) == set(ADVISOR_ROLES)
        assert validate_evidence(case["evidence"]) == case["evidence"]


def test_golden_advisor_decisions_are_exact_and_repeatable():
    for case in load_dataset()["cases"]:
        evidence = case["evidence"]
        for role in ADVISOR_ROLES:
            first = deterministic_review(role, evidence)
            second = deterministic_review(role, dict(reversed(list(evidence.items()))))
            expected = case["expected"][role]

            assert first == second, case["id"]
            assert {key: first[key] for key in expected} == expected, case["id"]
            assert set(first) == NORMALIZED_OUTPUT_KEYS, case["id"]
            assert_versioned_non_enforcing_output(first, role, evidence)


@pytest.mark.parametrize("field", PROHIBITED_EVIDENCE_FIELDS)
def test_privacy_canary_fields_fail_closed_before_advisor_invocation(field):
    evidence = {**baseline_evidence(), field: f"canary-{field}"}

    with pytest.raises(ValueError, match="Prohibited advisory evidence fields"):
        validate_evidence(evidence)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("scope_type"), "complete bounded schema"),
        (lambda value: value.update(permission_count=True), "Invalid permission_count"),
        (lambda value: value.update(permission_count=1001), "Invalid permission_count"),
        (lambda value: value.update(permission_risk_levels=["unknown"]), "Invalid permission_risk_levels"),
        (lambda value: value.update(scope_type="tenant"), "Invalid scope_type"),
        (lambda value: value.update(duration_bucket="permanent"), "Invalid duration_bucket"),
        (lambda value: value.update(target_account_active=1), "evidence must be boolean"),
    ],
)
def test_input_schema_mutations_fail_closed(mutation, message):
    evidence = baseline_evidence()
    mutation(evidence)

    with pytest.raises(ValueError, match=message):
        validate_evidence(evidence)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ({"reason_codes": [], "evidence_refs": []}, "Invalid advisor recommendation"),
        (
            {"recommendation": "approve", "reason_codes": [], "evidence_refs": []},
            "Invalid advisor recommendation",
        ),
        (
            {"recommendation": "support", "reason_codes": "BOUNDED_SCOPE", "evidence_refs": []},
            "Invalid advisor reason codes",
        ),
        (
            {"recommendation": "support", "reason_codes": ["GRANT_ACCESS"], "evidence_refs": []},
            "Invalid advisor reason codes",
        ),
        (
            {"recommendation": "support", "reason_codes": [], "evidence_refs": "scope_type"},
            "Invalid advisor evidence references",
        ),
        (
            {"recommendation": "support", "reason_codes": [], "evidence_refs": ["password"]},
            "Invalid advisor evidence references",
        ),
    ],
)
def test_malformed_model_outputs_are_rejected(output, message):
    evidence = baseline_evidence()

    with pytest.raises(ValueError, match=message):
        validate_agent_output("least_privilege", evidence, output)


def test_model_output_is_normalized_and_cannot_claim_enforcement():
    evidence = baseline_evidence()
    result = validate_agent_output(
        "least_privilege",
        evidence,
        {
            "recommendation": "support",
            "reason_codes": ["BOUNDED_SCOPE"],
            "evidence_refs": ["scope_type"],
            "enforcing": True,
            "authorization_decision": "grant",
            "raw_explanation": "untrusted free text",
        },
    )

    assert set(result) == NORMALIZED_OUTPUT_KEYS
    assert result["provider"] == "ollama_local"
    assert result["recommendation"] == "support"
    assert result["reason_codes"] == ["BOUNDED_SCOPE"]
    assert result["evidence_refs"] == ["scope_type"]
    assert_versioned_non_enforcing_output(result, "least_privilege", evidence)


class StubAdvisor:
    response: dict[str, Any] | None = None
    failure: Exception | None = None
    received_evidence: dict[str, Any] | None = None
    close_calls = 0

    def __init__(self, **_kwargs):
        pass

    async def review_privileged_access(self, _role, evidence):
        type(self).received_evidence = evidence
        if self.failure is not None:
            raise self.failure
        return deepcopy(self.response)

    async def close(self):
        type(self).close_calls += 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "fallback_reason"),
    [
        (ValueError("invalid model schema"), "invalid_output"),
        (RuntimeError("model unavailable"), "unavailable"),
    ],
)
async def test_model_failures_fall_back_to_exact_deterministic_advice(monkeypatch, failure, fallback_reason):
    evidence = baseline_evidence()
    expected = deterministic_review("least_privilege", evidence)
    monkeypatch.setattr(StubAdvisor, "failure", failure)
    monkeypatch.setattr(StubAdvisor, "response", None)
    monkeypatch.setattr(StubAdvisor, "received_evidence", None)
    monkeypatch.setattr(StubAdvisor, "close_calls", 0)
    monkeypatch.setattr(
        "app.services.privileged_access_advisory_service.settings.PRIVILEGED_ACCESS_AGENT_AI_ENABLED",
        True,
    )
    monkeypatch.setattr(
        "app.services.privileged_access_advisory_service.OllamaAIService",
        StubAdvisor,
    )

    result = await review_privileged_access("least_privilege", evidence)

    assert StubAdvisor.received_evidence == evidence
    assert StubAdvisor.close_calls == 1
    assert result["fallback_reason"] == fallback_reason
    assert result["provider"] == "deterministic_fallback"
    assert result["recommendation"] == expected["recommendation"]
    assert result["evidence_refs"] == expected["evidence_refs"]
    assert result["reason_codes"] == [*expected["reason_codes"], "ADVISOR_UNAVAILABLE"]
    assert_versioned_non_enforcing_output(result, "least_privilege", evidence)


@pytest.mark.asyncio
async def test_disabled_advisor_never_constructs_or_calls_a_model(monkeypatch):
    evidence = baseline_evidence()

    def fail_if_constructed(**_kwargs):
        raise AssertionError("disabled advisor constructed a model client")

    monkeypatch.setattr(
        "app.services.privileged_access_advisory_service.settings.PRIVILEGED_ACCESS_AGENT_AI_ENABLED",
        False,
    )
    monkeypatch.setattr(
        "app.services.privileged_access_advisory_service.OllamaAIService",
        fail_if_constructed,
    )

    result = await review_privileged_access("security_context", evidence)

    assert result["fallback_reason"] == "disabled"
    assert result["provider"] == "deterministic_fallback"
    assert_versioned_non_enforcing_output(result, "security_context", evidence)
