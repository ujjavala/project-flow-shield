import pytest

from app.services.privileged_access_advisory_service import (
    deterministic_review,
    review_privileged_access,
    validate_agent_output,
    validate_evidence,
)


def evidence(**overrides):
    value = {
        "permission_count": 2,
        "permission_risk_levels": ["low"],
        "role_priority_bucket": "medium",
        "scope_type": "team",
        "duration_bucket": "short",
        "target_account_active": True,
        "strong_auth_configured": True,
        "justification_length_bucket": "normal",
    }
    value.update(overrides)
    return value


def test_least_privilege_advisor_is_bounded_and_non_enforcing():
    result = deterministic_review("least_privilege", evidence())

    assert result["recommendation"] == "support"
    assert result["enforcing"] is False
    assert result["provider"] == "deterministic_fallback"
    assert len(result["evidence_digest"]) == 64
    assert result["schema_version"] == "1"
    assert result["prompt_version"] == "privileged-access-v1"
    assert result["policy_version"] == "privileged-access-policy-v1"


def test_security_context_flags_missing_strong_auth():
    result = deterministic_review(
        "security_context",
        evidence(strong_auth_configured=False),
    )

    assert result["recommendation"] == "concern"
    assert "NO_STRONG_AUTH" in result["reason_codes"]


def test_unexpected_sensitive_evidence_is_rejected():
    with pytest.raises(ValueError, match="Prohibited advisory evidence"):
        validate_evidence({**evidence(), "access_token": "canary"})


def test_model_output_cannot_reference_unknown_evidence_or_reason_codes():
    with pytest.raises(ValueError, match="Invalid advisor reason codes"):
        validate_agent_output(
            "least_privilege",
            evidence(),
            {
                "recommendation": "support",
                "reason_codes": ["GRANT_ACCESS_NOW"],
                "evidence_refs": ["scope_type"],
            },
        )


def test_evidence_rejects_type_confusion_and_unbounded_values():
    with pytest.raises(ValueError, match="Invalid permission_count"):
        validate_evidence(evidence(permission_count=True))
    with pytest.raises(ValueError, match="Invalid permission_risk_levels"):
        validate_evidence(evidence(permission_risk_levels=["low"] * 5))
    with pytest.raises(ValueError, match="complete bounded schema"):
        incomplete = evidence()
        incomplete.pop("scope_type")
        validate_evidence(incomplete)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("role_priority_bucket", "extreme", "Invalid role_priority_bucket"),
        ("scope_type", "internet", "Invalid scope_type"),
        ("duration_bucket", "forever", "Invalid duration_bucket"),
        ("justification_length_bucket", "unbounded", "Invalid justification_length_bucket"),
        ("target_account_active", "yes", "evidence must be boolean"),
        ("strong_auth_configured", 1, "evidence must be boolean"),
    ],
)
def test_evidence_rejects_invalid_bounded_fields(field, value, message):
    with pytest.raises(ValueError, match=message):
        validate_evidence(evidence(**{field: value}))


@pytest.mark.asyncio
async def test_disabled_ai_uses_versioned_deterministic_fallback(monkeypatch):
    monkeypatch.setattr(
        "app.services.privileged_access_advisory_service.settings.PRIVILEGED_ACCESS_AGENT_AI_ENABLED",
        False,
    )

    result = await review_privileged_access("least_privilege", evidence())

    assert result["provider"] == "deterministic_fallback"
    assert result["fallback_reason"] == "disabled"
    assert result["enforcing"] is False


def test_model_output_rejects_values_hidden_after_truncation_boundary():
    with pytest.raises(ValueError, match="Invalid advisor reason codes"):
        validate_agent_output(
            "least_privilege",
            evidence(),
            {
                "recommendation": "support",
                "reason_codes": ["BOUNDED_SCOPE"] * 8 + ["UNREVIEWED_VALUE"],
                "evidence_refs": ["scope_type"],
            },
        )

    with pytest.raises(ValueError, match="Invalid advisor evidence references"):
        validate_agent_output(
            "least_privilege",
            evidence(),
            {
                "recommendation": "support",
                "reason_codes": ["BOUNDED_SCOPE"],
                "evidence_refs": ["password"],
            },
        )
