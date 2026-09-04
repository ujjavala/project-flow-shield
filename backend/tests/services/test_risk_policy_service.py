"""Focused tests for deterministic, explainable, and shadow-only risk decisions."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.risk_policy import RiskDecision, RiskPolicy
from app.services.ollama_ai_service import OllamaAIService
from app.services.risk_policy_service import (
    DEFAULT_POLICY_DOCUMENT,
    RiskFeatures,
    canonical_policy_checksum,
    evaluate_and_persist,
    evaluate_policy,
    source_ip_is_blocked,
    validate_policy_document,
)


def test_same_features_and_policy_always_produce_the_same_explanation():
    features = RiskFeatures(
        known_network=False,
        known_device=False,
        recent_failed_attempts=1,
    )

    first = evaluate_policy(features, DEFAULT_POLICY_DOCUMENT)
    second = evaluate_policy(features, DEFAULT_POLICY_DOCUMENT)

    assert first == second
    assert first.outcome == "step_up"
    assert first.score == 38
    assert first.reason_codes == ["NEW_NETWORK", "NEW_DEVICE", "RECENT_FAILED_ATTEMPTS"]
    assert sum(item["points"] for item in first.contributions) == first.score


def test_configured_high_risk_feature_is_a_hard_deny():
    result = evaluate_policy(
        RiskFeatures(source_ip_blocked=True, known_network=False, known_device=False),
        DEFAULT_POLICY_DOCUMENT,
    )

    assert result.outcome == "deny"
    assert result.score == 100
    assert result.reason_codes[0] == "SOURCE_NETWORK_BLOCKED"


def test_policy_exposes_all_four_explicit_outcomes():
    allow = evaluate_policy(RiskFeatures(), DEFAULT_POLICY_DOCUMENT)
    step_up = evaluate_policy(RiskFeatures(impossible_travel=True), DEFAULT_POLICY_DOCUMENT)
    review = evaluate_policy(
        RiskFeatures(impossible_travel=True, known_network=False, known_device=False),
        DEFAULT_POLICY_DOCUMENT,
    )
    deny = evaluate_policy(RiskFeatures(credential_compromise_suspected=True), DEFAULT_POLICY_DOCUMENT)

    assert [allow.outcome, step_up.outcome, review.outcome, deny.outcome] == [
        "allow",
        "step_up",
        "review",
        "deny",
    ]


def test_invalid_threshold_order_is_rejected():
    invalid = {**DEFAULT_POLICY_DOCUMENT, "score_thresholds": {"step_up": 60, "review": 40, "deny": 80}}
    with pytest.raises(ValueError, match="step_up < review < deny"):
        validate_policy_document(invalid)


def test_fail_closed_feature_cannot_be_downgraded_to_allow():
    invalid = {
        **DEFAULT_POLICY_DOCUMENT,
        "hard_rules": [
            {
                "feature": "source_ip_blocked",
                "outcome": "allow",
                "reason_code": "UNSAFE_DOWNGRADE",
            }
        ],
    }
    with pytest.raises(ValueError, match="must have a deny hard rule"):
        validate_policy_document(invalid)


def test_fail_closed_deny_wins_regardless_of_rule_order():
    policy = {
        **DEFAULT_POLICY_DOCUMENT,
        "hard_rules": [
            {"feature": "known_network", "outcome": "allow", "reason_code": "KNOWN_NETWORK"},
            *DEFAULT_POLICY_DOCUMENT["hard_rules"],
        ],
    }

    result = evaluate_policy(
        RiskFeatures(source_ip_blocked=True, known_network=True),
        policy,
    )

    assert result.outcome == "deny"
    assert result.reason_codes[0] == "SOURCE_NETWORK_BLOCKED"


@pytest.mark.parametrize(
    "document,error",
    [
        ({**DEFAULT_POLICY_DOCUMENT, "unexpected": True}, "Unknown policy fields"),
        (
            {**DEFAULT_POLICY_DOCUMENT, "weights": {**DEFAULT_POLICY_DOCUMENT["weights"], "unknown": 10}},
            "Policy weights",
        ),
        ({**DEFAULT_POLICY_DOCUMENT, "caps": {"recent_failed_attempts": True}}, "cap must be an integer"),
        ({**DEFAULT_POLICY_DOCUMENT, "caps": {"recent_failed_attempts": 101}}, "cap must be an integer"),
    ],
)
def test_policy_rejects_ambiguous_or_unbounded_fields(document, error):
    with pytest.raises(ValueError, match=error):
        validate_policy_document(document)


def test_blocked_cidr_matching_is_deterministic_and_invalid_source_fails_closed():
    assert source_ip_is_blocked("203.0.113.42", ["203.0.113.0/24"])
    assert not source_ip_is_blocked("198.51.100.42", ["203.0.113.0/24"])
    assert source_ip_is_blocked("not-an-ip", [])


@pytest.mark.asyncio
async def test_ai_shadow_advice_is_persisted_but_cannot_change_allow_outcome():
    policy = RiskPolicy(
        id="policy-1",
        name="authentication-risk",
        version=7,
        status="active",
        policy_document=DEFAULT_POLICY_DOCUMENT,
        checksum=canonical_policy_checksum(DEFAULT_POLICY_DOCUMENT),
    )
    query_result = MagicMock()
    query_result.scalar_one_or_none.return_value = policy
    db = AsyncMock()
    db.add = MagicMock()
    db.execute.return_value = query_result

    async def disagreeing_advisor(features, deterministic):
        return {
            "status": "available",
            "advisory_outcome": "deny",
            "advisory_score": 99,
            "reason_codes": ["MODEL_DISAGREEMENT"],
        }

    with patch("app.services.risk_policy_service.settings.RISK_POLICY_AI_SHADOW_ENABLED", True):
        result = await evaluate_and_persist(
            db,
            correlation_id="correlation-1",
            context="test",
            user_id="user-1",
            features=RiskFeatures(),
            ai_advisor=disagreeing_advisor,
        )

    persisted = db.add.call_args.args[0]
    assert isinstance(persisted, RiskDecision)
    assert persisted.outcome == "allow"
    assert persisted.enforced_by == "deterministic_policy"
    assert persisted.ai_shadow["advisory_outcome"] == "deny"
    assert persisted.ai_shadow["non_enforcing"] is True
    assert result.outcome == "allow"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_ollama_shadow_advisor_parses_only_bounded_advice_without_authority_leakage():
    advisor = OllamaAIService()
    advisor._make_request = AsyncMock(
        return_value='{"advisory_outcome":"review","advisory_score":85,"reason_codes":["UNUSUAL_PATTERN"]}'
    )

    result = await advisor.advise_auth_risk(
        RiskFeatures(known_device=False).sanitized(),
        SimpleNamespace(outcome="authority-canary", score=987654),
    )

    assert result["advisory_outcome"] == "review"
    assert result["advisory_score"] == 85
    assert result["reason_codes"] == ["UNUSUAL_PATTERN"]
    prompt = advisor._make_request.await_args.args[0]
    assert "authority-canary" not in prompt
    assert "987654" not in prompt


@pytest.mark.asyncio
async def test_ollama_shadow_advisor_rejects_out_of_range_or_extra_output():
    advisor = OllamaAIService()
    advisor._make_request = AsyncMock(
        return_value='{"advisory_outcome":"review","advisory_score":145,"reason_codes":[],"override":true}'
    )

    with pytest.raises(ValueError):
        await advisor.advise_auth_risk(
            RiskFeatures().sanitized(),
            SimpleNamespace(outcome="allow", score=0),
        )
