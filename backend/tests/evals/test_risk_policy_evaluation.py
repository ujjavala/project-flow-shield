import itertools
import json
from pathlib import Path

from app.services.risk_policy_service import (
    DEFAULT_POLICY_DOCUMENT,
    RiskFeatures,
    evaluate_policy,
)


DATASET = Path(__file__).parents[2] / "evals" / "datasets" / "risk-policy-golden.v1.json"
SEVERITY = {"allow": 0, "step_up": 1, "review": 2, "deny": 3}


def test_golden_risk_policy_cases_match_exactly():
    cases = json.loads(DATASET.read_text(encoding="utf-8"))["cases"]

    for case in cases:
        decision = evaluate_policy(RiskFeatures(**case["features"]), DEFAULT_POLICY_DOCUMENT)
        expected = case["expected"]
        assert decision.outcome == expected["outcome"], case["id"]
        assert decision.score == expected["score"], case["id"]
        assert decision.reason_codes[0] == expected["leading_reason"], case["id"]


def test_boolean_risk_signals_are_monotonic():
    risk_signals = (
        "source_ip_blocked",
        "account_disabled",
        "credential_compromise_suspected",
        "impossible_travel",
    )
    for values in itertools.product((False, True), repeat=len(risk_signals)):
        baseline_features = dict(zip(risk_signals, values))
        baseline = evaluate_policy(RiskFeatures(**baseline_features), DEFAULT_POLICY_DOCUMENT)
        for signal in risk_signals:
            elevated_features = {**baseline_features, signal: True}
            elevated = evaluate_policy(RiskFeatures(**elevated_features), DEFAULT_POLICY_DOCUMENT)
            assert elevated.score >= baseline.score
            assert SEVERITY[elevated.outcome] >= SEVERITY[baseline.outcome]


def test_fail_closed_signals_always_deny_across_context_combinations():
    for blocked, compromised, known_network, known_device in itertools.product((False, True), repeat=4):
        if not (blocked or compromised):
            continue
        decision = evaluate_policy(
            RiskFeatures(
                source_ip_blocked=blocked,
                credential_compromise_suspected=compromised,
                known_network=known_network,
                known_device=known_device,
            ),
            DEFAULT_POLICY_DOCUMENT,
        )
        assert decision.outcome == "deny"
