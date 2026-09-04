"""Safety and behavioural checks for the deterministic security lab."""

from unittest.mock import patch

import pytest

from app.services.security_lab_service import (
    SCENARIOS,
    SecurityLabDisabled,
    UnsafeSimulationTarget,
    run_scenario,
    validated_target_origin,
)


def enabled_settings():
    return patch.multiple(
        "app.services.security_lab_service.settings",
        SECURITY_LAB_ENABLED=True,
        SECURITY_LAB_BASE_URL="http://localhost:8000",
        SECURITY_LAB_ALLOWED_BASE_URLS=["http://localhost:8000", "http://backend:8000"],
    )


def test_lab_is_disabled_by_default():
    with patch("app.services.security_lab_service.settings.SECURITY_LAB_ENABLED", False):
        with pytest.raises(SecurityLabDisabled, match="disabled"):
            run_scenario("risky-login-outcomes")


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://localhost:9000",
        "http://localhost:8000/user/login",
        "http://user:password@localhost:8000",
        "file:///etc/passwd",
    ],
)
def test_arbitrary_or_malformed_targets_are_rejected(target):
    with patch(
        "app.services.security_lab_service.settings.SECURITY_LAB_ALLOWED_BASE_URLS",
        ["http://localhost:8000"],
    ):
        with pytest.raises(UnsafeSimulationTarget):
            validated_target_origin(target)


def test_explicit_internal_allowlist_entry_is_accepted():
    with patch(
        "app.services.security_lab_service.settings.SECURITY_LAB_ALLOWED_BASE_URLS",
        ["http://backend:8000"],
    ):
        assert validated_target_origin("http://backend:8000/") == "http://backend:8000"


@pytest.mark.parametrize("scenario_id", [scenario.id for scenario in SCENARIOS])
def test_each_documented_scenario_returns_passing_machine_readable_evidence(scenario_id):
    with enabled_settings():
        result = run_scenario(scenario_id, seed=42)

    assert result["passed"] is True
    assert result["scenario_id"] == scenario_id
    assert result["seed"] == 42
    assert len(result["evidence_digest"]) == 64
    assert result["checks"]
    assert all(check["passed"] for check in result["checks"])


@pytest.mark.parametrize("scenario_id", [scenario.id for scenario in SCENARIOS])
def test_same_seed_produces_identical_evidence(scenario_id):
    with enabled_settings():
        first = run_scenario(scenario_id, seed=7)
        second = run_scenario(scenario_id, seed=7)

    assert first == second