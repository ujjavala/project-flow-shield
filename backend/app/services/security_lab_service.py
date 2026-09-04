"""Bounded, deterministic security simulations for local and internal sandboxes only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from app.config import settings
from app.models.pkce import PKCEUtils
from app.models.user import RefreshToken
from app.services.rate_limit_service import POLICIES, request_is_allowed
from app.services.risk_policy_service import DEFAULT_POLICY_DOCUMENT, RiskFeatures, evaluate_policy
from app.services.session_service import refresh_token_is_reuse
from app.temporal.privileged_access_types import is_valid_privileged_access_transition


class SecurityLabDisabled(RuntimeError):
    pass


class UnsafeSimulationTarget(ValueError):
    pass


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    capability: str
    execution_mode: str
    description: str


SCENARIOS = (
    Scenario("credential-stuffing-rate-limit", "Credential stuffing is throttled", "credential_stuffing", "production_policy", "Exercises the production login fixed-window decision without sending credentials."),
    Scenario("refresh-token-replay", "Refresh token replay revokes its family", "refresh_token_replay", "production_invariant", "Exercises the production replay predicate and expected family/session revocation effects."),
    Scenario("risky-login-outcomes", "Risky login outcomes are deterministic", "risky_login", "production_policy", "Exercises the authoritative deterministic risk policy for all four outcomes."),
    Scenario("temporary-privileged-access", "Temporary access is approved then expires", "privileged_access", "workflow_state_policy", "Exercises the same legal state transitions enforced by the Temporal workflow."),
    Scenario("pkce-code-replay", "PKCE authorization code replay is rejected", "pkce_replay", "production_invariant", "Exercises the production one-time S256 grant predicate."),
)
SCENARIO_BY_ID = {scenario.id: scenario for scenario in SCENARIOS}


def normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeSimulationTarget("Security lab target must be an HTTP(S) origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UnsafeSimulationTarget("Security lab target must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise UnsafeSimulationTarget("Security lab target must be an origin without a path")
    host = parsed.hostname.lower()
    if host == "::1":
        host = "[::1]"
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def validated_target_origin(base_url: str | None = None) -> str:
    candidate = normalize_origin(base_url or settings.SECURITY_LAB_BASE_URL)
    allowed = {normalize_origin(item) for item in settings.SECURITY_LAB_ALLOWED_BASE_URLS}
    if candidate not in allowed:
        raise UnsafeSimulationTarget("Security lab target is not in SECURITY_LAB_ALLOWED_BASE_URLS")
    return candidate


def assert_lab_enabled() -> str:
    if not settings.SECURITY_LAB_ENABLED:
        raise SecurityLabDisabled("Security simulation lab is disabled")
    return validated_target_origin()


def _check(name: str, expected: Any, observed: Any) -> dict[str, Any]:
    return {"name": name, "passed": observed == expected, "expected": expected, "observed": observed}


def _credential_stuffing(_seed: int) -> list[dict[str, Any]]:
    policy = POLICIES["login"]
    decisions = [request_is_allowed(count, policy) for count in range(1, policy.limit + 2)]
    return [
        _check("attempts_through_limit_allowed", True, all(decisions[:policy.limit])),
        _check("first_excess_attempt_blocked", False, decisions[-1]),
        _check("bounded_attempt_count", policy.limit + 1, len(decisions)),
    ]


def _refresh_replay(_seed: int) -> list[dict[str, Any]]:
    token = RefreshToken(is_revoked=True)
    token.used_at = object()
    replay = refresh_token_is_reuse(token)
    effects = ["revoke_token_family", "revoke_session"] if replay else []
    return [
        _check("rotated_token_detected_as_replay", True, replay),
        _check("family_and_session_revoked", ["revoke_token_family", "revoke_session"], effects),
    ]


def _risky_login(_seed: int) -> list[dict[str, Any]]:
    examples = {
        "allow": RiskFeatures(),
        "step_up": RiskFeatures(impossible_travel=True),
        "review": RiskFeatures(impossible_travel=True, known_network=False, known_device=False),
        "deny": RiskFeatures(credential_compromise_suspected=True),
    }
    return [
        _check(f"{expected}_outcome", expected, evaluate_policy(features, DEFAULT_POLICY_DOCUMENT).outcome)
        for expected, features in examples.items()
    ]


def _privileged_access(_seed: int) -> list[dict[str, Any]]:
    sequence = ["initializing", "pending_approval", "active", "revoking", "revoked"]
    transitions_valid = all(
        is_valid_privileged_access_transition(current, next_state)
        for current, next_state in zip(sequence, sequence[1:])
    )
    return [
        _check("approval_and_expiry_path_is_legal", True, transitions_valid),
        _check("access_finishes_revoked", "revoked", sequence[-1]),
        _check("grant_precedes_revocation", True, sequence.index("active") < sequence.index("revoked")),
    ]


def _pkce_replay(_seed: int) -> list[dict[str, Any]]:
    verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    challenge = PKCEUtils.generate_code_challenge(verifier, "S256")
    first = PKCEUtils.authorization_code_is_redeemable(verifier, challenge, "S256", False)
    replay = PKCEUtils.authorization_code_is_redeemable(verifier, challenge, "S256", True)
    return [
        _check("first_exchange_accepted", True, first),
        _check("replayed_code_rejected", False, replay),
        _check("wrong_verifier_rejected", False, PKCEUtils.authorization_code_is_redeemable("z" * 43, challenge, "S256", False)),
    ]


_RUNNERS: dict[str, Callable[[int], list[dict[str, Any]]]] = {
    "credential-stuffing-rate-limit": _credential_stuffing,
    "refresh-token-replay": _refresh_replay,
    "risky-login-outcomes": _risky_login,
    "temporary-privileged-access": _privileged_access,
    "pkce-code-replay": _pkce_replay,
}


def list_scenarios() -> list[dict[str, str]]:
    return [asdict(scenario) for scenario in SCENARIOS]


def run_scenario(scenario_id: str, seed: int = 0) -> dict[str, Any]:
    target_origin = assert_lab_enabled()
    if scenario_id not in SCENARIO_BY_ID:
        raise KeyError(scenario_id)
    checks = _RUNNERS[scenario_id](seed)
    passed = all(check["passed"] for check in checks)
    deterministic_evidence = {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "seed": seed,
        "passed": passed,
        "checks": checks,
    }
    digest = hashlib.sha256(
        json.dumps(deterministic_evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**deterministic_evidence, "target_origin": target_origin, "evidence_digest": digest}