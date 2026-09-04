"""Explainable deterministic authentication risk decisions.

The policy result is always authoritative. Optional AI output is captured only as
non-enforcing shadow advice and is never read when choosing an outcome.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.auth_security import AuthSession
from app.models.risk_policy import RiskDecision, RiskPolicy

logger = logging.getLogger(__name__)

OUTCOMES = ("allow", "step_up", "review", "deny")
POLICY_KEYS = {"score_thresholds", "weights", "caps", "hard_rules", "fail_closed_features"}
BOOLEAN_FEATURES = {
    "source_ip_blocked",
    "known_network",
    "known_device",
    "user_agent_present",
    "account_disabled",
    "credential_compromise_suspected",
    "impossible_travel",
}
WEIGHT_KEYS = {
    "source_ip_blocked",
    "credential_compromise_suspected",
    "account_disabled",
    "new_network",
    "new_device",
    "missing_user_agent",
    "impossible_travel",
    "recent_failed_attempt",
    "behavioral_risk",
}
DEFAULT_POLICY_NAME = "authentication-risk"
DEFAULT_POLICY_DOCUMENT: dict[str, Any] = {
    "score_thresholds": {"step_up": 35, "review": 60, "deny": 80},
    "weights": {
        "source_ip_blocked": 100,
        "credential_compromise_suspected": 100,
        "account_disabled": 100,
        "new_network": 15,
        "new_device": 15,
        "missing_user_agent": 10,
        "impossible_travel": 35,
        "recent_failed_attempt": 8,
        "behavioral_risk": 20,
    },
    "caps": {"recent_failed_attempts": 4},
    "hard_rules": [
        {
            "feature": "source_ip_blocked",
            "outcome": "deny",
            "reason_code": "SOURCE_NETWORK_BLOCKED",
        },
        {
            "feature": "credential_compromise_suspected",
            "outcome": "deny",
            "reason_code": "CREDENTIAL_COMPROMISE_SUSPECTED",
        },
        {
            "feature": "account_disabled",
            "outcome": "deny",
            "reason_code": "ACCOUNT_DISABLED",
        },
    ],
    "fail_closed_features": ["source_ip_blocked", "credential_compromise_suspected"],
}


class RiskPolicyError(RuntimeError):
    """Raised when a risk decision cannot be made or durably audited."""


@dataclass(frozen=True)
class RiskFeatures:
    source_ip_blocked: bool = False
    known_network: bool = True
    known_device: bool = True
    user_agent_present: bool = True
    account_disabled: bool = False
    credential_compromise_suspected: bool = False
    impossible_travel: bool = False
    recent_failed_attempts: int = 0
    behavioral_risk_score: float = 0.0

    def sanitized(self) -> dict[str, bool | int | float]:
        """Return persistence/AI-safe features; never include credentials, tokens, raw IPs, or user agents."""
        return {
            "source_ip_blocked": bool(self.source_ip_blocked),
            "known_network": bool(self.known_network),
            "known_device": bool(self.known_device),
            "user_agent_present": bool(self.user_agent_present),
            "account_disabled": bool(self.account_disabled),
            "credential_compromise_suspected": bool(self.credential_compromise_suspected),
            "impossible_travel": bool(self.impossible_travel),
            "recent_failed_attempts": max(0, int(self.recent_failed_attempts)),
            "behavioral_risk_score": max(0.0, min(1.0, float(self.behavioral_risk_score))),
        }


@dataclass(frozen=True)
class DeterministicDecision:
    outcome: str
    score: int
    contributions: list[dict[str, Any]]
    reason_codes: list[str]


@dataclass(frozen=True)
class PersistedRiskDecision:
    id: str
    correlation_id: str
    outcome: str
    score: int
    policy_name: str
    policy_version: int
    contributions: list[dict[str, Any]]
    reason_codes: list[str]
    ai_shadow: dict[str, Any] | None


def canonical_policy_checksum(document: dict[str, Any]) -> str:
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def validate_policy_document(document: dict[str, Any]) -> None:
    required = {"score_thresholds", "weights", "hard_rules", "fail_closed_features"}
    if not isinstance(document, dict) or not required.issubset(document):
        raise ValueError(f"Policy document must contain: {', '.join(sorted(required))}")
    unknown_keys = set(document) - POLICY_KEYS
    if unknown_keys:
        raise ValueError(f"Unknown policy fields: {', '.join(sorted(unknown_keys))}")

    thresholds = document["score_thresholds"]
    if not isinstance(thresholds, dict):
        raise ValueError("score_thresholds must be an object")
    values = [thresholds.get(name) for name in ("step_up", "review", "deny")]
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise ValueError("Policy thresholds must be integers")
    if not (0 <= values[0] < values[1] < values[2] <= 100):
        raise ValueError("Policy thresholds must satisfy 0 <= step_up < review < deny <= 100")

    if not isinstance(document["weights"], dict) or set(document["weights"]) - WEIGHT_KEYS or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 100
        for value in document["weights"].values()
    ):
        raise ValueError("Policy weights must be integers between 0 and 100")

    caps = document.get("caps", {})
    if set(caps) - {"recent_failed_attempts"}:
        raise ValueError("Unknown policy caps")
    failed_attempt_cap = caps.get("recent_failed_attempts", 4)
    if isinstance(failed_attempt_cap, bool) or not isinstance(failed_attempt_cap, int) or not 0 <= failed_attempt_cap <= 100:
        raise ValueError("recent_failed_attempts cap must be an integer between 0 and 100")

    if not isinstance(document["hard_rules"], list):
        raise ValueError("hard_rules must be a list")
    for rule in document["hard_rules"]:
        if (
            not isinstance(rule, dict)
            or set(rule) != {"feature", "outcome", "reason_code"}
            or rule.get("outcome") not in OUTCOMES
            or rule.get("feature") not in BOOLEAN_FEATURES
            or not isinstance(rule.get("reason_code"), str)
            or not rule["reason_code"]
            or len(rule["reason_code"]) > 80
        ):
            raise ValueError("Each hard rule requires feature, reason_code, and a valid outcome")

    if not isinstance(document["fail_closed_features"], list) or any(
        feature not in BOOLEAN_FEATURES for feature in document["fail_closed_features"]
    ):
        raise ValueError("fail_closed_features must be a list")
    deny_rules = {
        rule["feature"] for rule in document["hard_rules"] if rule.get("outcome") == "deny"
    }
    missing_deny_rules = set(document["fail_closed_features"]) - deny_rules
    if missing_deny_rules:
        raise ValueError("Every fail_closed_feature must have a deny hard rule")


def _score_contributions(
    values: dict[str, bool | int | float], policy_document: dict[str, Any]
) -> list[dict[str, Any]]:
    weights = policy_document["weights"]
    contributions: list[dict[str, Any]] = []

    def contribute(feature: str, value: Any, points: int, reason_code: str) -> None:
        if points > 0:
            contributions.append(
                {"feature": feature, "value": value, "points": points, "reason_code": reason_code}
            )

    contribute("source_ip_blocked", values["source_ip_blocked"], weights.get("source_ip_blocked", 0) if values["source_ip_blocked"] else 0, "SOURCE_NETWORK_BLOCKED")
    contribute("credential_compromise_suspected", values["credential_compromise_suspected"], weights.get("credential_compromise_suspected", 0) if values["credential_compromise_suspected"] else 0, "CREDENTIAL_COMPROMISE_SUSPECTED")
    contribute("account_disabled", values["account_disabled"], weights.get("account_disabled", 0) if values["account_disabled"] else 0, "ACCOUNT_DISABLED")
    contribute("known_network", values["known_network"], weights.get("new_network", 0) if not values["known_network"] else 0, "NEW_NETWORK")
    contribute("known_device", values["known_device"], weights.get("new_device", 0) if not values["known_device"] else 0, "NEW_DEVICE")
    contribute("user_agent_present", values["user_agent_present"], weights.get("missing_user_agent", 0) if not values["user_agent_present"] else 0, "MISSING_USER_AGENT")
    contribute("impossible_travel", values["impossible_travel"], weights.get("impossible_travel", 0) if values["impossible_travel"] else 0, "IMPOSSIBLE_TRAVEL")

    failed_attempt_cap = int(policy_document.get("caps", {}).get("recent_failed_attempts", 4))
    failed_attempts = min(values["recent_failed_attempts"], max(0, failed_attempt_cap))
    contribute("recent_failed_attempts", failed_attempts, failed_attempts * weights.get("recent_failed_attempt", 0), "RECENT_FAILED_ATTEMPTS")

    behavioral_points = round(values["behavioral_risk_score"] * weights.get("behavioral_risk", 0))
    contribute("behavioral_risk_score", values["behavioral_risk_score"], behavioral_points, "BEHAVIORAL_RISK_SIGNAL")
    return contributions


def _select_outcome(values: dict[str, Any], score: int, policy_document: dict[str, Any]) -> tuple[str, list[str]]:
    fail_closed = set(policy_document["fail_closed_features"])
    for rule in policy_document["hard_rules"]:
        if rule["feature"] in fail_closed and values.get(rule["feature"]) is True:
            return "deny", [rule["reason_code"]]
    for rule in policy_document["hard_rules"]:
        if values.get(rule["feature"]) is True:
            return rule["outcome"], [rule["reason_code"]]
    thresholds = policy_document["score_thresholds"]
    if score >= thresholds["deny"]:
        return "deny", []
    if score >= thresholds["review"]:
        return "review", []
    if score >= thresholds["step_up"]:
        return "step_up", []
    return "allow", []


def evaluate_policy(features: RiskFeatures, policy_document: dict[str, Any]) -> DeterministicDecision:
    """Pure, deterministic policy evaluation suitable for repeatable unit tests."""
    validate_policy_document(policy_document)
    values = features.sanitized()
    contributions = _score_contributions(values, policy_document)
    score = min(100, sum(item["points"] for item in contributions))
    outcome, reason_codes = _select_outcome(values, score, policy_document)

    reason_codes.extend(
        item["reason_code"] for item in contributions if item["reason_code"] not in reason_codes
    )
    if not reason_codes:
        reason_codes.append("BASELINE_RISK_ACCEPTABLE")
    return DeterministicDecision(outcome, score, contributions, reason_codes)


def source_ip_is_blocked(ip_address: str | None, blocked_cidrs: list[str] | None = None) -> bool:
    if not ip_address:
        return False
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return True
    for cidr in blocked_cidrs if blocked_cidrs is not None else settings.RISK_POLICY_BLOCKED_CIDRS:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.error("Ignoring invalid configured risk-policy CIDR")
    return False


async def build_login_features(db: AsyncSession, user_id: str, ip_address: str | None, user_agent: str | None) -> RiskFeatures:
    """Build bounded login features from durable sessions without exposing raw context."""
    known_network = True
    known_device = True
    if ip_address:
        result = await db.execute(
            select(AuthSession.id).where(AuthSession.user_id == user_id, AuthSession.ip_address == ip_address).limit(1)
        )
        known_network = result.scalar_one_or_none() is not None
    if user_agent:
        result = await db.execute(
            select(AuthSession.id).where(AuthSession.user_id == user_id, AuthSession.user_agent == user_agent).limit(1)
        )
        known_device = result.scalar_one_or_none() is not None
    return RiskFeatures(
        source_ip_blocked=source_ip_is_blocked(ip_address),
        known_network=known_network,
        known_device=known_device,
        user_agent_present=bool(user_agent),
    )


async def ensure_default_policy(db: AsyncSession) -> RiskPolicy:
    result = await db.execute(
        select(RiskPolicy).where(RiskPolicy.status == "active").order_by(RiskPolicy.activated_at.desc()).limit(1)
    )
    active = result.scalar_one_or_none()
    if active is not None:
        validate_policy_document(active.policy_document)
        if active.checksum != canonical_policy_checksum(active.policy_document):
            raise RiskPolicyError("Active risk policy integrity check failed")
        return active

    policy = RiskPolicy(
        name=DEFAULT_POLICY_NAME,
        version=1,
        status="active",
        description="Default explainable authentication risk policy",
        policy_document=DEFAULT_POLICY_DOCUMENT,
        checksum=canonical_policy_checksum(DEFAULT_POLICY_DOCUMENT),
        activated_at=datetime.now(timezone.utc),
    )
    db.add(policy)
    try:
        await db.commit()
        await db.refresh(policy)
        return policy
    except IntegrityError:
        await db.rollback()
        result = await db.execute(
            select(RiskPolicy).where(RiskPolicy.status == "active").order_by(RiskPolicy.activated_at.desc()).limit(1)
        )
        active = result.scalar_one_or_none()
        if active is None:
            raise RiskPolicyError("No active risk policy is available")
        return active


async def activate_policy(db: AsyncSession, policy: RiskPolicy) -> RiskPolicy:
    validate_policy_document(policy.policy_document)
    policy.checksum = canonical_policy_checksum(policy.policy_document)
    now = datetime.now(timezone.utc)
    await db.execute(
        update(RiskPolicy).where(RiskPolicy.status == "active", RiskPolicy.id != policy.id).values(status="retired")
    )
    policy.status = "active"
    policy.activated_at = now
    await db.commit()
    await db.refresh(policy)
    return policy


async def ollama_shadow_advisor(
    sanitized_features: dict[str, Any], deterministic_decision: DeterministicDecision
) -> dict[str, Any]:
    """Invoke the existing local AI service with sanitized, non-secret inputs only."""
    from app.services.ollama_ai_service import OllamaAIService

    advisor = OllamaAIService(
        host=settings.RISK_POLICY_AI_HOST,
        port=settings.RISK_POLICY_AI_PORT,
        model=settings.RISK_POLICY_AI_MODEL,
    )
    try:
        return await advisor.advise_auth_risk(sanitized_features, deterministic_decision)
    finally:
        await advisor.close()


async def evaluate_and_persist(
    db: AsyncSession,
    *,
    correlation_id: str,
    context: str,
    features: RiskFeatures,
    user_id: str | None = None,
    ai_advisor: Callable[[dict[str, Any], DeterministicDecision], Awaitable[dict[str, Any]]] | None = None,
) -> PersistedRiskDecision:
    """Evaluate the active policy and atomically persist its audit evidence."""
    try:
        policy = await ensure_default_policy(db)
        deterministic = evaluate_policy(features, policy.policy_document)
        ai_shadow: dict[str, Any] | None = None
        if settings.RISK_POLICY_AI_SHADOW_ENABLED and ai_advisor is not None:
            try:
                advice = await asyncio.wait_for(
                    ai_advisor(features.sanitized(), deterministic),
                    timeout=settings.RISK_POLICY_AI_SHADOW_TIMEOUT_SECONDS,
                )
                ai_shadow = {**advice, "non_enforcing": True}
            except Exception:
                logger.exception("Risk AI shadow advisor failed")
                ai_shadow = {"status": "unavailable", "non_enforcing": True}

        record = RiskDecision(
            correlation_id=correlation_id,
            user_id=user_id,
            context=context,
            policy_id=policy.id,
            policy_name=policy.name,
            policy_version=policy.version,
            policy_checksum=policy.checksum,
            outcome=deterministic.outcome,
            score=deterministic.score,
            input_features=features.sanitized(),
            contributions=deterministic.contributions,
            reason_codes=deterministic.reason_codes,
            ai_shadow=ai_shadow,
            ai_shadow_enabled=settings.RISK_POLICY_AI_SHADOW_ENABLED,
            enforced_by="deterministic_policy",
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        return PersistedRiskDecision(
            id=record.id,
            correlation_id=record.correlation_id,
            outcome=record.outcome,
            score=record.score,
            policy_name=record.policy_name,
            policy_version=record.policy_version,
            contributions=record.contributions,
            reason_codes=record.reason_codes,
            ai_shadow=record.ai_shadow,
        )
    except RiskPolicyError:
        raise
    except Exception as exc:
        await db.rollback()
        raise RiskPolicyError("Risk decision could not be evaluated and audited") from exc
