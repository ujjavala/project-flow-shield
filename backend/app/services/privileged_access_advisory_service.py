"""Bounded, non-enforcing advisors for privileged-access review.

Only allowlisted, non-secret features may cross the model boundary. Advisor output
is evidence for a human reviewer and is never an authorization decision.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Literal

from prometheus_client import Counter, Histogram

from app.config import settings
from app.services.ollama_ai_service import OllamaAIService

AgentRole = Literal["least_privilege", "security_context"]
Recommendation = Literal["support", "concern", "inconclusive"]
ADVISORY_SCHEMA_VERSION = "1"
ADVISORY_PROMPT_VERSION = "privileged-access-v1"
ADVISORY_POLICY_VERSION = "privileged-access-policy-v1"

_ADVISOR_CALLS = Counter(
    "flowshield_privileged_access_advisor_calls_total",
    "Privileged-access advisor outcomes without request or identity labels.",
    ["agent_role", "provider", "status", "prompt_version", "schema_version"],
)
_ADVISOR_LATENCY = Histogram(
    "flowshield_privileged_access_advisor_duration_seconds",
    "Privileged-access advisor latency without request or identity labels.",
    ["agent_role", "provider"],
)

_ALLOWED_REASON_CODES = {
    "HIGH_RISK_PERMISSION",
    "LONG_DURATION",
    "NO_SCOPE",
    "NO_STRONG_AUTH",
    "ACCOUNT_INACTIVE",
    "BOUNDED_SCOPE",
    "SHORT_DURATION",
    "STRONG_AUTH_PRESENT",
    "ADVISOR_UNAVAILABLE",
    "INVALID_ADVISOR_OUTPUT",
}
_ALLOWED_EVIDENCE_KEYS = {
    "permission_count",
    "permission_risk_levels",
    "role_priority_bucket",
    "scope_type",
    "duration_bucket",
    "target_account_active",
    "strong_auth_configured",
    "justification_length_bucket",
}


def evidence_digest(evidence: dict[str, Any]) -> str:
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Reject rather than redact unexpected data before an advisor sees it."""
    unknown = set(evidence) - _ALLOWED_EVIDENCE_KEYS
    if unknown:
        raise ValueError(f"Prohibited advisory evidence fields: {sorted(unknown)}")
    if set(evidence) != _ALLOWED_EVIDENCE_KEYS:
        raise ValueError("Advisory evidence must contain the complete bounded schema")
    if isinstance(evidence["permission_count"], bool) or not isinstance(evidence["permission_count"], int) or not 0 <= evidence["permission_count"] <= 1000:
        raise ValueError("Invalid permission_count")
    risk_levels = evidence["permission_risk_levels"]
    if not isinstance(risk_levels, list) or len(risk_levels) > 4 or any(
        value not in {"low", "medium", "high", "critical"} for value in risk_levels
    ):
        raise ValueError("Invalid permission_risk_levels")
    if evidence["role_priority_bucket"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("Invalid role_priority_bucket")
    if evidence["scope_type"] not in {"global", "organization", "department", "team", "project", "resource"}:
        raise ValueError("Invalid scope_type")
    if evidence["duration_bucket"] not in {"short", "medium", "long"}:
        raise ValueError("Invalid duration_bucket")
    if evidence["justification_length_bucket"] not in {"brief", "normal", "long"}:
        raise ValueError("Invalid justification_length_bucket")
    if not isinstance(evidence["target_account_active"], bool) or not isinstance(evidence["strong_auth_configured"], bool):
        raise ValueError("Advisor account evidence must be boolean")
    return evidence


def deterministic_review(agent_role: AgentRole, evidence: dict[str, Any]) -> dict[str, Any]:
    evidence = validate_evidence(evidence)
    reasons: list[str] = []
    refs: list[str] = []

    if agent_role == "least_privilege":
        risk_levels = set(evidence.get("permission_risk_levels", []))
        if risk_levels & {"high", "critical"}:
            reasons.append("HIGH_RISK_PERMISSION")
            refs.append("permission_risk_levels")
        if evidence.get("duration_bucket") == "long":
            reasons.append("LONG_DURATION")
            refs.append("duration_bucket")
        if evidence.get("scope_type") == "global":
            reasons.append("NO_SCOPE")
            refs.append("scope_type")
        if not reasons:
            reasons.extend(["BOUNDED_SCOPE", "SHORT_DURATION"])
            refs.extend(["scope_type", "duration_bucket"])
    else:
        if not evidence.get("target_account_active", False):
            reasons.append("ACCOUNT_INACTIVE")
            refs.append("target_account_active")
        if not evidence.get("strong_auth_configured", False):
            reasons.append("NO_STRONG_AUTH")
            refs.append("strong_auth_configured")
        if not reasons:
            reasons.append("STRONG_AUTH_PRESENT")
            refs.append("strong_auth_configured")

    recommendation: Recommendation = "concern" if any(
        code in {"HIGH_RISK_PERMISSION", "LONG_DURATION", "NO_SCOPE", "NO_STRONG_AUTH", "ACCOUNT_INACTIVE"}
        for code in reasons
    ) else "support"
    return {
        "schema_version": ADVISORY_SCHEMA_VERSION,
        "prompt_version": ADVISORY_PROMPT_VERSION,
        "policy_version": ADVISORY_POLICY_VERSION,
        "agent_role": agent_role,
        "recommendation": recommendation,
        "reason_codes": reasons,
        "evidence_refs": refs,
        "provider": "deterministic_fallback",
        "model": None,
        "enforcing": False,
        "evidence_digest": evidence_digest(evidence),
    }


def validate_agent_output(agent_role: AgentRole, evidence: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    recommendation = output.get("recommendation")
    if recommendation not in {"support", "concern", "inconclusive"}:
        raise ValueError("Invalid advisor recommendation")

    reason_codes = output.get("reason_codes", [])
    evidence_refs = output.get("evidence_refs", [])
    if not isinstance(reason_codes, list) or len(reason_codes) > 8 or not all(
        isinstance(code, str) and code in _ALLOWED_REASON_CODES for code in reason_codes
    ):
        raise ValueError("Invalid advisor reason codes")
    if not isinstance(evidence_refs, list) or len(evidence_refs) > 8 or not all(
        isinstance(ref, str) and ref in evidence for ref in evidence_refs
    ):
        raise ValueError("Invalid advisor evidence references")

    return {
        "schema_version": ADVISORY_SCHEMA_VERSION,
        "prompt_version": ADVISORY_PROMPT_VERSION,
        "policy_version": ADVISORY_POLICY_VERSION,
        "agent_role": agent_role,
        "recommendation": recommendation,
        "reason_codes": reason_codes[:8],
        "evidence_refs": evidence_refs[:8],
        "provider": "ollama_local",
        "model": settings.RISK_POLICY_AI_MODEL,
        "enforcing": False,
        "evidence_digest": evidence_digest(evidence),
    }


async def review_privileged_access(agent_role: AgentRole, evidence: dict[str, Any]) -> dict[str, Any]:
    """Run one bounded advisor, falling back to deterministic review."""
    evidence = validate_evidence(evidence)
    if not settings.PRIVILEGED_ACCESS_AGENT_AI_ENABLED:
        result = deterministic_review(agent_role, evidence)
        result["fallback_reason"] = "disabled"
        _ADVISOR_CALLS.labels(
            agent_role, "deterministic_fallback", "disabled", ADVISORY_PROMPT_VERSION, ADVISORY_SCHEMA_VERSION
        ).inc()
        return result

    started = time.monotonic()
    service = OllamaAIService(
        host=settings.RISK_POLICY_AI_HOST,
        port=settings.RISK_POLICY_AI_PORT,
        model=settings.RISK_POLICY_AI_MODEL,
    )
    try:
        output = await service.review_privileged_access(agent_role, evidence)
        result = validate_agent_output(agent_role, evidence, output)
        result["fallback_reason"] = None
        _ADVISOR_CALLS.labels(
            agent_role, "ollama_local", "available", ADVISORY_PROMPT_VERSION, ADVISORY_SCHEMA_VERSION
        ).inc()
        return result
    except ValueError:
        result = deterministic_review(agent_role, evidence)
        result["reason_codes"] = [*result["reason_codes"], "ADVISOR_UNAVAILABLE"][:8]
        result["fallback_reason"] = "invalid_output"
        _ADVISOR_CALLS.labels(
            agent_role, "deterministic_fallback", "invalid_output", ADVISORY_PROMPT_VERSION, ADVISORY_SCHEMA_VERSION
        ).inc()
        return result
    except Exception:
        result = deterministic_review(agent_role, evidence)
        result["reason_codes"] = [*result["reason_codes"], "ADVISOR_UNAVAILABLE"][:8]
        result["fallback_reason"] = "unavailable"
        _ADVISOR_CALLS.labels(
            agent_role, "deterministic_fallback", "unavailable", ADVISORY_PROMPT_VERSION, ADVISORY_SCHEMA_VERSION
        ).inc()
        return result
    finally:
        _ADVISOR_LATENCY.labels(agent_role, "ollama_local").observe(time.monotonic() - started)
        await service.close()
