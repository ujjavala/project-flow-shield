"""History-safe contracts for durable privileged-access operations.

Only stable identifiers and non-secret business metadata belong in these payloads.
Credentials, tokens, evidence contents, and notification bodies must stay outside
Temporal history and be resolved by activities from durable storage.
"""

from dataclasses import dataclass
from typing import Any, Optional


PRIVILEGED_ACCESS_TRANSITIONS = {
    "initializing": frozenset({"invalid", "pending_approval"}),
    "pending_approval": frozenset({"expired", "denied", "active"}),
    "active": frozenset({"revoking"}),
    "revoking": frozenset({"revoked"}),
}


def is_valid_privileged_access_transition(current: str, next_state: str) -> bool:
    """Validate the state policy used by the durable privileged-access workflow."""
    return next_state in PRIVILEGED_ACCESS_TRANSITIONS.get(current, frozenset())


@dataclass(frozen=True)
class PrivilegedAccessRequest:
    request_id: str
    requester_id: str
    target_user_id: str
    role_id: str
    scope_id: Optional[str]
    duration_seconds: int
    approval_timeout_seconds: int


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    approver_id: str


@dataclass(frozen=True)
class PrivilegedAccessStatus:
    request_id: str
    state: str
    approver_id: Optional[str] = None
    grant_effect_id: Optional[str] = None
    denial_reason: Optional[str] = None
    advisories: tuple[dict[str, Any], ...] = ()