"""Versioned deterministic risk policies and immutable decision audit records."""

import uuid

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.sql import func

from app.database.base import Base


class RiskPolicy(Base):
    __tablename__ = "risk_policies"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_risk_policy_name_version"),
        CheckConstraint("status IN ('draft', 'active', 'retired')", name="ck_risk_policy_status"),
        CheckConstraint("version > 0", name="ck_risk_policy_version"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="draft", index=True)
    policy_document = Column(JSON, nullable=False)
    checksum = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)


class RiskDecision(Base):
    __tablename__ = "risk_decisions"
    __table_args__ = (
        CheckConstraint("outcome IN ('allow', 'step_up', 'deny', 'review')", name="ck_risk_decision_outcome"),
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_decision_score"),
        UniqueConstraint("correlation_id", name="uq_risk_decision_correlation_id"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    correlation_id = Column(String(100), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    context = Column(String(50), nullable=False, index=True)
    policy_id = Column(String, ForeignKey("risk_policies.id", ondelete="RESTRICT"), nullable=False, index=True)
    policy_name = Column(String(100), nullable=False)
    policy_version = Column(Integer, nullable=False)
    policy_checksum = Column(String(64), nullable=False)
    outcome = Column(String(16), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    input_features = Column(JSON, nullable=False)
    contributions = Column(JSON, nullable=False)
    reason_codes = Column(JSON, nullable=False)
    ai_shadow = Column(JSON, nullable=True)
    ai_shadow_enabled = Column(Boolean, nullable=False, default=False)
    enforced_by = Column(String(40), nullable=False, default="deterministic_policy")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
