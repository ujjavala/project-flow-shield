"""Immutable, machine-readable evidence from explicitly enabled security simulations."""

import uuid

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.sql import func

from app.database.base import Base


class SecuritySimulationRun(Base):
    __tablename__ = "security_simulation_runs"
    __table_args__ = (
        CheckConstraint("status IN ('passed', 'failed')", name="ck_security_simulation_status"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_id = Column(String(80), nullable=False, index=True)
    status = Column(String(16), nullable=False, index=True)
    seed = Column(Integer, nullable=False)
    target_origin = Column(String(255), nullable=False)
    evidence = Column(JSON, nullable=False)
    evidence_digest = Column(String(64), nullable=False)
    requested_by = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)