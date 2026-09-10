"""SQLAlchemy ORM models for Tripwire database tables.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §21
"""

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class PrincipalModel(Base):
    """Principal (user) with cross-session trajectory state.

    Contract: §21 principals table, §17 cross-session state
    """
    __tablename__ = "principals"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    scope: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string or text
    trajectory_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    scope_footprint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of resources
    max_destructiveness: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    action_counts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON dict
    last_session_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationship to sessions
    sessions: Mapped[list["SessionModel"]] = relationship("SessionModel", back_populates="principal")

    def __repr__(self) -> str:
        return f"<PrincipalModel(id={self.id}, trajectory_score={self.trajectory_score}, risk={self.risk_band})>"

    @property
    def risk_band(self) -> str:
        """Calculate risk band from trajectory score (for display only)."""
        if self.trajectory_score < 0.35:
            return "LOW"
        elif self.trajectory_score <= 0.65:
            return "MEDIUM"
        else:
            return "HIGH"

    @property
    def scope_footprint_list(self) -> list[str]:
        """Parse scope_footprint JSON string to list."""
        if not self.scope_footprint:
            return []
        try:
            return json.loads(self.scope_footprint)
        except (json.JSONDecodeError, TypeError):
            return []

    @scope_footprint_list.setter
    def scope_footprint_list(self, value: list[str]) -> None:
        """Serialize scope_footprint list to JSON string."""
        self.scope_footprint = json.dumps(value) if value else None

    @property
    def action_counts_dict(self) -> dict[str, int]:
        """Parse action_counts JSON string to dict."""
        if not self.action_counts:
            return {}
        try:
            return json.loads(self.action_counts)
        except (json.JSONDecodeError, TypeError):
            return {}

    @action_counts_dict.setter
    def action_counts_dict(self, value: dict[str, int]) -> None:
        """Serialize action_counts dict to JSON string."""
        self.action_counts = json.dumps(value) if value else None


class SessionModel(Base):
    """Session representing a bounded agent interaction.

    Contract: §21 sessions table
    """
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(255), ForeignKey("principals.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    trajectory_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Relationship to principal
    principal: Mapped["PrincipalModel"] = relationship("PrincipalModel", back_populates="sessions")

    # Relationship to audit events
    audit_events: Mapped[list["AuditEventModel"]] = relationship("AuditEventModel", back_populates="session")

    def __repr__(self) -> str:
        return f"<SessionModel(id={self.id}, principal_id={self.principal_id}, agent_id={self.agent_id})>"

    @property
    def risk_band(self) -> str:
        """Calculate risk band from trajectory score (for display only)."""
        if self.trajectory_score < 0.35:
            return "LOW"
        elif self.trajectory_score <= 0.65:
            return "MEDIUM"
        else:
            return "HIGH"


class AuditEventModel(Base):
    """Audit event for a security-relevant action.

    Contract: §21 audit_events table, §7 AuditEvent schema
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), ForeignKey("sessions.id"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str] = mapped_column(String(500), nullable=False)
    reversibility: Mapped[str] = mapped_column(String(50), nullable=False)  # READ, WRITE, DESTRUCTIVE
    trajectory_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(50), nullable=False)  # LOW, MEDIUM, HIGH
    decision: Mapped[str] = mapped_column(String(50), nullable=False)  # ALLOW, CONFIRM, HARD_CONFIRM, BLOCK
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string of parameters
    execution_status: Mapped[str] = mapped_column(String(50), default="NOT_EXECUTED", nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationship to session
    session: Mapped["SessionModel"] = relationship("SessionModel", back_populates="audit_events")

    def __repr__(self) -> str:
        return f"<AuditEventModel(action_id={self.action_id}, decision={self.decision}, status={self.execution_status})>"

    @property
    def parameters_dict(self) -> dict[str, Any]:
        """Parse parameters JSON string to dictionary."""
        if not self.parameters:
            return {}
        try:
            return json.loads(self.parameters)
        except (json.JSONDecodeError, TypeError):
            return {}

    @parameters_dict.setter
    def parameters_dict(self, value: dict[str, Any]) -> None:
        """Serialize parameters dictionary to JSON string."""
        self.parameters = json.dumps(value) if value is not None else None
