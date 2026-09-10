"""Domain models for Tripwire core concepts.

These are pure domain value objects, not database models.
Database persistence belongs to Phase A3.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import ActionClass, Decision, RiskBand


class ActionProposal(BaseModel):
    """Action proposal submitted by an agent.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §7
    """
    principal_id: str
    session_id: str
    agent_id: str
    action: str
    resource: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class ActionDecision(BaseModel):
    """Security decision result for an action proposal.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §7
    """
    action_id: str
    decision: Decision
    trajectory_score: float
    risk_band: RiskBand
    reversibility: ActionClass
    reason: str


class TrajectoryEvent(BaseModel):
    """Single event in a trajectory sequence.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §7
    """
    step: int
    action: str
    resource: str
    reversibility: ActionClass
    trajectory_score: float
    risk_band: RiskBand
    decision: Decision


class AuditEvent(BaseModel):
    """Audit record for a security-relevant action.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §7
    """
    action_id: str
    principal_id: str
    session_id: str
    agent_id: str
    action: str
    resource: str
    reversibility: ActionClass
    trajectory_score: float
    risk_band: RiskBand
    decision: Decision
    reason: str
    timestamp: datetime
