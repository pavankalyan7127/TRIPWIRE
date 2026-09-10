"""Pydantic response schemas matching the contract specification."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models.enums import ActionClass, Decision, RiskBand


class SessionCreateResponse(BaseModel):
    """Response returned when a session is created.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.1
    """
    session_id: str
    principal_id: str
    agent_id: str
    trajectory_score: float = 0.0
    risk_band: RiskBand = RiskBand.LOW


class ActionDecisionResponse(BaseModel):
    """Response returned when an action proposal is evaluated.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.2, §7
    """
    action_id: str
    decision: Decision
    trajectory_score: float
    risk_band: RiskBand
    reversibility: ActionClass
    reason: str


class ConfirmationResponse(BaseModel):
    """Response returned when an action confirmation is processed.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §4
    """
    action_id: str
    decision: Decision
    approved_by: str
    execution_status: str = Field(
        ...,
        description="Execution outcome: EXECUTED or NOT_EXECUTED",
    )


class TrajectoryEventSchema(BaseModel):
    """Single event in a session's trajectory.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §5, §7
    """
    step: int
    action: str
    resource: str
    reversibility: ActionClass
    trajectory_score: float
    risk_band: RiskBand
    decision: Decision


class TrajectoryResponse(BaseModel):
    """Response returned by GET /api/v1/sessions/{session_id}/trajectory.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §5
    """
    session_id: str
    principal_id: str
    trajectory_score: float
    risk_band: RiskBand
    events: list[TrajectoryEventSchema] = Field(default_factory=list)


class AuditEventSchema(BaseModel):
    """Single audit event in audit history.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §6, §7
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
    execution_status: str = Field(default="NOT_EXECUTED", description="Execution outcome: NOT_EXECUTED or EXECUTED")
    approved_by: Optional[str] = Field(default=None, description="Identifier of the approver if confirmed")
    executed_at: Optional[datetime] = Field(default=None, description="Timestamp of execution if executed")
    parameters: Optional[dict[str, Any]] = Field(default=None, description="Action parameters dictionary")


class AuditResponse(BaseModel):
    """Response returned by GET /api/v1/audit/{session_id}.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §6
    """
    session_id: str
    events: list[AuditEventSchema] = Field(default_factory=list)
