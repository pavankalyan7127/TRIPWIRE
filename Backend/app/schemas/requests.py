"""Pydantic request schemas matching the contract specification."""

from typing import Any

from pydantic import BaseModel, Field, field_validator


class SessionCreateRequest(BaseModel):
    """Request to create a new session.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.1
    """
    principal_id: str = Field(..., description="Unique identifier of the user/principal")
    agent_id: str = Field(..., description="Unique identifier of the agent")


class ActionProposalRequest(BaseModel):
    """Request to propose an action for security evaluation.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.2, §7
    This is the primary security boundary request.
    It deliberately does NOT contain any decision or authorization fields.
    """
    principal_id: str = Field(..., description="Unique identifier of the user/principal")
    session_id: str = Field(..., description="Session identifier")
    agent_id: str = Field(..., description="Agent identifier")
    action: str = Field(..., description="Tool/action name being proposed")
    resource: str = Field(..., description="Resource target for the action")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")


class ConfirmationRequest(BaseModel):
    """Request to confirm an action requiring human approval.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §4
    """
    approved_by: str = Field(..., description="Identifier of the approver (e.g. admin_001)")

    @field_validator("approved_by")
    @classmethod
    def validate_approved_by(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("approved_by must be a non-empty string.")
        return v.strip()

