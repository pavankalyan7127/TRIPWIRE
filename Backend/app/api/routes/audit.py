"""Audit and trajectory API routes.

Implements:
- GET /api/v1/audit/{session_id} for retrieving audit events
- GET /api/v1/sessions/{session_id}/trajectory for retrieving trajectory data

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §5, §6
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.repositories.audit import AuditRepository
from app.db.repositories.session import SessionRepository
from app.db.session import get_db
from app.models.enums import ActionClass, Decision, RiskBand
from app.schemas.responses import (
    AuditEventSchema,
    AuditResponse,
    TrajectoryEventSchema,
    TrajectoryResponse,
)
from app.security.decision_engine import classify_risk_band

router = APIRouter()


@router.get("/audit/{session_id}", response_model=AuditResponse)
def get_audit(
    session_id: str,
    db: Session = Depends(get_db),
) -> AuditResponse:
    """Retrieve audit events for a session.

    Returns all security evaluation events for the specified session.

    Args:
        session_id: Session identifier.
        db: Database session (dependency-injected).

    Returns:
        AuditResponse containing list of audit events.

    Raises:
        HTTPException: If session not found.
    """
    session_repo = SessionRepository(db)
    audit_repo = AuditRepository(db)

    # Verify session exists
    session_model = session_repo.get_by_id(session_id)
    if session_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    # Retrieve audit events for this session
    audit_events = audit_repo.get_by_session_id(session_id)

    # Convert to response schema
    event_schemas = [
        AuditEventSchema(
            action_id=event.action_id,
            principal_id=event.principal_id,
            session_id=event.session_id,
            agent_id=event.agent_id,
            action=event.action,
            resource=event.resource,
            reversibility=ActionClass(event.reversibility),
            trajectory_score=event.trajectory_score,
            risk_band=RiskBand(event.risk_band),
            decision=Decision(event.decision),
            reason=event.reason,
            timestamp=event.timestamp,
            execution_status=event.execution_status,
            approved_by=event.approved_by,
            executed_at=event.executed_at,
            parameters=event.parameters_dict,
        )
        for event in audit_events
    ]

    return AuditResponse(
        session_id=session_id,
        events=event_schemas,
    )


@router.get("/sessions/{session_id}/trajectory", response_model=TrajectoryResponse)
def get_trajectory(
    session_id: str,
    db: Session = Depends(get_db),
) -> TrajectoryResponse:
    """Retrieve trajectory information for a session.

    Returns the current trajectory score, risk band, and sequence of evaluated actions.
    This is a read-only GET endpoint that does NOT mutate trajectory state.

    Args:
        session_id: Session identifier.
        db: Database session (dependency-injected).

    Returns:
        TrajectoryResponse containing trajectory score, risk band, and event sequence.

    Raises:
        HTTPException: If session not found.
    """
    session_repo = SessionRepository(db)
    audit_repo = AuditRepository(db)

    # Verify session exists
    session_model = session_repo.get_by_id(session_id)
    if session_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    # Get current trajectory score from session
    trajectory_score = session_model.trajectory_score
    risk_band = classify_risk_band(trajectory_score)

    # Retrieve audit events to construct trajectory event sequence
    audit_events = audit_repo.get_by_session_id(session_id)

    # Convert audit events to trajectory events
    trajectory_events = [
        TrajectoryEventSchema(
            step=idx + 1,
            action=event.action,
            resource=event.resource,
            reversibility=ActionClass(event.reversibility),
            trajectory_score=event.trajectory_score,
            risk_band=RiskBand(event.risk_band),
            decision=Decision(event.decision),
        )
        for idx, event in enumerate(audit_events)
    ]

    return TrajectoryResponse(
        session_id=session_id,
        principal_id=session_model.principal_id,
        trajectory_score=trajectory_score,
        risk_band=risk_band,
        events=trajectory_events,
    )
