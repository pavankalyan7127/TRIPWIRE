"""Session management API routes.

Implements POST /api/v1/sessions for creating new agent sessions.
Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.1
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.db.session import get_db
from app.schemas.requests import SessionCreateRequest
from app.schemas.responses import SessionCreateResponse
from app.security.decision_engine import classify_risk_band

router = APIRouter()


@router.post("/sessions", response_model=SessionCreateResponse, status_code=status.HTTP_201_CREATED)
def create_session(
    request: SessionCreateRequest,
    db: Session = Depends(get_db),
) -> SessionCreateResponse:
    """Create a new agent session.

    A new session is associated with a principal and an agent.
    The session inherits the principal's historical trajectory state from persistence.

    Args:
        request: Session creation request containing principal_id and agent_id.
        db: Database session (dependency-injected).

    Returns:
        SessionCreateResponse with session_id, principal_id, agent_id, trajectory_score, risk_band.

    Raises:
        HTTPException: If session creation fails.
    """
    principal_repo = PrincipalRepository(db)
    session_repo = SessionRepository(db)

    # Get or create principal (establishes principal if first-time)
    principal = principal_repo.get_or_create(request.principal_id)

    # Retrieve persisted principal trajectory state
    trajectory_score = principal.trajectory_score
    risk_band = classify_risk_band(trajectory_score)

    # Generate unique session ID
    session_id = f"session_{uuid.uuid4().hex[:12]}"

    # Create new session associated with principal and agent
    session_model = session_repo.create(
        session_id=session_id,
        principal_id=request.principal_id,
        agent_id=request.agent_id,
        trajectory_score=trajectory_score,
    )

    return SessionCreateResponse(
        session_id=session_model.id,
        principal_id=session_model.principal_id,
        agent_id=session_model.agent_id,
        trajectory_score=trajectory_score,
        risk_band=risk_band,
    )
