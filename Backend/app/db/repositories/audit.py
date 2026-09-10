"""Repository for AuditEvent persistence operations."""

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.db.models import AuditEventModel


class AuditRepository:
    """Repository for audit event persistence operations.

    Handles creation, execution status updates, and retrieval of audit events.
    Does NOT implement audit policy or API logic.
    """

    def __init__(self, db: Session):
        """Initialize repository with a database session.

        Args:
            db: SQLAlchemy session for database operations.
        """
        self.db = db

    def create(
        self,
        action_id: str,
        principal_id: str,
        session_id: str,
        agent_id: str,
        action: str,
        resource: str,
        reversibility: str,
        trajectory_score: float,
        risk_band: str,
        decision: str,
        reason: str,
        parameters: Optional[dict[str, Any] | str] = None,
        execution_status: str = "NOT_EXECUTED",
        approved_by: Optional[str] = None,
        executed_at: Optional[datetime] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditEventModel:
        """Create a new audit event.

        Args:
            action_id: Identifier of the evaluated action.
            principal_id: ID of the principal.
            session_id: ID of the session.
            agent_id: ID of the agent.
            action: Tool/action name.
            resource: Resource target.
            reversibility: Action class (READ, WRITE, DESTRUCTIVE).
            trajectory_score: Trajectory score at evaluation.
            risk_band: Risk band (LOW, MEDIUM, HIGH).
            decision: Security decision (ALLOW, CONFIRM, HARD_CONFIRM, BLOCK).
            reason: Explanation of the decision.
            parameters: Action parameters dictionary or JSON string.
            execution_status: Execution outcome (NOT_EXECUTED, EXECUTED).
            approved_by: Human approver ID if confirmed.
            executed_at: Execution timestamp if executed.
            timestamp: Event timestamp (defaults to utcnow).

        Returns:
            The created AuditEventModel instance.
        """
        params_str: Optional[str] = None
        if isinstance(parameters, dict):
            params_str = json.dumps(parameters)
        elif isinstance(parameters, str):
            params_str = parameters

        event = AuditEventModel(
            action_id=action_id,
            principal_id=principal_id,
            session_id=session_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            reversibility=reversibility,
            trajectory_score=trajectory_score,
            risk_band=risk_band,
            decision=decision,
            reason=reason,
            parameters=params_str,
            execution_status=execution_status,
            approved_by=approved_by,
            executed_at=executed_at,
            timestamp=timestamp or datetime.utcnow(),
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def update_execution(
        self,
        action_id: str,
        execution_status: str,
        approved_by: Optional[str] = None,
        executed_at: Optional[datetime] = None,
    ) -> Optional[AuditEventModel]:
        """Update the execution status and approver of an existing audit event.

        Args:
            action_id: The action ID to update.
            execution_status: New execution status (EXECUTED or NOT_EXECUTED).
            approved_by: ID of the human approver.
            executed_at: Timestamp when execution occurred.

        Returns:
            Updated AuditEventModel if found, None otherwise.
        """
        event = self.get_by_action_id(action_id)
        if event is None:
            return None

        event.execution_status = execution_status
        if approved_by is not None:
            event.approved_by = approved_by
        if executed_at is not None:
            event.executed_at = executed_at

        self.db.commit()
        self.db.refresh(event)
        return event

    def get_by_session_id(self, session_id: str) -> list[AuditEventModel]:
        """Retrieve all audit events for a session, ordered chronologically with deterministic tie-breaking.

        Args:
            session_id: The session ID to query.

        Returns:
            List of AuditEventModel instances.
        """
        if not session_id or not session_id.strip():
            return []
        return (
            self.db.query(AuditEventModel)
            .filter(AuditEventModel.session_id == session_id.strip())
            .order_by(AuditEventModel.timestamp.asc(), AuditEventModel.id.asc())
            .all()
        )

    def get_by_action_id(self, action_id: str) -> Optional[AuditEventModel]:
        """Retrieve a specific audit event by action ID.

        Args:
            action_id: The action ID to query.

        Returns:
            AuditEventModel if found, None otherwise.
        """
        return self.db.query(AuditEventModel).filter(AuditEventModel.action_id == action_id).first()
