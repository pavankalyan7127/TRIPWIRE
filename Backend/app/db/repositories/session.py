"""Repository for Session persistence operations."""

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import SessionModel


class SessionRepository:
    """Repository for session persistence operations.

    Handles CRUD operations for sessions.
    Does NOT implement trajectory calculations.
    """

    def __init__(self, db: Session):
        """Initialize repository with a database session.

        Args:
            db: SQLAlchemy session for database operations.
        """
        self.db = db

    def create(
        self,
        session_id: str,
        principal_id: str,
        agent_id: str,
        trajectory_score: float = 0.0,
    ) -> SessionModel:
        """Create a new session.

        Args:
            session_id: Unique identifier for the session.
            principal_id: ID of the principal owning the session.
            agent_id: ID of the agent.
            trajectory_score: Initial trajectory score (default 0.0).

        Returns:
            The created SessionModel instance.
        """
        session = SessionModel(
            id=session_id,
            principal_id=principal_id,
            agent_id=agent_id,
            trajectory_score=trajectory_score,
            started_at=datetime.utcnow(),
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def get_by_id(self, session_id: str) -> Optional[SessionModel]:
        """Retrieve a session by ID.

        Args:
            session_id: The session's unique identifier.

        Returns:
            SessionModel if found, None otherwise.
        """
        return self.db.query(SessionModel).filter(SessionModel.id == session_id).first()

    def update_trajectory_score(self, session_id: str, trajectory_score: float) -> Optional[SessionModel]:
        """Update session's trajectory score.

        Args:
            session_id: The session to update.
            trajectory_score: New trajectory score.

        Returns:
            Updated SessionModel if found, None otherwise.
        """
        session = self.get_by_id(session_id)
        if session is None:
            return None

        session.trajectory_score = trajectory_score
        self.db.commit()
        self.db.refresh(session)
        return session

    def end_session(self, session_id: str) -> Optional[SessionModel]:
        """Mark a session as ended.

        Args:
            session_id: The session to end.

        Returns:
            Updated SessionModel if found, None otherwise.
        """
        session = self.get_by_id(session_id)
        if session is None:
            return None

        session.ended_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(session)
        return session
