"""Repository for Principal persistence operations."""

from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import PrincipalModel


class PrincipalRepository:
    """Repository for principal persistence operations.

    Handles CRUD operations for principals and their cross-session state.
    Does NOT implement authorization or trajectory logic.
    """

    def __init__(self, db: Session):
        """Initialize repository with a database session.

        Args:
            db: SQLAlchemy session for database operations.
        """
        self.db = db

    def create(self, principal_id: str, role: Optional[str] = None, scope: Optional[str] = None) -> PrincipalModel:
        """Create a new principal.

        Args:
            principal_id: Unique identifier for the principal.
            role: Optional role designation.
            scope: Optional scope/permissions (text or JSON string).

        Returns:
            The created PrincipalModel instance.
        """
        principal = PrincipalModel(
            id=principal_id,
            role=role,
            scope=scope,
            trajectory_score=0.0,
            max_destructiveness=0.0,
        )
        self.db.add(principal)
        self.db.commit()
        self.db.refresh(principal)
        return principal

    def get_by_id(self, principal_id: str) -> Optional[PrincipalModel]:
        """Retrieve a principal by ID.

        Args:
            principal_id: The principal's unique identifier.

        Returns:
            PrincipalModel if found, None otherwise.
        """
        return self.db.query(PrincipalModel).filter(PrincipalModel.id == principal_id).first()

    def get_or_create(self, principal_id: str, role: Optional[str] = None, scope: Optional[str] = None) -> PrincipalModel:
        """Get existing principal or create if not exists.

        Args:
            principal_id: Unique identifier for the principal.
            role: Optional role (only used if creating).
            scope: Optional scope (only used if creating).

        Returns:
            The PrincipalModel instance (existing or newly created).
        """
        principal = self.get_by_id(principal_id)
        if principal is None:
            principal = self.create(principal_id, role, scope)
        return principal

    def update_trajectory_state(
        self,
        principal_id: str,
        trajectory_score: Optional[float] = None,
        scope_footprint: Optional[list[str]] = None,
        max_destructiveness: Optional[float] = None,
        action_counts: Optional[dict[str, int]] = None,
    ) -> Optional[PrincipalModel]:
        """Update principal's persistent trajectory state.

        Args:
            principal_id: The principal to update.
            trajectory_score: New trajectory score.
            scope_footprint: List of resources touched.
            max_destructiveness: Maximum destructiveness level reached.
            action_counts: Dict of action class counts.

        Returns:
            Updated PrincipalModel if found, None otherwise.
        """
        principal = self.get_by_id(principal_id)
        if principal is None:
            return None

        if trajectory_score is not None:
            principal.trajectory_score = trajectory_score
        if scope_footprint is not None:
            principal.scope_footprint_list = scope_footprint
        if max_destructiveness is not None:
            principal.max_destructiveness = max_destructiveness
        if action_counts is not None:
            principal.action_counts_dict = action_counts

        self.db.commit()
        self.db.refresh(principal)
        return principal
