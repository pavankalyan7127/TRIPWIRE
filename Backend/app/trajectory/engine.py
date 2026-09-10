"""Tripwire Trajectory Engine and Monitoring Service.

Evaluates behavioral trajectory across sequences of actions within and across sessions.
Maintains session-local velocity and persists principal-level historical state.
Does NOT compute final security decisions (ALLOW/CONFIRM/BLOCK).

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §13, §14, §15, §17
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.models.enums import ActionClass
from app.security.tool_registry import ToolRegistry, default_tool_registry
from app.trajectory.signals import (
    TrajectorySignals,
    calculate_destructiveness_growth,
    calculate_footprint_breadth,
    calculate_scope_drift,
    calculate_step_score,
    calculate_velocity,
    update_asymmetric_ema,
)


@dataclass(frozen=True)
class TrajectoryResult:
    """Explicit output of a trajectory step evaluation.

    Contains trajectory metrics, individual signal values, and updated state.
    Contains NO final security decision enums (ALLOW/CONFIRM/BLOCK).

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §13
    """
    previous_score: float
    new_score: float
    signals: TrajectorySignals
    action: str
    resource: str
    action_class: ActionClass
    destructiveness_level: float
    footprint: list[str]
    max_destructiveness: float
    action_counts: dict[str, int]

    @property
    def trajectory_score(self) -> float:
        """Alias for new_score."""
        return self.new_score

    @property
    def scope_drift(self) -> float:
        """Convenience accessor for scope drift signal."""
        return self.signals.scope_drift

    @property
    def destructiveness_growth(self) -> float:
        """Convenience accessor for destructiveness growth signal."""
        return self.signals.destructiveness_growth

    @property
    def velocity(self) -> float:
        """Convenience accessor for velocity signal."""
        return self.signals.velocity

    @property
    def footprint_breadth(self) -> float:
        """Convenience accessor for footprint breadth signal."""
        return self.signals.footprint_breadth

    @property
    def step_score(self) -> float:
        """Convenience accessor for composite step score."""
        return self.signals.step_score


class TrajectoryEngine:
    """Evaluates and persists behavioral trajectory for AI agent action proposals.

    Rules:
    1. Consumes trusted tool metadata strictly from ToolRegistry (never agent input).
    2. Unknown tools fail closed (KeyError).
    3. Destructiveness growth is computed using the prior maximum before updating.
    4. Velocity is strictly session-local (resets to 0.0 for first action of each session).
    5. Footprint breadth includes current resource and uses fixed denominator 6.
    6. Trajectory score updates via asymmetric EMA (alpha=0.6 rising, alpha=0.2 falling).
    7. Trajectory state persists to the principal across sessions.
    """

    def __init__(
        self,
        db: Session,
        tool_registry: Optional[ToolRegistry] = None,
    ):
        """Initialize TrajectoryEngine with database session and tool registry.

        Args:
            db: SQLAlchemy Session for repository access.
            tool_registry: Optional ToolRegistry instance (defaults to default_tool_registry).
        """
        self.db = db
        self.principal_repo = PrincipalRepository(db)
        self.session_repo = SessionRepository(db)
        self.tool_registry = tool_registry or default_tool_registry

        # Session-local in-memory velocity tracking: session_id -> last_action_timestamp
        self._session_last_action: dict[str, datetime] = {}

    def get_session_last_action(self, session_id: str) -> Optional[datetime]:
        """Get the timestamp of the last action in the given session."""
        return self._session_last_action.get(session_id)

    def set_session_last_action(self, session_id: str, timestamp: datetime) -> None:
        """Record the timestamp of the latest action in the given session."""
        self._session_last_action[session_id] = timestamp

    def clear_session_velocity(self, session_id: str) -> None:
        """Clear session-local velocity state (e.g. when session ends)."""
        self._session_last_action.pop(session_id, None)

    def evaluate_action(
        self,
        principal_id: str,
        session_id: str,
        action: str,
        timestamp: Optional[datetime] = None,
    ) -> TrajectoryResult:
        """Evaluate an action proposal, update behavioral signals, and persist state.

        Args:
            principal_id: Identifier of the principal.
            session_id: Identifier of the current session.
            action: Tool/action name being proposed.
            timestamp: Optional explicit timestamp for deterministic testing.
                       Defaults to current UTC time.

        Returns:
            TrajectoryResult containing signal breakdown and new trajectory score.

        Raises:
            KeyError: If the proposed action is not registered in ToolRegistry (fail-closed).
            ValueError: If principal_id or session_id is empty or invalid.
        """
        if not principal_id or not principal_id.strip():
            raise ValueError("principal_id must be a non-empty string.")
        if not session_id or not session_id.strip():
            raise ValueError("session_id must be a non-empty string.")
        if not action or not action.strip():
            raise ValueError("action must be a non-empty string.")

        # 1. Resolve trusted metadata from ToolRegistry (fail-closed on unknown tool)
        tool = self.tool_registry.get(action.strip())
        if tool is None:
            raise KeyError(f"Tool '{action}' is not registered in Tripwire tool registry.")

        resource = tool.resource
        action_class = tool.action_class
        current_level = tool.destructiveness_level

        # 2. Retrieve persisted principal state (seed new principal with 0.0)
        principal = self.principal_repo.get_or_create(principal_id.strip())
        prior_score = principal.trajectory_score
        prior_footprint = list(principal.scope_footprint_list)
        prior_max_destructiveness = principal.max_destructiveness
        prior_action_counts = dict(principal.action_counts_dict)

        # 3. Verify/ensure session exists in database
        session = self.session_repo.get_by_id(session_id.strip())
        if session is not None and session.principal_id != principal_id.strip():
            raise ValueError(
                f"Session '{session_id}' belongs to principal '{session.principal_id}', "
                f"not '{principal_id}'."
            )

        # 4. Resolve evaluation timestamp
        current_time = timestamp if timestamp is not None else datetime.now(timezone.utc)

        # 5. Signal 1: Scope Drift (using prior footprint)
        scope_drift = calculate_scope_drift(resource, prior_footprint)

        # 6. Signal 2: Destructiveness Growth (prior_max snapshotted BEFORE updating)
        growth = calculate_destructiveness_growth(current_level, prior_max_destructiveness)
        new_max_destructiveness = max(prior_max_destructiveness, current_level)

        # 7. Signal 3: Velocity (strictly session-local)
        last_action_at = self.get_session_last_action(session_id)
        if last_action_at is not None:
            seconds_elapsed = (current_time - last_action_at).total_seconds()
        else:
            seconds_elapsed = None

        velocity = calculate_velocity(seconds_elapsed)
        self.set_session_last_action(session_id, current_time)

        # 8. Signal 4: Footprint Breadth (computed on updated distinct footprint)
        updated_footprint = list(prior_footprint)
        if resource not in updated_footprint:
            updated_footprint.append(resource)

        distinct_count = len(set(updated_footprint))
        footprint_breadth = calculate_footprint_breadth(distinct_count)

        # 9. Composite Step Score
        step_score = calculate_step_score(
            scope_drift=scope_drift,
            destructiveness_growth=growth,
            velocity=velocity,
            footprint_breadth=footprint_breadth,
        )

        # 10. Asymmetric EMA Trajectory Score Update
        new_score = update_asymmetric_ema(
            previous_score=prior_score,
            step_score=step_score,
        )

        # 11. Update Action Counts
        updated_action_counts = dict(prior_action_counts)
        class_key = action_class.value
        updated_action_counts[class_key] = updated_action_counts.get(class_key, 0) + 1

        # 12. Persist updated principal state to database
        self.principal_repo.update_trajectory_state(
            principal_id=principal_id.strip(),
            trajectory_score=new_score,
            scope_footprint=updated_footprint,
            max_destructiveness=new_max_destructiveness,
            action_counts=updated_action_counts,
        )

        # 13. Persist session trajectory score to database if session exists
        if session is not None:
            self.session_repo.update_trajectory_score(session_id.strip(), new_score)

        # 14. Return TrajectoryResult
        signals = TrajectorySignals(
            scope_drift=scope_drift,
            destructiveness_growth=growth,
            velocity=velocity,
            footprint_breadth=footprint_breadth,
            step_score=step_score,
        )

        return TrajectoryResult(
            previous_score=prior_score,
            new_score=new_score,
            signals=signals,
            action=action,
            resource=resource,
            action_class=action_class,
            destructiveness_level=current_level,
            footprint=updated_footprint,
            max_destructiveness=new_max_destructiveness,
            action_counts=updated_action_counts,
        )
