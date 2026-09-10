"""Trajectory signal calculations and formulas for Tripwire.

Implements the four deterministic behavioral signals, step score weighting,
and asymmetric exponential moving average (EMA) according to the master contract.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §13, §14, §15
"""

from dataclasses import dataclass
from typing import Sequence

# Signal weights defined in Contract §14
WEIGHT_SCOPE_DRIFT: float = 0.30
WEIGHT_DESTRUCTIVENESS_GROWTH: float = 0.35
WEIGHT_VELOCITY: float = 0.15
WEIGHT_FOOTPRINT_BREADTH: float = 0.20

# Fixed catalog size for footprint breadth denominator (Contract §11, CLAUDE.md §11.4)
FIXED_CATALOG_SIZE: int = 6

# Asymmetric EMA smoothing factors (Contract §15)
ALPHA_RISING: float = 0.6
ALPHA_FALLING: float = 0.2


@dataclass(frozen=True)
class TrajectorySignals:
    """Individual normalized signals (0.0 - 1.0) and composite step score."""
    scope_drift: float
    destructiveness_growth: float
    velocity: float
    footprint_breadth: float
    step_score: float


def calculate_scope_drift(current_resource: str, prior_footprint: Sequence[str]) -> float:
    """Calculate scope drift signal.

    Contract §13, CLAUDE.md §11.1
    Returns 1.0 if the current exact resource is outside the prior footprint, 0.0 otherwise.

    Args:
        current_resource: Target resource string from trusted tool definition.
        prior_footprint: List/set of resources previously touched by the principal.

    Returns:
        1.0 for new resource (drift), 0.0 for known resource.
    """
    if not current_resource or not current_resource.strip():
        return 0.0
    return 0.0 if current_resource in prior_footprint else 1.0


def calculate_destructiveness_growth(current_level: float, prior_max: float) -> float:
    """Calculate destructiveness growth signal.

    Contract §13, CLAUDE.md §11.2
    destructiveness_growth = max(0, current_level - prior_max)

    CRITICAL: prior_max must be snapshotted BEFORE updating with current_level.

    Args:
        current_level: Operational level of current action (READ=0.0, WRITE=0.5, DESTRUCTIVE=1.0).
        prior_max: Maximum destructiveness level observed prior to this action.

    Returns:
        Growth delta bounded to [0.0, 1.0].
    """
    return max(0.0, min(1.0, current_level - prior_max))


def calculate_velocity(seconds_since_last_action: float | None) -> float:
    """Calculate velocity signal within the current session.

    Contract §13, CLAUDE.md §11.3
    velocity = clamp(1 - seconds_since_last_action / 60, 0, 1)

    CRITICAL: Velocity is strictly session-local.
    The first action of a session (seconds_since_last_action is None) MUST return 0.0.

    Args:
        seconds_since_last_action: Elapsed seconds since the prior action in this session,
                                  or None if this is the first action of the session.

    Returns:
        Normalized velocity score in [0.0, 1.0].
    """
    if seconds_since_last_action is None:
        return 0.0

    if seconds_since_last_action < 0.0:
        seconds_since_last_action = 0.0

    raw = 1.0 - (seconds_since_last_action / 60.0)
    return max(0.0, min(1.0, raw))


def calculate_footprint_breadth(updated_distinct_resource_count: int) -> float:
    """Calculate footprint breadth signal.

    Contract §13, CLAUDE.md §11.4
    footprint_breadth = distinct_resources_touched / 6

    CRITICAL: Uses the fixed catalog size of 6 as the denominator.
    Includes the current resource in the distinct count.

    Args:
        updated_distinct_resource_count: Number of distinct resources touched by the principal,
                                         including the current action's resource.

    Returns:
        Normalized breadth score in [0.0, 1.0].
    """
    if updated_distinct_resource_count <= 0:
        return 0.0
    return max(0.0, min(1.0, updated_distinct_resource_count / float(FIXED_CATALOG_SIZE)))


def calculate_step_score(
    scope_drift: float,
    destructiveness_growth: float,
    velocity: float,
    footprint_breadth: float,
) -> float:
    """Calculate the composite step score using contract weights.

    Contract §14:
    step_score = 0.30 * scope_drift
               + 0.35 * destructiveness_growth
               + 0.15 * velocity
               + 0.20 * footprint_breadth

    Args:
        scope_drift: Scope drift signal [0, 1].
        destructiveness_growth: Destructiveness growth signal [0, 1].
        velocity: Velocity signal [0, 1].
        footprint_breadth: Footprint breadth signal [0, 1].

    Returns:
        Weighted step score in [0.0, 1.0].
    """
    score = (
        WEIGHT_SCOPE_DRIFT * scope_drift
        + WEIGHT_DESTRUCTIVENESS_GROWTH * destructiveness_growth
        + WEIGHT_VELOCITY * velocity
        + WEIGHT_FOOTPRINT_BREADTH * footprint_breadth
    )
    return max(0.0, min(1.0, score))


def update_asymmetric_ema(previous_score: float, step_score: float) -> float:
    """Update trajectory score using asymmetric Exponential Moving Average (EMA).

    Contract §15:
    If step_score >= previous_score:
        new_score = previous_score + 0.6 * (step_score - previous_score)
    Else:
        new_score = previous_score + 0.2 * (step_score - previous_score)

    This makes risk rise rapidly upon escalation (alpha=0.6) and decay slowly (alpha=0.2).

    Args:
        previous_score: Trajectory score before this action.
        step_score: Composite step score for the current action.

    Returns:
        Updated trajectory score in [0.0, 1.0].
    """
    if step_score >= previous_score:
        alpha = ALPHA_RISING
    else:
        alpha = ALPHA_FALLING

    new_score = previous_score + alpha * (step_score - previous_score)
    return max(0.0, min(1.0, new_score))
