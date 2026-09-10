"""Tripwire Decision Engine.

Combines authorization, trajectory risk, and trusted action classification
to produce the final security decision according to the contract decision matrix.

Does NOT perform tool execution, confirmation handling, or audit logging.
Does NOT query authorization or trajectory state (those are inputs).

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §9
"""

import math
from dataclasses import dataclass

from app.models.enums import ActionClass, Decision, RiskBand


# Risk band thresholds (Contract §16)
RISK_THRESHOLD_LOW_UPPER = 0.35
RISK_THRESHOLD_HIGH_LOWER = 0.65


@dataclass(frozen=True)
class DecisionResult:
    """Explicit output of the decision engine evaluation.

    Contains the final security decision and supporting context.
    Does NOT contain tool execution results or confirmation state.
    """
    decision: Decision
    risk_band: RiskBand
    action_class: ActionClass
    trajectory_score: float
    reason: str


def classify_risk_band(trajectory_score: float) -> RiskBand:
    """Classify trajectory score into risk band.

    Contract §16:
        LOW:    trajectory_score < 0.35
        MEDIUM: 0.35 <= trajectory_score <= 0.65
        HIGH:   trajectory_score > 0.65

    Args:
        trajectory_score: Normalized trajectory score in [0.0, 1.0].

    Returns:
        RiskBand enum.

    Raises:
        ValueError: If trajectory_score is invalid (NaN, inf, out of bounds).
    """
    # Validate trajectory score
    if not isinstance(trajectory_score, (int, float)):
        raise ValueError(f"Trajectory score must be numeric, got {type(trajectory_score).__name__}")

    if math.isnan(trajectory_score):
        raise ValueError("Trajectory score is NaN")

    if math.isinf(trajectory_score):
        raise ValueError("Trajectory score is infinite")

    if trajectory_score < 0.0 or trajectory_score > 1.0:
        raise ValueError(
            f"Trajectory score must be in [0.0, 1.0], got {trajectory_score}"
        )

    # Apply risk band thresholds
    if trajectory_score < RISK_THRESHOLD_LOW_UPPER:
        return RiskBand.LOW
    elif trajectory_score <= RISK_THRESHOLD_HIGH_LOWER:
        return RiskBand.MEDIUM
    else:
        return RiskBand.HIGH


def decide(
    authorized: bool,
    trajectory_score: float,
    action_class: ActionClass,
) -> DecisionResult:
    """Apply the Tripwire decision matrix to produce a security decision.

    Decision Matrix (Contract §9):
    ┌───────────────┬────────┬──────────────┬──────────────┐
    │ Authorization │ Risk   │ Action Class │ Decision     │
    ├───────────────┼────────┼──────────────┼──────────────┤
    │ Unauthorized  │ Any    │ Any          │ BLOCK        │
    ├───────────────┼────────┼──────────────┼──────────────┤
    │ Authorized    │ LOW    │ READ         │ ALLOW        │
    │ Authorized    │ LOW    │ WRITE        │ ALLOW        │
    │ Authorized    │ LOW    │ DESTRUCTIVE  │ CONFIRM      │
    ├───────────────┼────────┼──────────────┼──────────────┤
    │ Authorized    │ MEDIUM │ READ         │ ALLOW        │
    │ Authorized    │ MEDIUM │ WRITE        │ CONFIRM      │
    │ Authorized    │ MEDIUM │ DESTRUCTIVE  │ HARD_CONFIRM │
    ├───────────────┼────────┼──────────────┼──────────────┤
    │ Authorized    │ HIGH   │ READ         │ BLOCK        │
    │ Authorized    │ HIGH   │ WRITE        │ BLOCK        │
    │ Authorized    │ HIGH   │ DESTRUCTIVE  │ BLOCK        │
    └───────────────┴────────┴──────────────┴──────────────┘

    Args:
        authorized: Authorization result (from AuthorizationService).
        trajectory_score: Trajectory score in [0.0, 1.0] (from TrajectoryEngine).
        action_class: Trusted action classification (from ToolRegistry).

    Returns:
        DecisionResult containing final decision and supporting context.

    Raises:
        ValueError: If inputs are invalid or missing.
        TypeError: If inputs have incorrect types.
    """
    # Validate inputs
    if not isinstance(authorized, bool):
        raise TypeError(f"authorized must be bool, got {type(authorized).__name__}")

    if not isinstance(action_class, ActionClass):
        raise TypeError(
            f"action_class must be ActionClass enum, got {type(action_class).__name__}"
        )

    # Classify risk band (validates trajectory_score)
    risk_band = classify_risk_band(trajectory_score)

    # PRIORITY RULE 1: Unauthorized → BLOCK (regardless of risk/action)
    if not authorized:
        return DecisionResult(
            decision=Decision.BLOCK,
            risk_band=risk_band,
            action_class=action_class,
            trajectory_score=trajectory_score,
            reason="Unauthorized action",
        )

    # Authorized actions: apply matrix based on risk band and action class
    if risk_band == RiskBand.LOW:
        if action_class == ActionClass.READ:
            return DecisionResult(
                decision=Decision.ALLOW,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized low-risk READ action",
            )
        elif action_class == ActionClass.WRITE:
            return DecisionResult(
                decision=Decision.ALLOW,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized low-risk WRITE action",
            )
        elif action_class == ActionClass.DESTRUCTIVE:
            return DecisionResult(
                decision=Decision.CONFIRM,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized low-risk DESTRUCTIVE action requires confirmation",
            )

    elif risk_band == RiskBand.MEDIUM:
        if action_class == ActionClass.READ:
            return DecisionResult(
                decision=Decision.ALLOW,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized medium-risk READ action",
            )
        elif action_class == ActionClass.WRITE:
            return DecisionResult(
                decision=Decision.CONFIRM,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized medium-risk WRITE action requires confirmation",
            )
        elif action_class == ActionClass.DESTRUCTIVE:
            return DecisionResult(
                decision=Decision.HARD_CONFIRM,
                risk_band=risk_band,
                action_class=action_class,
                trajectory_score=trajectory_score,
                reason="Authorized medium-risk DESTRUCTIVE action requires hard confirmation",
            )

    elif risk_band == RiskBand.HIGH:
        # HIGH risk: all action classes are BLOCKED
        return DecisionResult(
            decision=Decision.BLOCK,
            risk_band=risk_band,
            action_class=action_class,
            trajectory_score=trajectory_score,
            reason="High-risk trajectory exceeds safety threshold",
        )

    # Unreachable: all combinations covered, but fail closed if somehow reached
    raise RuntimeError(
        f"Unreachable decision matrix state: authorized={authorized}, "
        f"risk_band={risk_band}, action_class={action_class}"
    )


class DecisionEngine:
    """Stateless decision engine for Tripwire security decisions.

    The DecisionEngine evaluates action proposals against the contract decision matrix.
    It does NOT:
    - Retrieve authorization state (that's AuthorizationService)
    - Calculate trajectory scores (that's TrajectoryEngine)
    - Execute tools
    - Handle confirmations
    - Write audit events

    Usage:
        engine = DecisionEngine()
        result = engine.evaluate(
            authorized=True,
            trajectory_score=0.42,
            action_class=ActionClass.WRITE,
        )
        # result.decision == Decision.CONFIRM
    """

    def evaluate(
        self,
        authorized: bool,
        trajectory_score: float,
        action_class: ActionClass,
    ) -> DecisionResult:
        """Evaluate an action proposal and return the security decision.

        This is a thin wrapper around the pure `decide()` function.

        Args:
            authorized: Authorization result.
            trajectory_score: Trajectory score [0.0, 1.0].
            action_class: Trusted action classification.

        Returns:
            DecisionResult containing the final decision.

        Raises:
            ValueError: If inputs are invalid.
            TypeError: If inputs have incorrect types.
        """
        return decide(
            authorized=authorized,
            trajectory_score=trajectory_score,
            action_class=action_class,
        )
