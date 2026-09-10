"""Tests for the Tripwire Decision Engine.

Tests verify:
- Complete 10-row decision matrix coverage
- Risk band threshold boundaries (0.35, 0.65)
- Unauthorized always blocks (priority rule)
- HIGH risk always blocks (all action classes)
- Fail-closed behavior on invalid inputs
- Agent tampering resistance (trusted metadata only)
- Deterministic decisions (no randomness)
"""

import math

import pytest

from app.models.enums import ActionClass, Decision, RiskBand
from app.security.decision_engine import (
    DecisionEngine,
    DecisionResult,
    classify_risk_band,
    decide,
)


class TestRiskBandClassification:
    """Tests for risk band threshold classification."""

    def test_risk_band_zero_is_low(self):
        """Trajectory score 0.0 is LOW risk."""
        assert classify_risk_band(0.0) == RiskBand.LOW

    def test_risk_band_just_below_threshold_is_low(self):
        """Trajectory score 0.349999 is LOW risk."""
        assert classify_risk_band(0.349999) == RiskBand.LOW

    def test_risk_band_at_lower_threshold_is_medium(self):
        """Trajectory score 0.35 is MEDIUM risk (boundary included)."""
        assert classify_risk_band(0.35) == RiskBand.MEDIUM

    def test_risk_band_mid_range_is_medium(self):
        """Trajectory score 0.5 is MEDIUM risk."""
        assert classify_risk_band(0.5) == RiskBand.MEDIUM

    def test_risk_band_at_upper_threshold_is_medium(self):
        """Trajectory score 0.65 is MEDIUM risk (boundary included)."""
        assert classify_risk_band(0.65) == RiskBand.MEDIUM

    def test_risk_band_just_above_threshold_is_high(self):
        """Trajectory score 0.650001 is HIGH risk."""
        assert classify_risk_band(0.650001) == RiskBand.HIGH

    def test_risk_band_one_is_high(self):
        """Trajectory score 1.0 is HIGH risk."""
        assert classify_risk_band(1.0) == RiskBand.HIGH

    def test_risk_band_invalid_negative_raises(self):
        """Negative trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
            classify_risk_band(-0.01)

    def test_risk_band_invalid_above_one_raises(self):
        """Trajectory score > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
            classify_risk_band(1.01)

    def test_risk_band_nan_raises(self):
        """NaN trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="NaN"):
            classify_risk_band(float("nan"))

    def test_risk_band_positive_infinity_raises(self):
        """Positive infinity trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="infinite"):
            classify_risk_band(float("inf"))

    def test_risk_band_negative_infinity_raises(self):
        """Negative infinity trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="infinite"):
            classify_risk_band(float("-inf"))


class TestUnauthorizedDecisions:
    """Tests for unauthorized actions (priority rule: always BLOCK)."""

    def test_unauthorized_low_read_blocks(self):
        """Unauthorized + LOW + READ → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.1,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.LOW
        assert result.action_class == ActionClass.READ
        assert "Unauthorized" in result.reason

    def test_unauthorized_low_write_blocks(self):
        """Unauthorized + LOW + WRITE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.2,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.LOW

    def test_unauthorized_low_destructive_blocks(self):
        """Unauthorized + LOW + DESTRUCTIVE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.0,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.BLOCK

    def test_unauthorized_medium_read_blocks(self):
        """Unauthorized + MEDIUM + READ → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.5,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.MEDIUM

    def test_unauthorized_medium_write_blocks(self):
        """Unauthorized + MEDIUM + WRITE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.5,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.BLOCK

    def test_unauthorized_medium_destructive_blocks(self):
        """Unauthorized + MEDIUM + DESTRUCTIVE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.5,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.BLOCK

    def test_unauthorized_high_read_blocks(self):
        """Unauthorized + HIGH + READ → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.8,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.HIGH

    def test_unauthorized_high_write_blocks(self):
        """Unauthorized + HIGH + WRITE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=0.8,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.BLOCK

    def test_unauthorized_high_destructive_blocks(self):
        """Unauthorized + HIGH + DESTRUCTIVE → BLOCK."""
        result = decide(
            authorized=False,
            trajectory_score=1.0,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.BLOCK


class TestAuthorizedLowRiskDecisions:
    """Tests for authorized actions at LOW risk (score < 0.35)."""

    def test_authorized_low_read_allows(self):
        """Authorized + LOW + READ → ALLOW."""
        result = decide(
            authorized=True,
            trajectory_score=0.1,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.ALLOW
        assert result.risk_band == RiskBand.LOW
        assert result.action_class == ActionClass.READ
        assert "low-risk READ" in result.reason

    def test_authorized_low_write_allows(self):
        """Authorized + LOW + WRITE → ALLOW."""
        result = decide(
            authorized=True,
            trajectory_score=0.2,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.ALLOW
        assert result.risk_band == RiskBand.LOW
        assert result.action_class == ActionClass.WRITE

    def test_authorized_low_destructive_confirms(self):
        """Authorized + LOW + DESTRUCTIVE → CONFIRM."""
        result = decide(
            authorized=True,
            trajectory_score=0.3,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.CONFIRM
        assert result.risk_band == RiskBand.LOW
        assert result.action_class == ActionClass.DESTRUCTIVE
        assert "confirmation" in result.reason


class TestAuthorizedMediumRiskDecisions:
    """Tests for authorized actions at MEDIUM risk (0.35 <= score <= 0.65)."""

    def test_authorized_medium_read_allows(self):
        """Authorized + MEDIUM + READ → ALLOW."""
        result = decide(
            authorized=True,
            trajectory_score=0.5,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.ALLOW
        assert result.risk_band == RiskBand.MEDIUM
        assert result.action_class == ActionClass.READ

    def test_authorized_medium_write_confirms(self):
        """Authorized + MEDIUM + WRITE → CONFIRM."""
        result = decide(
            authorized=True,
            trajectory_score=0.5,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.CONFIRM
        assert result.risk_band == RiskBand.MEDIUM
        assert result.action_class == ActionClass.WRITE

    def test_authorized_medium_destructive_hard_confirms(self):
        """Authorized + MEDIUM + DESTRUCTIVE → HARD_CONFIRM."""
        result = decide(
            authorized=True,
            trajectory_score=0.5,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.HARD_CONFIRM
        assert result.risk_band == RiskBand.MEDIUM
        assert result.action_class == ActionClass.DESTRUCTIVE
        assert "hard confirmation" in result.reason


class TestAuthorizedHighRiskDecisions:
    """Tests for authorized actions at HIGH risk (score > 0.65)."""

    def test_authorized_high_read_blocks(self):
        """Authorized + HIGH + READ → BLOCK."""
        result = decide(
            authorized=True,
            trajectory_score=0.7,
            action_class=ActionClass.READ,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.HIGH
        assert result.action_class == ActionClass.READ
        assert "High-risk" in result.reason

    def test_authorized_high_write_blocks(self):
        """Authorized + HIGH + WRITE → BLOCK."""
        result = decide(
            authorized=True,
            trajectory_score=0.8,
            action_class=ActionClass.WRITE,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.HIGH
        assert result.action_class == ActionClass.WRITE

    def test_authorized_high_destructive_blocks(self):
        """Authorized + HIGH + DESTRUCTIVE → BLOCK."""
        result = decide(
            authorized=True,
            trajectory_score=1.0,
            action_class=ActionClass.DESTRUCTIVE,
        )
        assert result.decision == Decision.BLOCK
        assert result.risk_band == RiskBand.HIGH
        assert result.action_class == ActionClass.DESTRUCTIVE


class TestDecisionMatrixCompleteness:
    """Property tests ensuring every valid combination has a defined outcome."""

    @pytest.mark.parametrize(
        "authorized,score,action_class,expected_decision",
        [
            # Unauthorized: always BLOCK
            (False, 0.0, ActionClass.READ, Decision.BLOCK),
            (False, 0.0, ActionClass.WRITE, Decision.BLOCK),
            (False, 0.0, ActionClass.DESTRUCTIVE, Decision.BLOCK),
            (False, 0.5, ActionClass.READ, Decision.BLOCK),
            (False, 0.5, ActionClass.WRITE, Decision.BLOCK),
            (False, 0.5, ActionClass.DESTRUCTIVE, Decision.BLOCK),
            (False, 0.8, ActionClass.READ, Decision.BLOCK),
            (False, 0.8, ActionClass.WRITE, Decision.BLOCK),
            (False, 0.8, ActionClass.DESTRUCTIVE, Decision.BLOCK),
            # Authorized LOW
            (True, 0.1, ActionClass.READ, Decision.ALLOW),
            (True, 0.1, ActionClass.WRITE, Decision.ALLOW),
            (True, 0.1, ActionClass.DESTRUCTIVE, Decision.CONFIRM),
            # Authorized MEDIUM
            (True, 0.5, ActionClass.READ, Decision.ALLOW),
            (True, 0.5, ActionClass.WRITE, Decision.CONFIRM),
            (True, 0.5, ActionClass.DESTRUCTIVE, Decision.HARD_CONFIRM),
            # Authorized HIGH
            (True, 0.8, ActionClass.READ, Decision.BLOCK),
            (True, 0.8, ActionClass.WRITE, Decision.BLOCK),
            (True, 0.8, ActionClass.DESTRUCTIVE, Decision.BLOCK),
        ],
    )
    def test_decision_matrix_exhaustive(self, authorized, score, action_class, expected_decision):
        """Every valid matrix combination produces the expected decision."""
        result = decide(
            authorized=authorized,
            trajectory_score=score,
            action_class=action_class,
        )
        assert result.decision == expected_decision


class TestInvalidInputs:
    """Tests verifying fail-closed behavior on invalid/malformed inputs."""

    def test_invalid_trajectory_score_type_raises(self):
        """Non-numeric trajectory score raises TypeError."""
        with pytest.raises((ValueError, TypeError)):
            decide(
                authorized=True,
                trajectory_score="0.5",  # type: ignore[arg-type]
                action_class=ActionClass.READ,
            )

    def test_invalid_authorized_type_raises(self):
        """Non-bool authorized raises TypeError."""
        with pytest.raises(TypeError, match="authorized must be bool"):
            decide(
                authorized="true",  # type: ignore[arg-type]
                trajectory_score=0.5,
                action_class=ActionClass.READ,
            )

    def test_invalid_action_class_type_raises(self):
        """Non-ActionClass enum raises TypeError."""
        with pytest.raises(TypeError, match="action_class must be ActionClass enum"):
            decide(
                authorized=True,
                trajectory_score=0.5,
                action_class="READ",  # type: ignore[arg-type]
            )

    def test_out_of_bounds_negative_score_raises(self):
        """Trajectory score < 0 raises ValueError."""
        with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
            decide(
                authorized=True,
                trajectory_score=-0.1,
                action_class=ActionClass.READ,
            )

    def test_out_of_bounds_above_one_score_raises(self):
        """Trajectory score > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
            decide(
                authorized=True,
                trajectory_score=1.5,
                action_class=ActionClass.WRITE,
            )

    def test_nan_score_raises(self):
        """NaN trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="NaN"):
            decide(
                authorized=True,
                trajectory_score=float("nan"),
                action_class=ActionClass.READ,
            )

    def test_infinite_score_raises(self):
        """Infinite trajectory score raises ValueError."""
        with pytest.raises(ValueError, match="infinite"):
            decide(
                authorized=True,
                trajectory_score=float("inf"),
                action_class=ActionClass.READ,
            )


class TestDecisionEngineDeterminism:
    """Tests verifying deterministic behavior."""

    def test_same_inputs_produce_same_decision(self):
        """Repeated calls with identical inputs produce identical results."""
        results = [
            decide(
                authorized=True,
                trajectory_score=0.42,
                action_class=ActionClass.WRITE,
            )
            for _ in range(10)
        ]

        # All results must be identical
        assert all(r.decision == Decision.CONFIRM for r in results)
        assert all(r.risk_band == RiskBand.MEDIUM for r in results)
        assert all(r.action_class == ActionClass.WRITE for r in results)
        assert all(r.trajectory_score == 0.42 for r in results)

    def test_decision_is_deterministic_no_randomness(self):
        """Decision engine contains no randomness or non-deterministic behavior."""
        engine = DecisionEngine()

        # Same inputs must produce same output every time
        for _ in range(100):
            result = engine.evaluate(
                authorized=True,
                trajectory_score=0.5,
                action_class=ActionClass.DESTRUCTIVE,
            )
            assert result.decision == Decision.HARD_CONFIRM


class TestDecisionEngineClass:
    """Tests for DecisionEngine wrapper class."""

    def test_engine_evaluate_delegates_to_decide(self):
        """DecisionEngine.evaluate produces same result as decide()."""
        engine = DecisionEngine()

        direct = decide(
            authorized=True,
            trajectory_score=0.6,
            action_class=ActionClass.WRITE,
        )

        wrapped = engine.evaluate(
            authorized=True,
            trajectory_score=0.6,
            action_class=ActionClass.WRITE,
        )

        assert direct.decision == wrapped.decision
        assert direct.risk_band == wrapped.risk_band
        assert direct.action_class == wrapped.action_class
        assert direct.trajectory_score == wrapped.trajectory_score

    def test_engine_is_stateless(self):
        """DecisionEngine maintains no state between evaluations."""
        engine = DecisionEngine()

        result1 = engine.evaluate(
            authorized=True,
            trajectory_score=0.1,
            action_class=ActionClass.READ,
        )
        assert result1.decision == Decision.ALLOW

        result2 = engine.evaluate(
            authorized=False,
            trajectory_score=0.1,
            action_class=ActionClass.READ,
        )
        assert result2.decision == Decision.BLOCK

        # First evaluation should not affect second
        result3 = engine.evaluate(
            authorized=True,
            trajectory_score=0.1,
            action_class=ActionClass.READ,
        )
        assert result3.decision == Decision.ALLOW


class TestSecurityInvariantsAndTampering:
    """Security tests verifying tamper-resistance and fail-closed behavior."""

    def test_agent_payload_tampering_cannot_override_trusted_action_class(self):
        """Agent proposal payload attempting to claim drop_table is READ does not fool the engine.

        Invariant: The DecisionEngine MUST receive the trusted ActionClass from ToolRegistry.
        """
        from app.schemas.requests import ActionProposalRequest
        from app.security.tool_registry import default_tool_registry

        # Malicious payload from agent
        proposal = ActionProposalRequest(
            principal_id="attacker",
            session_id="session_001",
            agent_id="agent_001",
            action="drop_table",
            resource="db_schema:core",
            parameters={"action_class": "READ", "reversibility": "READ"},
        )

        # Lookup trusted metadata
        trusted_tool = default_tool_registry.get_or_raise(proposal.action)
        assert trusted_tool.action_class == ActionClass.DESTRUCTIVE

        # Decision engine evaluates using trusted metadata
        result = decide(
            authorized=True,
            trajectory_score=0.2,  # LOW risk
            action_class=trusted_tool.action_class,
        )

        # Even at LOW risk, a DESTRUCTIVE action requires CONFIRM, not ALLOW
        assert result.decision == Decision.CONFIRM
        assert result.action_class == ActionClass.DESTRUCTIVE

    def test_unknown_tool_fails_closed_before_or_at_engine(self):
        """Unknown tool cannot be evaluated or assigned a permissive default."""
        from app.security.tool_registry import default_tool_registry

        unknown_action = "arbitrary_backdoor_tool"
        tool = default_tool_registry.get(unknown_action)
        assert tool is None

        # Fails closed if attempted with invalid type or None
        with pytest.raises(TypeError):
            decide(
                authorized=True,
                trajectory_score=0.1,
                action_class=tool.action_class if tool else None,  # type: ignore[arg-type]
            )

    def test_high_risk_trajectory_never_allows_or_confirms(self):
        """HIGH risk trajectory (> 0.65) MUST result in BLOCK for all action classes."""
        for action_class in [ActionClass.READ, ActionClass.WRITE, ActionClass.DESTRUCTIVE]:
            result = decide(
                authorized=True,
                trajectory_score=0.75,
                action_class=action_class,
            )
            assert result.decision == Decision.BLOCK
            assert result.risk_band == RiskBand.HIGH


class TestCanonicalScenariosWithDecisionEngine:
    """Tests evaluating canonical scenario sequences through the Decision Engine."""

    def test_attack_scenario_progression(self):
        """Database escalation attack trajectory progression through Decision Engine.

        Contract §18:
        1. read_logs (LOW, READ) → ALLOW
        2. read_customer (MEDIUM, READ) → ALLOW
        3. update_customer (MEDIUM, WRITE) → CONFIRM
        4. export_customers (MEDIUM, WRITE) → CONFIRM
        5. change_permissions (MEDIUM, DESTRUCTIVE) → HARD_CONFIRM
        6. drop_table (HIGH, DESTRUCTIVE) → BLOCK
        """
        # Step 1: read_logs (Score 0.20, LOW, READ)
        res1 = decide(authorized=True, trajectory_score=0.20, action_class=ActionClass.READ)
        assert res1.decision == Decision.ALLOW
        assert res1.risk_band == RiskBand.LOW

        # Step 2: read_customer (Score 0.37, MEDIUM, READ)
        res2 = decide(authorized=True, trajectory_score=0.37, action_class=ActionClass.READ)
        assert res2.decision == Decision.ALLOW
        assert res2.risk_band == RiskBand.MEDIUM

        # Step 3: update_customer (Score 0.45, MEDIUM, WRITE)
        res3 = decide(authorized=True, trajectory_score=0.45, action_class=ActionClass.WRITE)
        assert res3.decision == Decision.CONFIRM
        assert res3.risk_band == RiskBand.MEDIUM

        # Step 4: export_customers (Score 0.55, MEDIUM, WRITE)
        res4 = decide(authorized=True, trajectory_score=0.55, action_class=ActionClass.WRITE)
        assert res4.decision == Decision.CONFIRM
        assert res4.risk_band == RiskBand.MEDIUM

        # Step 5: change_permissions (Score 0.62, MEDIUM, DESTRUCTIVE)
        res5 = decide(authorized=True, trajectory_score=0.62, action_class=ActionClass.DESTRUCTIVE)
        assert res5.decision == Decision.HARD_CONFIRM
        assert res5.risk_band == RiskBand.MEDIUM

        # Step 6: drop_table (Score 0.72, HIGH, DESTRUCTIVE)
        res6 = decide(authorized=True, trajectory_score=0.72, action_class=ActionClass.DESTRUCTIVE)
        assert res6.decision == Decision.BLOCK
        assert res6.risk_band == RiskBand.HIGH

    def test_legitimate_scenario_progression(self):
        """Legitimate schema migration sequence maintains controlled access without blind blocking.

        Contract §19:
        Actions remain in LOW/MEDIUM bands.
        Destructive actions at MEDIUM produce HARD_CONFIRM, not BLOCK.
        """
        # Read operations at LOW/MEDIUM
        res1 = decide(authorized=True, trajectory_score=0.20, action_class=ActionClass.READ)
        assert res1.decision == Decision.ALLOW

        # Write operations at MEDIUM
        res2 = decide(authorized=True, trajectory_score=0.38, action_class=ActionClass.WRITE)
        assert res2.decision == Decision.CONFIRM

        # Destructive operation at MEDIUM
        res3 = decide(authorized=True, trajectory_score=0.48, action_class=ActionClass.DESTRUCTIVE)
        assert res3.decision == Decision.HARD_CONFIRM


class TestDecisionResult:
    """Tests for DecisionResult data structure."""

    def test_decision_result_is_immutable(self):
        """DecisionResult is a frozen dataclass."""
        result = DecisionResult(
            decision=Decision.ALLOW,
            risk_band=RiskBand.LOW,
            action_class=ActionClass.READ,
            trajectory_score=0.2,
            reason="Test",
        )

        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            result.decision = Decision.BLOCK  # type: ignore[misc]

    def test_decision_result_contains_all_context(self):
        """DecisionResult exposes all necessary decision context."""
        result = decide(
            authorized=True,
            trajectory_score=0.55,
            action_class=ActionClass.DESTRUCTIVE,
        )

        assert hasattr(result, "decision")
        assert hasattr(result, "risk_band")
        assert hasattr(result, "action_class")
        assert hasattr(result, "trajectory_score")
        assert hasattr(result, "reason")

        assert result.decision == Decision.HARD_CONFIRM
        assert result.risk_band == RiskBand.MEDIUM
        assert result.action_class == ActionClass.DESTRUCTIVE
        assert result.trajectory_score == 0.55
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0
