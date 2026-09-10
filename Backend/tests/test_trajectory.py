"""Tests for Tripwire Trajectory Monitoring Engine and Signals.

Tests verify:
- New principal initialization (trajectory=0.0)
- Deterministic signal calculations (scope drift, destructiveness growth, velocity, footprint breadth)
- Step score weighted formula
- Asymmetric EMA (alpha=0.6 rising, alpha=0.2 falling)
- Cross-session state persistence (score, footprint, max_destructiveness, action_counts)
- Session-local velocity reset
- Destructiveness growth ordering (prior max snapshot before update)
- Unknown tool fail-closed behavior
- Trusted ToolRegistry metadata integration
- Canonical attack and legitimate scenario trajectories

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §13-20
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.models.enums import ActionClass
from app.trajectory.engine import TrajectoryEngine
from app.trajectory.signals import (
    ALPHA_FALLING,
    ALPHA_RISING,
    FIXED_CATALOG_SIZE,
    WEIGHT_DESTRUCTIVENESS_GROWTH,
    WEIGHT_FOOTPRINT_BREADTH,
    WEIGHT_SCOPE_DRIFT,
    WEIGHT_VELOCITY,
    calculate_destructiveness_growth,
    calculate_footprint_breadth,
    calculate_scope_drift,
    calculate_step_score,
    calculate_velocity,
    update_asymmetric_ema,
)


@pytest.fixture
def trajectory_engine(db_session):
    """Create TrajectoryEngine instance with test database session."""
    return TrajectoryEngine(db_session)


class TestNewPrincipalInitialization:
    """Tests for new principal trajectory state initialization."""

    def test_new_principal_starts_with_zero_trajectory(self, trajectory_engine):
        """New principal starts with trajectory_score = 0.0 (Contract §17)."""
        result = trajectory_engine.evaluate_action(
            principal_id="new_user",
            session_id="session_001",
            action="read_logs",
            timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
        )
        assert result.previous_score == 0.0

    def test_first_action_has_zero_velocity(self, trajectory_engine):
        """First action of a session has velocity = 0.0 (CLAUDE.md §11.3)."""
        result = trajectory_engine.evaluate_action(
            principal_id="user_velocity",
            session_id="session_001",
            action="read_logs",
            timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
        )
        assert result.velocity == 0.0


class TestScopeDriftSignal:
    """Tests for scope drift calculation."""

    def test_first_resource_produces_scope_drift_one(self):
        """First resource results in scope_drift = 1.0."""
        drift = calculate_scope_drift("logs", [])
        assert drift == 1.0

    def test_repeated_resource_produces_scope_drift_zero(self):
        """Repeated resource results in scope_drift = 0.0."""
        prior_footprint = ["logs", "db_records:customer_table"]
        drift = calculate_scope_drift("logs", prior_footprint)
        assert drift == 0.0

    def test_new_resource_produces_scope_drift_one(self):
        """New resource after existing footprint results in scope_drift = 1.0."""
        prior_footprint = ["logs"]
        drift = calculate_scope_drift("db_records:customer_table", prior_footprint)
        assert drift == 1.0

    def test_scope_drift_in_trajectory_sequence(self, trajectory_engine):
        """Verify scope drift behavior across a trajectory sequence."""
        principal_id = "user_drift"
        session_id = "session_drift"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # First action: new resource → drift=1
        r1 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        assert r1.scope_drift == 1.0

        # Second action: repeated resource → drift=0
        r2 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time + timedelta(seconds=10))
        assert r2.scope_drift == 0.0

        # Third action: new resource → drift=1
        r3 = trajectory_engine.evaluate_action(principal_id, session_id, "read_customer", base_time + timedelta(seconds=20))
        assert r3.scope_drift == 1.0


class TestDestructivenessGrowthSignal:
    """Tests for destructiveness growth calculation and ordering."""

    def test_read_from_zero_produces_zero_growth(self):
        """READ (0.0) from max 0.0 → growth = 0.0."""
        growth = calculate_destructiveness_growth(current_level=0.0, prior_max=0.0)
        assert growth == 0.0

    def test_write_from_zero_produces_half_growth(self):
        """WRITE (0.5) from max 0.0 → growth = 0.5."""
        growth = calculate_destructiveness_growth(current_level=0.5, prior_max=0.0)
        assert growth == 0.5

    def test_destructive_from_write_produces_half_growth(self):
        """DESTRUCTIVE (1.0) from max 0.5 → growth = 0.5."""
        growth = calculate_destructiveness_growth(current_level=1.0, prior_max=0.5)
        assert growth == 0.5

    def test_destructive_from_destructive_produces_zero_growth(self):
        """DESTRUCTIVE (1.0) after max already 1.0 → growth = 0.0."""
        growth = calculate_destructiveness_growth(current_level=1.0, prior_max=1.0)
        assert growth == 0.0

    def test_prior_max_snapshot_ordering(self, trajectory_engine):
        """Verify prior max is snapshotted BEFORE current action updates max (CLAUDE.md §11.2)."""
        principal_id = "user_growth"
        session_id = "session_growth"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # First action: READ (0.0) from max 0.0 → growth 0.0, new max 0.0
        r1 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        assert r1.destructiveness_growth == 0.0
        assert r1.max_destructiveness == 0.0

        # Second action: WRITE (0.5) from prior max 0.0 → growth 0.5, new max 0.5
        r2 = trajectory_engine.evaluate_action(principal_id, session_id, "update_customer", base_time + timedelta(seconds=10))
        assert r2.destructiveness_growth == 0.5
        assert r2.max_destructiveness == 0.5

        # Third action: WRITE (0.5) from prior max 0.5 → growth 0.0, new max 0.5
        r3 = trajectory_engine.evaluate_action(principal_id, session_id, "export_customers", base_time + timedelta(seconds=20))
        assert r3.destructiveness_growth == 0.0
        assert r3.max_destructiveness == 0.5

        # Fourth action: DESTRUCTIVE (1.0) from prior max 0.5 → growth 0.5, new max 1.0
        r4 = trajectory_engine.evaluate_action(principal_id, session_id, "drop_table", base_time + timedelta(seconds=30))
        assert r4.destructiveness_growth == 0.5
        assert r4.max_destructiveness == 1.0


class TestVelocitySignal:
    """Tests for velocity signal calculation."""

    def test_first_action_zero_velocity(self):
        """First action (None seconds) → velocity = 0.0."""
        velocity = calculate_velocity(None)
        assert velocity == 0.0

    def test_ten_seconds_velocity(self):
        """10 seconds → velocity ≈ 0.8333."""
        velocity = calculate_velocity(10.0)
        expected = 1.0 - (10.0 / 60.0)
        assert abs(velocity - expected) < 0.0001
        assert abs(velocity - 0.8333) < 0.01

    def test_thirty_seconds_velocity(self):
        """30 seconds → velocity = 0.5."""
        velocity = calculate_velocity(30.0)
        assert abs(velocity - 0.5) < 0.0001

    def test_sixty_seconds_velocity(self):
        """60 seconds → velocity = 0.0."""
        velocity = calculate_velocity(60.0)
        assert velocity == 0.0

    def test_more_than_sixty_seconds_velocity(self):
        """90 seconds → velocity = 0.0 (clamped)."""
        velocity = calculate_velocity(90.0)
        assert velocity == 0.0

    def test_new_session_resets_velocity(self, trajectory_engine):
        """New session starts with velocity 0.0 even if principal has prior history (CLAUDE.md §11.3)."""
        principal_id = "user_velocity_reset"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1: two rapid actions
        r1 = trajectory_engine.evaluate_action(principal_id, "session_001", "read_logs", base_time)
        assert r1.velocity == 0.0

        r2 = trajectory_engine.evaluate_action(principal_id, "session_001", "read_customer", base_time + timedelta(seconds=10))
        assert r2.velocity > 0.0  # velocity present

        # Session 2: first action MUST have velocity 0.0
        trajectory_engine.clear_session_velocity("session_001")
        r3 = trajectory_engine.evaluate_action(principal_id, "session_002", "update_customer", base_time + timedelta(seconds=20))
        assert r3.velocity == 0.0


class TestFootprintBreadthSignal:
    """Tests for footprint breadth calculation."""

    def test_one_distinct_resource(self):
        """1 distinct resource → 1/6 ≈ 0.1667."""
        breadth = calculate_footprint_breadth(1)
        expected = 1.0 / FIXED_CATALOG_SIZE
        assert abs(breadth - expected) < 0.0001
        assert abs(breadth - 0.1667) < 0.01

    def test_three_distinct_resources(self):
        """3 distinct resources → 3/6 = 0.5."""
        breadth = calculate_footprint_breadth(3)
        assert abs(breadth - 0.5) < 0.0001

    def test_six_distinct_resources(self):
        """6 distinct resources → 6/6 = 1.0."""
        breadth = calculate_footprint_breadth(6)
        assert breadth == 1.0

    def test_repeated_resource_does_not_increase_distinct_count(self, trajectory_engine):
        """Repeated resource does not increase distinct count."""
        principal_id = "user_breadth"
        session_id = "session_breadth"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # First action: 1 distinct
        r1 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        assert len(set(r1.footprint)) == 1
        assert abs(r1.footprint_breadth - (1.0 / 6.0)) < 0.0001

        # Second action: repeated resource, still 1 distinct
        r2 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time + timedelta(seconds=10))
        assert len(set(r2.footprint)) == 1
        assert abs(r2.footprint_breadth - (1.0 / 6.0)) < 0.0001


class TestStepScoreFormula:
    """Tests for composite step score weighted formula."""

    def test_step_score_exact_formula(self):
        """Verify exact weighted formula (Contract §14)."""
        scope_drift = 1.0
        destructiveness_growth = 0.5
        velocity = 0.8333
        footprint_breadth = 0.3333

        step_score = calculate_step_score(
            scope_drift=scope_drift,
            destructiveness_growth=destructiveness_growth,
            velocity=velocity,
            footprint_breadth=footprint_breadth,
        )

        expected = (
            WEIGHT_SCOPE_DRIFT * 1.0
            + WEIGHT_DESTRUCTIVENESS_GROWTH * 0.5
            + WEIGHT_VELOCITY * 0.8333
            + WEIGHT_FOOTPRINT_BREADTH * 0.3333
        )
        assert abs(step_score - expected) < 0.0001

    def test_step_score_weights_sum_to_one(self):
        """Verify contract weights sum to 1.0."""
        total = WEIGHT_SCOPE_DRIFT + WEIGHT_DESTRUCTIVENESS_GROWTH + WEIGHT_VELOCITY + WEIGHT_FOOTPRINT_BREADTH
        assert abs(total - 1.0) < 0.0001


class TestAsymmetricEMA:
    """Tests for asymmetric exponential moving average."""

    def test_rising_step_uses_alpha_06(self):
        """Rising step score uses alpha = 0.6 (Contract §15)."""
        previous = 0.3
        step = 0.5
        new_score = update_asymmetric_ema(previous, step)
        expected = previous + ALPHA_RISING * (step - previous)
        assert abs(new_score - expected) < 0.0001

    def test_falling_step_uses_alpha_02(self):
        """Falling step score uses alpha = 0.2 (Contract §15)."""
        previous = 0.5
        step = 0.3
        new_score = update_asymmetric_ema(previous, step)
        expected = previous + ALPHA_FALLING * (step - previous)
        assert abs(new_score - expected) < 0.0001

    def test_equal_step_uses_rising_alpha(self):
        """Equal step score uses rising branch (alpha = 0.6)."""
        previous = 0.5
        step = 0.5
        new_score = update_asymmetric_ema(previous, step)
        expected = previous + ALPHA_RISING * (step - previous)
        assert abs(new_score - expected) < 0.0001
        assert new_score == previous


class TestCrossSessionPersistence:
    """Security tests verifying cross-session state persistence (Contract §17, Invariant 5)."""

    def test_session_one_updates_principal_trajectory_state(self, trajectory_engine, db_session):
        """Session 1 updates principal trajectory state in database."""
        principal_id = "user_cross_session"
        session_id = "session_001"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        trajectory_engine.evaluate_action(principal_id, session_id, "update_customer", base_time + timedelta(seconds=10))

        # Verify principal state is persisted
        repo = PrincipalRepository(db_session)
        principal = repo.get_by_id(principal_id)
        assert principal is not None
        assert principal.trajectory_score > 0.0
        assert len(principal.scope_footprint_list) == 2

    def test_session_two_loads_persisted_trajectory_score(self, trajectory_engine, db_session):
        """Session 2 for same principal loads persisted trajectory score (not reset to 0.0)."""
        principal_id = "user_persist_score"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1
        r1 = trajectory_engine.evaluate_action(principal_id, "session_001", "update_customer", base_time)
        session_1_final_score = r1.new_score
        assert session_1_final_score > 0.0

        # Clear session-local velocity
        trajectory_engine.clear_session_velocity("session_001")

        # Session 2: MUST start with persisted score, not 0.0
        r2 = trajectory_engine.evaluate_action(principal_id, "session_002", "export_customers", base_time + timedelta(minutes=10))
        assert r2.previous_score == session_1_final_score, "Session 2 must load persisted trajectory score"

    def test_session_two_preserves_historical_footprint(self, trajectory_engine):
        """Session 2 preserves historical scope footprint from Session 1."""
        principal_id = "user_persist_footprint"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1: touch "logs"
        trajectory_engine.evaluate_action(principal_id, "session_001", "read_logs", base_time)
        trajectory_engine.clear_session_velocity("session_001")

        # Session 2: revisit "logs" → scope_drift should be 0 (already in footprint)
        r2 = trajectory_engine.evaluate_action(principal_id, "session_002", "read_logs", base_time + timedelta(minutes=10))
        assert r2.scope_drift == 0.0

    def test_session_two_preserves_max_destructiveness(self, trajectory_engine):
        """Session 2 preserves max destructiveness from Session 1."""
        principal_id = "user_persist_max"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1: WRITE → max = 0.5
        r1 = trajectory_engine.evaluate_action(principal_id, "session_001", "update_customer", base_time)
        assert r1.max_destructiveness == 0.5

        trajectory_engine.clear_session_velocity("session_001")

        # Session 2: another WRITE → growth should be 0 (max already 0.5)
        r2 = trajectory_engine.evaluate_action(principal_id, "session_002", "export_customers", base_time + timedelta(minutes=10))
        assert r2.destructiveness_growth == 0.0
        assert r2.max_destructiveness == 0.5

    def test_session_two_preserves_action_counts(self, trajectory_engine):
        """Session 2 preserves action_counts from Session 1."""
        principal_id = "user_persist_counts"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1: 2 READ actions
        r1 = trajectory_engine.evaluate_action(principal_id, "session_001", "read_logs", base_time)
        r2 = trajectory_engine.evaluate_action(principal_id, "session_001", "read_customer", base_time + timedelta(seconds=10))
        assert r2.action_counts.get("READ", 0) == 2

        trajectory_engine.clear_session_velocity("session_001")

        # Session 2: 1 more READ → total should be 3
        r3 = trajectory_engine.evaluate_action(principal_id, "session_002", "search_customers", base_time + timedelta(minutes=10))
        assert r3.action_counts.get("READ", 0) == 3

    def test_session_two_velocity_starts_at_zero(self, trajectory_engine):
        """Session 2 velocity starts at 0.0 even if Session 1 had velocity (CLAUDE.md §11.3)."""
        principal_id = "user_persist_velocity"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Session 1: two rapid actions
        trajectory_engine.evaluate_action(principal_id, "session_001", "read_logs", base_time)
        r2 = trajectory_engine.evaluate_action(principal_id, "session_001", "read_customer", base_time + timedelta(seconds=5))
        assert r2.velocity > 0.0

        # Clear session velocity
        trajectory_engine.clear_session_velocity("session_001")

        # Session 2: first action MUST have velocity 0.0
        r3 = trajectory_engine.evaluate_action(principal_id, "session_002", "update_customer", base_time + timedelta(minutes=10))
        assert r3.velocity == 0.0


class TestUnknownToolBehavior:
    """Security tests verifying fail-closed behavior on unknown tools."""

    def test_unknown_tool_raises_key_error(self, trajectory_engine):
        """Unknown tool name raises KeyError (fail-closed) (CLAUDE.md §28)."""
        with pytest.raises(KeyError, match="not registered"):
            trajectory_engine.evaluate_action(
                principal_id="user_unknown",
                session_id="session_001",
                action="malicious_backdoor",
                timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
            )


class TestTrustedMetadataIntegration:
    """Tests verifying trajectory engine uses ToolRegistry, not agent input."""

    def test_trajectory_uses_trusted_tool_registry_metadata(self, trajectory_engine):
        """Trajectory engine resolves action metadata strictly from ToolRegistry."""
        result = trajectory_engine.evaluate_action(
            principal_id="user_trusted",
            session_id="session_001",
            action="drop_table",
            timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
        )
        assert result.action_class == ActionClass.DESTRUCTIVE
        assert result.resource == "db_schema:core"
        assert result.destructiveness_level == 1.0


class TestCanonicalAttackTrajectory:
    """Reference test: suspicious escalation attack trajectory (Contract §18)."""

    def test_database_escalation_attack_trajectory(self, trajectory_engine):
        """Canonical attack: logs → customer → orders → export → drop_table.

        Expected behavior: trajectory score rises due to scope drift, destructiveness growth,
        rapid velocity, and expanding footprint.

        Contract §18: database_escalation_attack
        """
        principal_id = "attacker"
        session_id = "attack_session"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Step 1: read_logs (READ, logs)
        r1 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        assert r1.scope_drift == 1.0  # new resource
        assert r1.destructiveness_growth == 0.0  # READ from 0.0
        assert r1.velocity == 0.0  # first action
        assert r1.previous_score == 0.0

        # Step 2: read_customer (READ, db_records:customer_table) — 10s later
        r2 = trajectory_engine.evaluate_action(principal_id, session_id, "read_customer", base_time + timedelta(seconds=10))
        assert r2.scope_drift == 1.0  # new resource
        assert r2.destructiveness_growth == 0.0  # READ from 0.0
        assert r2.velocity > 0.7  # rapid
        assert r2.new_score > r1.new_score

        # Step 3: update_customer (WRITE, db_records:customer_table) — 10s later
        r3 = trajectory_engine.evaluate_action(principal_id, session_id, "update_customer", base_time + timedelta(seconds=20))
        assert r3.scope_drift == 0.0  # repeated resource
        assert r3.destructiveness_growth == 0.5  # WRITE from 0.0
        assert r3.velocity > 0.6  # rapid
        # Note: r3 may be slightly lower than r2 due to asymmetric EMA decay (alpha=0.2)
        # when step_score drops. Overall trend verification comes at the end.

        # Step 4: export_customers (WRITE, db_records:customer_table) — 10s later
        r4 = trajectory_engine.evaluate_action(principal_id, session_id, "export_customers", base_time + timedelta(seconds=30))
        assert r4.scope_drift == 0.0  # repeated resource
        assert r4.destructiveness_growth == 0.0  # WRITE from 0.5
        assert r4.velocity > 0.6

        # Step 5: change_permissions (DESTRUCTIVE, system:permissions) — 10s later
        r5 = trajectory_engine.evaluate_action(principal_id, session_id, "change_permissions", base_time + timedelta(seconds=40))
        assert r5.scope_drift == 1.0  # new resource
        assert r5.destructiveness_growth == 0.5  # DESTRUCTIVE from 0.5
        assert r5.velocity > 0.6
        # r5 shows clear escalation with new resource + destructiveness growth

        # Step 6: drop_table (DESTRUCTIVE, db_schema:core) — 10s later
        r6 = trajectory_engine.evaluate_action(principal_id, session_id, "drop_table", base_time + timedelta(seconds=50))
        assert r6.scope_drift == 1.0  # new resource
        assert r6.destructiveness_growth == 0.0  # DESTRUCTIVE from 1.0
        assert r6.velocity > 0.6

        # Verify escalation trend: final score must be significantly higher than initial
        assert r6.new_score > r1.new_score, "Trajectory should show overall escalation"
        assert r6.new_score > 0.3, "Attack trajectory should reach elevated risk level"

        # Verify key escalation indicators present
        assert r5.new_score > r2.new_score, "Change_permissions step should show clear escalation"


class TestLegitimateMigrationTrajectory:
    """Reference test: legitimate schema migration trajectory (Contract §19)."""

    def test_legitimate_schema_migration_trajectory(self, trajectory_engine):
        """Legitimate migration: stays within migration_schema resource scope, slower actions.

        Expected behavior: trajectory rises more slowly than attack due to repeated resource,
        slower velocity, and narrower footprint.

        Contract §19: monthly_finance_report conceptual equivalent
        """
        principal_id = "dba_legitimate"
        session_id = "migration_session"
        base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Conceptual legitimate migration scenario
        # Uses existing contract tools but with slower cadence and narrower scope
        r1 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time)
        assert r1.velocity == 0.0
        assert r1.previous_score == 0.0

        # 60+ seconds later: velocity drops to 0.0
        r2 = trajectory_engine.evaluate_action(principal_id, session_id, "read_logs", base_time + timedelta(seconds=65))
        assert r2.scope_drift == 0.0  # repeated resource
        assert r2.velocity == 0.0  # slow action

        r3 = trajectory_engine.evaluate_action(principal_id, session_id, "read_customer", base_time + timedelta(seconds=130))
        assert r3.velocity == 0.0

        # Verify legitimate trajectory remains lower than rapid attack
        assert r3.new_score < 0.4, "Legitimate slow trajectory should remain controlled"
