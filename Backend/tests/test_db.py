"""Persistence and database tests for Tripwire.

Tests verify:
- Database foundation (engine, tables, sessions)
- Principal persistence and cross-session trajectory state
- Session persistence and relationships
- Audit event persistence and round-tripping
- Structured field serialization (JSON)
- Isolation from developer's local database
"""

import json
from datetime import datetime, timezone

import pytest

from app.db.models import AuditEventModel, PrincipalModel, SessionModel
from app.db.repositories.audit import AuditRepository
from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.db.session import init_db


class TestDatabaseFoundation:
    """Tests for database initialization and connectivity."""

    def test_tables_created(self, db_engine):
        """All three contract tables must exist in the database."""
        from sqlalchemy import inspect

        inspector = inspect(db_engine)
        tables = inspector.get_table_names()
        assert "principals" in tables
        assert "sessions" in tables
        assert "audit_events" in tables

    def test_init_db_safe_to_call_multiple_times(self, db_engine):
        """init_db should be idempotent (safe to call repeatedly)."""
        # Should not raise any errors
        init_db(db_engine)
        init_db(db_engine)


class TestPrincipalRepository:
    """Tests for PrincipalRepository persistence operations."""

    def test_create_principal(self, db_session):
        """Can create a principal with default trajectory state."""
        repo = PrincipalRepository(db_session)
        principal = repo.create(principal_id="user_001", role="analyst", scope="customer:read")

        assert principal.id == "user_001"
        assert principal.role == "analyst"
        assert principal.scope == "customer:read"
        assert principal.trajectory_score == 0.0
        assert principal.max_destructiveness == 0.0
        assert principal.scope_footprint_list == []
        assert principal.action_counts_dict == {}
        assert principal.risk_band == "LOW"

    def test_get_by_id(self, db_session):
        """Can retrieve an existing principal by ID."""
        repo = PrincipalRepository(db_session)
        repo.create(principal_id="user_002")

        found = repo.get_by_id("user_002")
        assert found is not None
        assert found.id == "user_002"

        not_found = repo.get_by_id("nonexistent")
        assert not_found is None

    def test_get_or_create_existing(self, db_session):
        """get_or_create returns existing principal without modifying it."""
        repo = PrincipalRepository(db_session)
        created = repo.create(principal_id="user_003", role="admin")

        retrieved = repo.get_or_create(principal_id="user_003", role="user")
        assert retrieved.id == created.id
        assert retrieved.role == "admin"  # preserved, not overwritten

    def test_get_or_create_new(self, db_session):
        """get_or_create creates new principal if not exists."""
        repo = PrincipalRepository(db_session)
        principal = repo.get_or_create(principal_id="user_004", role="developer")
        assert principal.id == "user_004"
        assert principal.role == "developer"

    def test_update_trajectory_state(self, db_session):
        """Can update principal's persistent trajectory state."""
        repo = PrincipalRepository(db_session)
        repo.create(principal_id="user_005")

        updated = repo.update_trajectory_state(
            principal_id="user_005",
            trajectory_score=0.45,
            scope_footprint=["logs", "db_records:customer_table"],
            max_destructiveness=0.5,
            action_counts={"READ": 2, "WRITE": 1},
        )

        assert updated is not None
        assert updated.trajectory_score == 0.45
        assert updated.risk_band == "MEDIUM"
        assert updated.scope_footprint_list == ["logs", "db_records:customer_table"]
        assert updated.max_destructiveness == 0.5
        assert updated.action_counts_dict == {"READ": 2, "WRITE": 1}

    def test_persisted_state_survives_new_db_session(self, db_engine):
        """Persisted principal state survives closing and reopening a session."""
        from sqlalchemy.orm import sessionmaker

        SessionMaker = sessionmaker(bind=db_engine)

        # Session 1: create and update
        session1 = SessionMaker()
        repo1 = PrincipalRepository(session1)
        repo1.create(principal_id="user_persist")
        repo1.update_trajectory_state(
            principal_id="user_persist",
            trajectory_score=0.72,
            scope_footprint=["logs", "system:permissions"],
            max_destructiveness=1.0,
            action_counts={"READ": 1, "DESTRUCTIVE": 1},
        )
        session1.close()

        # Session 2: retrieve from fresh DB session
        session2 = SessionMaker()
        repo2 = PrincipalRepository(session2)
        loaded = repo2.get_by_id("user_persist")

        assert loaded is not None
        assert loaded.trajectory_score == 0.72
        assert loaded.risk_band == "HIGH"
        assert loaded.scope_footprint_list == ["logs", "system:permissions"]
        assert loaded.max_destructiveness == 1.0
        assert loaded.action_counts_dict == {"READ": 1, "DESTRUCTIVE": 1}
        session2.close()


class TestSessionRepository:
    """Tests for SessionRepository persistence operations."""

    def test_create_session(self, db_session):
        """Can create a session associated with a principal."""
        principal_repo = PrincipalRepository(db_session)
        principal_repo.create(principal_id="user_006")

        session_repo = SessionRepository(db_session)
        session = session_repo.create(
            session_id="session_001",
            principal_id="user_006",
            agent_id="agent_001",
            trajectory_score=0.0,
        )

        assert session.id == "session_001"
        assert session.principal_id == "user_006"
        assert session.agent_id == "agent_001"
        assert session.trajectory_score == 0.0
        assert session.started_at is not None
        assert session.ended_at is None
        assert session.risk_band == "LOW"

    def test_get_session_by_id(self, db_session):
        """Can retrieve a session by ID."""
        PrincipalRepository(db_session).create("user_007")
        repo = SessionRepository(db_session)
        repo.create(session_id="session_002", principal_id="user_007", agent_id="agent_001")

        found = repo.get_by_id("session_002")
        assert found is not None
        assert found.id == "session_002"

        not_found = repo.get_by_id("nonexistent")
        assert not_found is None

    def test_update_trajectory_score(self, db_session):
        """Can update session's trajectory score."""
        PrincipalRepository(db_session).create("user_008")
        repo = SessionRepository(db_session)
        repo.create(session_id="session_003", principal_id="user_008", agent_id="agent_001")

        updated = repo.update_trajectory_score("session_003", 0.58)
        assert updated is not None
        assert updated.trajectory_score == 0.58
        assert updated.risk_band == "MEDIUM"

    def test_end_session(self, db_session):
        """Can mark a session as ended."""
        PrincipalRepository(db_session).create("user_009")
        repo = SessionRepository(db_session)
        repo.create(session_id="session_004", principal_id="user_009", agent_id="agent_001")

        ended = repo.end_session("session_004")
        assert ended is not None
        assert ended.ended_at is not None

    def test_session_principal_relationship(self, db_session):
        """Session correctly references its Principal and vice versa."""
        PrincipalRepository(db_session).create("user_rel")
        repo = SessionRepository(db_session)
        repo.create(session_id="session_rel_1", principal_id="user_rel", agent_id="agent_001")
        repo.create(session_id="session_rel_2", principal_id="user_rel", agent_id="agent_002")

        principal = PrincipalRepository(db_session).get_by_id("user_rel")
        assert len(principal.sessions) == 2
        assert {s.id for s in principal.sessions} == {"session_rel_1", "session_rel_2"}


class TestAuditRepository:
    """Tests for AuditRepository persistence operations."""

    def test_create_audit_event(self, db_session):
        """Can create an audit event matching contract §6, §21."""
        PrincipalRepository(db_session).create("user_audit")
        SessionRepository(db_session).create("session_audit", "user_audit", "agent_001")

        repo = AuditRepository(db_session)
        now = datetime(2026, 9, 10, 10, 0, 0)
        event = repo.create(
            action_id="action_001",
            principal_id="user_audit",
            session_id="session_audit",
            agent_id="agent_001",
            action="read_customer",
            resource="db_records:customer_table",
            reversibility="READ",
            trajectory_score=0.22,
            risk_band="LOW",
            decision="ALLOW",
            reason="Authorized read within permitted scope",
            timestamp=now,
        )

        assert event.id is not None
        assert event.action_id == "action_001"
        assert event.principal_id == "user_audit"
        assert event.session_id == "session_audit"
        assert event.agent_id == "agent_001"
        assert event.action == "read_customer"
        assert event.resource == "db_records:customer_table"
        assert event.reversibility == "READ"
        assert event.trajectory_score == 0.22
        assert event.risk_band == "LOW"
        assert event.decision == "ALLOW"
        assert event.reason == "Authorized read within permitted scope"
        assert event.timestamp == now

    def test_get_by_session_id(self, db_session):
        """Can retrieve audit events for a session in chronological order."""
        PrincipalRepository(db_session).create("user_audit_list")
        SessionRepository(db_session).create("session_audit_list", "user_audit_list", "agent_001")

        repo = AuditRepository(db_session)
        t1 = datetime(2026, 9, 10, 10, 0, 0)
        t2 = datetime(2026, 9, 10, 10, 1, 0)

        repo.create(
            action_id="action_001",
            principal_id="user_audit_list",
            session_id="session_audit_list",
            agent_id="agent_001",
            action="read_logs",
            resource="logs",
            reversibility="READ",
            trajectory_score=0.20,
            risk_band="LOW",
            decision="ALLOW",
            reason="Step 1",
            timestamp=t1,
        )
        repo.create(
            action_id="action_002",
            principal_id="user_audit_list",
            session_id="session_audit_list",
            agent_id="agent_001",
            action="read_customer",
            resource="db_records:customer_table",
            reversibility="READ",
            trajectory_score=0.37,
            risk_band="MEDIUM",
            decision="ALLOW",
            reason="Step 2",
            timestamp=t2,
        )

        events = repo.get_by_session_id("session_audit_list")
        assert len(events) == 2
        assert events[0].action_id == "action_001"
        assert events[1].action_id == "action_002"

    def test_get_by_action_id(self, db_session):
        """Can retrieve a specific audit event by action ID."""
        PrincipalRepository(db_session).create("user_audit_single")
        SessionRepository(db_session).create("session_audit_single", "user_audit_single", "agent_001")

        repo = AuditRepository(db_session)
        repo.create(
            action_id="action_target",
            principal_id="user_audit_single",
            session_id="session_audit_single",
            agent_id="agent_001",
            action="update_customer",
            resource="db_records:customer_table",
            reversibility="WRITE",
            trajectory_score=0.42,
            risk_band="MEDIUM",
            decision="CONFIRM",
            reason="Confirmation required",
        )

        found = repo.get_by_action_id("action_target")
        assert found is not None
        assert found.decision == "CONFIRM"
        assert found.reversibility == "WRITE"

        not_found = repo.get_by_action_id("nonexistent")
        assert not_found is None


class TestCrossSessionSecurityRequirement:
    """Security test: proves persistence foundation supports cross-session state (Invariant 6)."""

    def test_cross_session_trajectory_state_persists(self, db_engine):
        """Session 1 stores state -> Session 1 ends -> Session 2 starts -> state is preserved.

        Contract: §17, §20, Invariant 6
        """
        from sqlalchemy.orm import sessionmaker

        SessionMaker = sessionmaker(bind=db_engine)

        # === SESSION 1 ===
        db1 = SessionMaker()
        principal_repo1 = PrincipalRepository(db1)
        session_repo1 = SessionRepository(db1)

        # Principal begins first session
        principal = principal_repo1.create(principal_id="user_cross_session")
        s1 = session_repo1.create(
            session_id="session_001",
            principal_id="user_cross_session",
            agent_id="agent_001",
            trajectory_score=0.0,
        )

        # Actions occur during Session 1: trajectory rises to 0.45
        principal_repo1.update_trajectory_state(
            principal_id="user_cross_session",
            trajectory_score=0.45,
            scope_footprint=["logs", "db_records:customer_table"],
            max_destructiveness=0.5,
            action_counts={"READ": 2, "WRITE": 1},
        )
        session_repo1.update_trajectory_score("session_001", 0.45)
        session_repo1.end_session("session_001")
        db1.close()

        # === SESSION 2 ===
        # A new session begins for the SAME principal in a separate DB connection
        db2 = SessionMaker()
        principal_repo2 = PrincipalRepository(db2)
        session_repo2 = SessionRepository(db2)

        # Retrieve principal — trajectory state MUST NOT be reset to 0
        persisted_principal = principal_repo2.get_by_id("user_cross_session")

        assert persisted_principal is not None
        assert persisted_principal.trajectory_score == 0.45, "Trajectory score must persist across sessions"
        assert persisted_principal.risk_band == "MEDIUM", "Risk band must reflect persisted score"
        assert persisted_principal.scope_footprint_list == ["logs", "db_records:customer_table"]
        assert persisted_principal.max_destructiveness == 0.5
        assert persisted_principal.action_counts_dict == {"READ": 2, "WRITE": 1}

        # Create Session 2 seeded with the persisted score
        s2 = session_repo2.create(
            session_id="session_002",
            principal_id="user_cross_session",
            agent_id="agent_002",
            trajectory_score=persisted_principal.trajectory_score,  # Seeded from persisted state!
        )

        assert s2.trajectory_score == 0.45, "New session must be seeded with persisted score"
        assert s2.risk_band == "MEDIUM"

        # Verify Session 1 is marked ended and Session 2 is active
        s1_loaded = session_repo2.get_by_id("session_001")
        assert s1_loaded.ended_at is not None
        assert s2.ended_at is None

        db2.close()
