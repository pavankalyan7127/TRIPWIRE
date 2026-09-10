"""Comprehensive tests for Phase A11: Audit & Trajectory Read APIs.

Validates:
1. GET /api/v1/sessions/{session_id}/trajectory
   - Response structure (session_id, principal_id, trajectory_score, risk_band, events)
   - Sequential 1-based step indexing for events
   - Correct trajectory event schemas (step, action, resource, reversibility, trajectory_score, risk_band, decision)
   - Empty session behavior (0 actions, correct initial score and risk band)
   - Multi-action progression
   - Fail-closed 404 on nonexistent session
   - Strictly read-only & idempotent (no state mutation, no score changes, no audit creation)
   - Session isolation (events never leak across sessions)

2. GET /api/v1/audit/{session_id}
   - Response structure (session_id, events)
   - Complete audit event lifecycle fields (execution_status, approved_by, executed_at, parameters)
   - Proposed-only action lifecycle (NOT_EXECUTED, approved_by=None, executed_at=None)
   - Confirmed & executed action lifecycle (EXECUTED, approved_by="...", executed_at populated)
   - Confirmed but revalidation blocked lifecycle (NOT_EXECUTED, approved_by="...", executed_at=None)
   - Empty session behavior (200 with empty events)
   - Fail-closed 404 on nonexistent session
   - Deterministic chronological ordering (timestamp.asc(), id.asc())
   - Strictly read-only & idempotent
   - Session data isolation

3. Cross-Session Consistency
   - Cross-session score inheritance reflection in trajectory endpoint
   - Complete audit isolation between consecutive sessions for the same principal
   - Complete isolation between multiple principals

4. Security Invariants
   - ToolExecutionGate is never invoked during GET calls
   - Principal and Session database records remain completely unmutated
"""

from datetime import datetime, timezone
import pytest

from app.db.models import AuditEventModel, PrincipalModel, SessionModel
from app.models.enums import ActionClass, Decision, RiskBand
from app.security.execution_gate import get_execution_gate


class TestTrajectoryReadAPI:
    """Tests for GET /api/v1/sessions/{session_id}/trajectory."""

    def test_trajectory_empty_session_returns_200_and_defaults(self, client_with_db):
        """Newly created session with 0 actions returns 200 with empty events list."""
        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_empty_traj", "agent_id": "agent_001"},
        )
        assert resp.status_code == 201
        session_id = resp.json()["session_id"]

        traj_resp = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
        assert traj_resp.status_code == 200
        data = traj_resp.json()

        assert data["session_id"] == session_id
        assert data["principal_id"] == "user_empty_traj"
        assert data["trajectory_score"] == 0.0
        assert data["risk_band"] == "LOW"
        assert data["events"] == []

    def test_trajectory_multi_action_progression_sequential_steps(self, client_with_db, db_session):
        """Multi-action session returns correct 1-based sequential steps and event details."""
        principal = PrincipalModel(
            id="user_seq_test",
            scope="logs:read,customer:read,customer:write,schema:admin",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_seq_test", "agent_id": "agent_001"},
        )
        session_id = session_resp.json()["session_id"]

        actions = [
            ("read_logs", "logs"),
            ("search_customers", "db_records:customer_table"),
            ("read_customer", "db_records:customer_table"),
        ]

        for action, resource in actions:
            prop_resp = client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_seq_test",
                    "session_id": session_id,
                    "agent_id": "agent_001",
                    "action": action,
                    "resource": resource,
                },
            )
            assert prop_resp.status_code == 200

        traj_resp = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
        assert traj_resp.status_code == 200
        data = traj_resp.json()

        assert data["session_id"] == session_id
        assert data["principal_id"] == "user_seq_test"
        assert len(data["events"]) == 3

        for idx, event in enumerate(data["events"]):
            expected_step = idx + 1
            assert event["step"] == expected_step
            assert event["action"] == actions[idx][0]
            assert event["resource"] == actions[idx][1]
            assert event["reversibility"] in ["READ", "WRITE", "DESTRUCTIVE"]
            assert 0.0 <= event["trajectory_score"] <= 1.0
            assert event["risk_band"] in ["LOW", "MEDIUM", "HIGH"]
            assert event["decision"] in ["ALLOW", "CONFIRM", "HARD_CONFIRM", "BLOCK"]

    def test_trajectory_nonexistent_session_returns_404(self, client_with_db):
        """Querying trajectory for nonexistent session returns 404."""
        response = client_with_db.get("/api/v1/sessions/session_does_not_exist/trajectory")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_trajectory_strictly_read_only_and_idempotent(self, client_with_db, db_session):
        """Calling GET trajectory multiple times does not alter any database state."""
        principal = PrincipalModel(
            id="user_idempotent_traj",
            scope="logs:read",
            trajectory_score=0.22,
        )
        db_session.add(principal)
        db_session.commit()

        session_resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_idempotent_traj", "agent_id": "agent_001"},
        )
        session_id = session_resp.json()["session_id"]

        # Propose one action
        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_idempotent_traj",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )

        db_session.expire_all()
        principal_before = db_session.query(PrincipalModel).filter_by(id="user_idempotent_traj").first()
        session_before = db_session.query(SessionModel).filter_by(id=session_id).first()
        audit_count_before = db_session.query(AuditEventModel).filter_by(session_id=session_id).count()

        # Call GET trajectory 5 times
        for _ in range(5):
            res = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
            assert res.status_code == 200

        db_session.expire_all()
        principal_after = db_session.query(PrincipalModel).filter_by(id="user_idempotent_traj").first()
        session_after = db_session.query(SessionModel).filter_by(id=session_id).first()
        audit_count_after = db_session.query(AuditEventModel).filter_by(session_id=session_id).count()

        assert principal_before.trajectory_score == principal_after.trajectory_score
        assert session_before.trajectory_score == session_after.trajectory_score
        assert audit_count_before == audit_count_after

    def test_trajectory_session_isolation(self, client_with_db, db_session):
        """Events from Session 1 do not leak into Session 2 for the same principal."""
        principal = PrincipalModel(
            id="user_iso_traj",
            scope="logs:read,customer:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        s1_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_iso_traj", "agent_id": "agent_001"},
        ).json()["session_id"]

        s2_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_iso_traj", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Action only in session 1
        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_iso_traj",
                "session_id": s1_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )

        traj1 = client_with_db.get(f"/api/v1/sessions/{s1_id}/trajectory").json()
        traj2 = client_with_db.get(f"/api/v1/sessions/{s2_id}/trajectory").json()

        assert len(traj1["events"]) == 1
        assert traj1["events"][0]["action"] == "read_logs"
        assert len(traj2["events"]) == 0


class TestAuditReadAPI:
    """Tests for GET /api/v1/audit/{session_id}."""

    def test_audit_empty_session_returns_200_empty_events(self, client_with_db):
        """Empty session returns 200 with empty events list."""
        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_empty_audit", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]

        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        data = audit_resp.json()
        assert data["session_id"] == session_id
        assert data["events"] == []

    def test_audit_nonexistent_session_returns_404(self, client_with_db):
        """Audit for nonexistent session returns 404."""
        response = client_with_db.get("/api/v1/audit/session_nonexistent_12345")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_audit_proposed_only_actions_have_not_executed_lifecycle(self, client_with_db, db_session):
        """Proposed actions show execution_status='NOT_EXECUTED' and contain action parameters."""
        principal = PrincipalModel(
            id="user_prop_audit",
            scope="logs:read,customer:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_prop_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        params = {"filter": "ERROR", "limit": 50}
        prop_resp = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_prop_audit",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
                "parameters": params,
            },
        )
        action_id = prop_resp.json()["action_id"]

        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        data = audit_resp.json()
        assert len(data["events"]) == 1
        event = data["events"][0]

        assert event["action_id"] == action_id
        assert event["principal_id"] == "user_prop_audit"
        assert event["session_id"] == session_id
        assert event["agent_id"] == "agent_001"
        assert event["action"] == "read_logs"
        assert event["resource"] == "logs"
        assert event["reversibility"] == "READ"
        assert event["decision"] == "ALLOW"
        assert event["execution_status"] == "NOT_EXECUTED"
        assert event["approved_by"] is None
        assert event["executed_at"] is None
        assert event["parameters"] == params
        assert event["timestamp"] is not None

    def test_audit_confirmed_and_executed_action_lifecycle(self, client_with_db, db_session):
        """Confirmed and executed actions reflect execution_status='EXECUTED' with approver and timestamp."""
        principal = PrincipalModel(
            id="user_exec_audit",
            scope="customer:write,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_exec_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Propose destructive action requiring confirmation
        prop_resp = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_exec_audit",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
                "parameters": {"target_user": "bob", "role": "admin"},
            },
        )
        action_id = prop_resp.json()["action_id"]
        assert prop_resp.json()["decision"] in ["CONFIRM", "HARD_CONFIRM"]

        # Confirm the action
        confirm_resp = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "security_admin_alice"},
        )
        assert confirm_resp.status_code == 200
        assert confirm_resp.json()["execution_status"] == "EXECUTED"

        # Check GET /audit
        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        data = audit_resp.json()
        assert len(data["events"]) == 1
        event = data["events"][0]

        assert event["action_id"] == action_id
        assert event["execution_status"] == "EXECUTED"
        assert event["approved_by"] == "security_admin_alice"
        assert event["executed_at"] is not None
        assert event["parameters"] == {"target_user": "bob", "role": "admin"}

    def test_audit_confirmed_but_blocked_revalidation_lifecycle(self, client_with_db, db_session):
        """Confirmed action that gets BLOCKED on revalidation reflects NOT_EXECUTED with approver recorded."""
        principal = PrincipalModel(
            id="user_block_audit",
            scope="permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_block_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Propose action
        prop_resp = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_block_audit",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        )
        action_id = prop_resp.json()["action_id"]

        # Elevate principal trajectory score to HIGH (0.80) to force revalidation BLOCK
        principal.trajectory_score = 0.80
        db_session.commit()

        # Confirm the action -> should be BLOCKED and NOT_EXECUTED
        confirm_resp = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_bob"},
        )
        assert confirm_resp.status_code == 200
        assert confirm_resp.json()["decision"] == "BLOCK"
        assert confirm_resp.json()["execution_status"] == "NOT_EXECUTED"

        # Check GET /audit
        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        event = audit_resp.json()["events"][0]
        assert event["action_id"] == action_id
        assert event["execution_status"] == "NOT_EXECUTED"
        assert event["approved_by"] == "admin_bob"
        assert event["executed_at"] is None

    def test_audit_deterministic_chronological_ordering(self, client_with_db, db_session):
        """Audit events are returned in strict chronological order with secondary tie-breaking."""
        principal = PrincipalModel(
            id="user_order_test",
            scope="logs:read,customer:read,customer:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_order_test", "agent_id": "agent_001"},
        ).json()["session_id"]

        action_names = ["read_logs", "search_customers", "read_customer", "update_customer"]
        for action in action_names:
            client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_order_test",
                    "session_id": session_id,
                    "agent_id": "agent_001",
                    "action": action,
                    "resource": "logs" if action == "read_logs" else "db_records:customer_table",
                },
            )

        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        events = audit_resp.json()["events"]
        assert len(events) == 4
        for idx, expected_action in enumerate(action_names):
            assert events[idx]["action"] == expected_action

    def test_audit_strictly_read_only_and_idempotent(self, client_with_db, db_session):
        """Calling GET audit multiple times does not alter any database state."""
        principal = PrincipalModel(
            id="user_idempotent_audit",
            scope="logs:read",
            trajectory_score=0.15,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_idempotent_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_idempotent_audit",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )

        db_session.expire_all()
        events_count_before = db_session.query(AuditEventModel).filter_by(session_id=session_id).count()

        for _ in range(5):
            res = client_with_db.get(f"/api/v1/audit/{session_id}")
            assert res.status_code == 200
            assert len(res.json()["events"]) == 1

        db_session.expire_all()
        events_count_after = db_session.query(AuditEventModel).filter_by(session_id=session_id).count()
        assert events_count_before == events_count_after

    def test_audit_session_isolation(self, client_with_db, db_session):
        """Audit events from Session 1 do not appear in Session 2."""
        principal = PrincipalModel(
            id="user_iso_audit",
            scope="logs:read,customer:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        s1_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_iso_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        s2_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_iso_audit", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Action in session 1
        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_iso_audit",
                "session_id": s1_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )

        # Action in session 2
        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_iso_audit",
                "session_id": s2_id,
                "agent_id": "agent_001",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        )

        a1 = client_with_db.get(f"/api/v1/audit/{s1_id}").json()
        a2 = client_with_db.get(f"/api/v1/audit/{s2_id}").json()

        assert len(a1["events"]) == 1
        assert a1["events"][0]["action"] == "read_logs"
        assert a1["events"][0]["session_id"] == s1_id

        assert len(a2["events"]) == 1
        assert a2["events"][0]["action"] == "read_customer"
        assert a2["events"][0]["session_id"] == s2_id


class TestCrossSessionAndPrincipalConsistency:
    """Tests for cross-session inheritance and multi-principal isolation."""

    def test_cross_session_score_inheritance_in_trajectory(self, client_with_db, db_session):
        """Session 2 inherits principal's trajectory score; GET /trajectory reflects it accurately."""
        principal = PrincipalModel(
            id="user_cross_session",
            scope="logs:read,customer:read",
            trajectory_score=0.55,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_cross_session", "agent_id": "agent_001"},
        ).json()["session_id"]

        traj_resp = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
        assert traj_resp.status_code == 200
        data = traj_resp.json()

        assert data["trajectory_score"] == 0.55
        assert data["risk_band"] == "MEDIUM"
        assert data["events"] == []

    def test_multi_principal_session_isolation(self, client_with_db, db_session):
        """Sessions of distinct principals are strictly isolated in trajectory and audit responses."""
        p1 = PrincipalModel(id="user_alpha", scope="logs:read", trajectory_score=0.1)
        p2 = PrincipalModel(id="user_beta", scope="customer:read", trajectory_score=0.2)
        db_session.add_all([p1, p2])
        db_session.commit()

        s_alpha = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_alpha", "agent_id": "agent_alpha"},
        ).json()["session_id"]

        s_beta = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_beta", "agent_id": "agent_beta"},
        ).json()["session_id"]

        client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_alpha",
                "session_id": s_alpha,
                "agent_id": "agent_alpha",
                "action": "read_logs",
                "resource": "logs",
            },
        )

        audit_alpha = client_with_db.get(f"/api/v1/audit/{s_alpha}").json()
        audit_beta = client_with_db.get(f"/api/v1/audit/{s_beta}").json()

        assert len(audit_alpha["events"]) == 1
        assert audit_alpha["events"][0]["principal_id"] == "user_alpha"

        assert len(audit_beta["events"]) == 0


class TestSecurityInvariantsReadAPIs:
    """Security invariants: GET endpoints never execute tools or mutate security state."""

    def test_get_endpoints_do_not_execute_tools(self, client_with_db, db_session):
        """GET trajectory and GET audit never call the execution gate."""
        from app.main import app
        from app.security.execution_gate import ToolExecutionGate, get_execution_gate
        from app.security.mock_tools import MockToolExecutionRecorder

        recorder = MockToolExecutionRecorder()
        test_gate = ToolExecutionGate(recorder=recorder)
        app.dependency_overrides[get_execution_gate] = lambda: test_gate

        try:
            principal = PrincipalModel(
                id="user_gate_test",
                scope="logs:read",
                trajectory_score=0.0,
            )
            db_session.add(principal)
            db_session.commit()

            session_id = client_with_db.post(
                "/api/v1/sessions",
                json={"principal_id": "user_gate_test", "agent_id": "agent_001"},
            ).json()["session_id"]

            # Propose action
            client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_gate_test",
                    "session_id": session_id,
                    "agent_id": "agent_001",
                    "action": "read_logs",
                    "resource": "logs",
                },
            )
            # Proposal does not execute tools
            assert len(recorder.records) == 0

            # Read trajectory and audit multiple times
            client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
            client_with_db.get(f"/api/v1/audit/{session_id}")

            # Gate still has zero execution records
            assert len(recorder.records) == 0
        finally:
            app.dependency_overrides.pop(get_execution_gate, None)
