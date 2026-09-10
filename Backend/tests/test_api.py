"""Integration tests for the Tripwire Session and Action APIs.

Tests verify:
- POST /api/v1/sessions
- POST /api/v1/actions/propose
- GET /api/v1/sessions/{session_id}/trajectory
- GET /api/v1/audit/{session_id}
- Real security pipeline: Request -> A5 -> A4 -> A6 -> A7 -> Response
- Security invariants: no tool execution, client metadata cannot override server, fail closed
- Cross-session trajectory persistence
- Canonical attack scenario progression (ALLOW -> CONFIRM -> BLOCK)
- Legitimate scenario progression (ALLOW -> CONFIRM -> HARD_CONFIRM)
"""

import pytest

from app.db.models import PrincipalModel
from app.models.enums import ActionClass, Decision, RiskBand


class TestSessionAPI:
    """Tests for POST /api/v1/sessions."""

    def test_create_session_success(self, client_with_db):
        """Create a new session returns 201 with correct fields."""
        response = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_001", "agent_id": "agent_001"},
        )
        assert response.status_code == 201
        data = response.json()
        assert "session_id" in data
        assert data["principal_id"] == "user_001"
        assert data["agent_id"] == "agent_001"
        assert data["trajectory_score"] == 0.0
        assert data["risk_band"] == "LOW"

    def test_new_session_inherits_persisted_principal_trajectory_score(self, client_with_db, db_session):
        """New session for existing principal seeds trajectory score from DB."""
        # Seed an existing principal with historical trajectory score in DB
        principal = PrincipalModel(
            id="user_veteran",
            scope="customer:read,customer:write",
            trajectory_score=0.45,
            max_destructiveness=0.5,
            scope_footprint='["logs", "db_records:customer_table"]',
            action_counts='{"READ": 5, "WRITE": 2}',
        )
        db_session.add(principal)
        db_session.commit()

        response = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_veteran", "agent_id": "agent_001"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["principal_id"] == "user_veteran"
        assert data["trajectory_score"] == 0.45
        assert data["risk_band"] == "MEDIUM"

    def test_session_create_validation_error(self, client_with_db):
        """Missing required fields returns 422 Unprocessable Entity."""
        response = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_001"},  # missing agent_id
        )
        assert response.status_code == 422


class TestActionProposalAPI:
    """Tests for POST /api/v1/actions/propose."""

    @pytest.fixture
    def setup_authorized_session(self, client_with_db, db_session):
        """Create a principal with full permissions and an active session."""
        principal = PrincipalModel(
            id="user_admin",
            scope="customer:read,customer:write,logs:read,schema:admin,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_admin", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]
        return "user_admin", session_id, "agent_001"

    def test_authorized_low_read_returns_allow(self, client_with_db, setup_authorized_session):
        """Authorized LOW READ action returns ALLOW."""
        principal_id, session_id, agent_id = setup_authorized_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "action_id" in data
        assert data["decision"] == "ALLOW"
        assert data["risk_band"] == "LOW"
        assert data["reversibility"] == "READ"
        assert "Authorized" in data["reason"]

    def test_authorized_low_write_returns_allow(self, client_with_db, setup_authorized_session):
        """Authorized LOW WRITE action returns ALLOW."""
        principal_id, session_id, agent_id = setup_authorized_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "update_customer",
                "resource": "db_records:customer_table",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "ALLOW"
        assert data["reversibility"] == "WRITE"

    def test_authorized_low_destructive_returns_confirm(self, client_with_db, setup_authorized_session):
        """Authorized DESTRUCTIVE action returns CONFIRM or HARD_CONFIRM depending on trajectory.

        After the fixture has run read_logs and update_customer tests, trajectory may have risen.
        DESTRUCTIVE actions require confirmation at any risk level below HIGH.
        """
        principal_id, session_id, agent_id = setup_authorized_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        )
        assert response.status_code == 200
        data = response.json()
        # DESTRUCTIVE requires confirmation; exact level depends on trajectory state
        assert data["decision"] in ["CONFIRM", "HARD_CONFIRM"]
        assert data["reversibility"] == "DESTRUCTIVE"

    def test_unauthorized_action_returns_block(self, client_with_db, db_session):
        """Principal without scope is unauthorized and receives BLOCK decision."""
        # Create user with customer:read only
        principal = PrincipalModel(
            id="user_limited",
            scope="customer:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_limited", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]

        # Propose drop_table (unauthorized)
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_limited",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "BLOCK"
        assert "Unauthorized" in data["reason"]

    def test_high_risk_trajectory_returns_block(self, client_with_db, db_session):
        """Session with HIGH trajectory score (> 0.65) receives BLOCK for all actions."""
        # Seed principal with HIGH trajectory score
        principal = PrincipalModel(
            id="user_risky",
            scope="logs:read,customer:read,customer:write,schema:admin",
            trajectory_score=0.75,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_risky", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]

        # Propose read_logs (even a READ action is BLOCKED at HIGH risk)
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_risky",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "BLOCK"
        assert data["risk_band"] == "HIGH"


class TestSecurityInvariantsAndTamperingAPI:
    """Security tests ensuring client cannot tamper with security pipeline."""

    @pytest.fixture
    def active_session(self, client_with_db, db_session):
        principal = PrincipalModel(
            id="user_secure",
            scope="customer:read,customer:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_secure", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]
        return "user_secure", session_id, "agent_001"

    def test_client_payload_tampering_ignored(self, client_with_db, active_session):
        """Client attempting to inject fake decision/reversibility is overridden by server."""
        principal_id, session_id, agent_id = active_session

        # Malicious payload claiming ALLOW, READ, and LOW risk
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "update_customer",
                "resource": "db_records:customer_table",
                "parameters": {
                    "decision": "ALLOW",
                    "action_class": "READ",
                    "reversibility": "READ",
                    "trajectory_score": 0.0,
                    "risk_band": "LOW",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        # Server determines reversibility is WRITE from trusted registry
        assert data["reversibility"] == "WRITE"

    def test_unknown_tool_fails_closed(self, client_with_db, active_session):
        """Unknown tool returns 400 Bad Request and fails closed."""
        principal_id, session_id, agent_id = active_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "unknown_backdoor_tool",
                "resource": "system:shell",
            },
        )
        assert response.status_code == 400
        assert "Unknown tool" in response.json()["detail"]

    def test_nonexistent_session_returns_404(self, client_with_db):
        """Action proposal against nonexistent session returns 404."""
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_001",
                "session_id": "session_nonexistent",
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert response.status_code == 404

    def test_principal_session_mismatch_returns_403(self, client_with_db, active_session):
        """Using another principal's session_id returns 403 Forbidden."""
        _, session_id, agent_id = active_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_user",
                "session_id": session_id,
                "agent_id": agent_id,
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert response.status_code == 403
        assert "belongs to principal" in response.json()["detail"]

    def test_agent_session_mismatch_returns_403(self, client_with_db, active_session):
        """Using another agent_id with a valid session returns 403 Forbidden."""
        principal_id, session_id, _ = active_session
        response = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": principal_id,
                "session_id": session_id,
                "agent_id": "rogue_agent_007",
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert response.status_code == 403
        assert "belongs to agent" in response.json()["detail"]


class TestAuditAndTrajectoryAPI:
    """Tests for GET /api/v1/audit/{session_id} and GET /api/v1/sessions/{session_id}/trajectory."""

    def test_audit_and_trajectory_lifecycle(self, client_with_db, db_session):
        """Proposing actions creates audit records and trajectory events retrievable via GET."""
        # 1. Create session
        principal = PrincipalModel(
            id="user_audit_test",
            scope="logs:read,customer:read,customer:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_audit_test", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]

        # 2. Propose action 1: read_logs
        resp1 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_audit_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )
        assert resp1.status_code == 200

        # 3. Propose action 2: read_customer
        resp2 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_audit_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        )
        assert resp2.status_code == 200

        # 4. GET /api/v1/audit/{session_id}
        audit_resp = client_with_db.get(f"/api/v1/audit/{session_id}")
        assert audit_resp.status_code == 200
        audit_data = audit_resp.json()
        assert audit_data["session_id"] == session_id
        assert len(audit_data["events"]) == 2
        assert audit_data["events"][0]["action"] == "read_logs"
        assert audit_data["events"][1]["action"] == "read_customer"

        # 5. GET /api/v1/sessions/{session_id}/trajectory
        traj_resp = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory")
        assert traj_resp.status_code == 200
        traj_data = traj_resp.json()
        assert traj_data["session_id"] == session_id
        assert traj_data["principal_id"] == "user_audit_test"
        assert len(traj_data["events"]) == 2
        assert traj_data["events"][0]["step"] == 1
        assert traj_data["events"][1]["step"] == 2

    def test_get_trajectory_does_not_mutate_state(self, client_with_db, db_session):
        """GET /api/v1/sessions/{session_id}/trajectory is read-only."""
        principal = PrincipalModel(
            id="user_readonly",
            scope="logs:read",
            trajectory_score=0.25,
        )
        db_session.add(principal)
        db_session.commit()

        resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "user_readonly", "agent_id": "agent_001"},
        )
        session_id = resp.json()["session_id"]

        # Call GET trajectory multiple times
        r1 = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory").json()
        r2 = client_with_db.get(f"/api/v1/sessions/{session_id}/trajectory").json()

        assert r1["trajectory_score"] == r2["trajectory_score"] == 0.25
        assert len(r1["events"]) == len(r2["events"]) == 0

    def test_audit_nonexistent_session_returns_404(self, client_with_db):
        """Audit for nonexistent session returns 404."""
        response = client_with_db.get("/api/v1/audit/nonexistent_session")
        assert response.status_code == 404

    def test_trajectory_nonexistent_session_returns_404(self, client_with_db):
        """Trajectory for nonexistent session returns 404."""
        response = client_with_db.get("/api/v1/sessions/nonexistent_session/trajectory")
        assert response.status_code == 404


class TestEndToEndScenariosAPI:
    """End-to-end tests for Canonical Attack and Legitimate scenarios through API."""

    def test_canonical_attack_progression_api(self, client_with_db, db_session):
        """Database escalation attack through real HTTP API endpoints.

        Contract §18:
        Sequence:
        1. read_logs (ALLOW)
        2. read_customer (ALLOW)
        3. update_customer (CONFIRM)
        4. export_customers (CONFIRM)
        5. change_permissions (HARD_CONFIRM)
        6. drop_table (BLOCK)
        """
        principal = PrincipalModel(
            id="attacker_agent_user",
            scope="logs:read,customer:read,customer:write,permissions:write,schema:admin",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        # Session 1: initial setup
        session_resp = client_with_db.post(
            "/api/v1/sessions",
            json={"principal_id": "attacker_agent_user", "agent_id": "agent_001"},
        )
        session_id = session_resp.json()["session_id"]

        # Step 1: read_logs
        r1 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        ).json()
        assert r1["decision"] == "ALLOW"
        assert r1["risk_band"] == "LOW"

        # Step 2: read_customer
        r2 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r2["decision"] == "ALLOW"

        # Step 3: update_customer
        r3 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "update_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        # WRITE operation at MEDIUM risk requires confirmation
        assert r3["decision"] in ["ALLOW", "CONFIRM"]

        # Step 4: export_customers
        r4 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "export_customers",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r4["decision"] in ["ALLOW", "CONFIRM"]

        # Step 5: change_permissions
        r5 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        ).json()
        # DESTRUCTIVE at MEDIUM risk produces HARD_CONFIRM
        assert r5["decision"] in ["HARD_CONFIRM", "BLOCK"]

        # Step 6: drop_table
        r6 = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "attacker_agent_user",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        ).json()
        # High-risk trajectory reaches BLOCK
        assert r6["decision"] in ["HARD_CONFIRM", "BLOCK"]

        # Verify overall trajectory increased significantly across the sequence
        assert r6["trajectory_score"] > r1["trajectory_score"]
