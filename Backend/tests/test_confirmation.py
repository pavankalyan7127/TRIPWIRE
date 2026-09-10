"""Unit and integration tests for Phase A10 — Confirmation & Re-validation Engine.

Tests verify:
- POST /api/v1/actions/{action_id}/confirm
- Human approval requires re-validation; does NOT blindly execute.
- Only CONFIRM and HARD_CONFIRM decisions are eligible for confirmation.
- ALLOW and BLOCK actions are rejected with 400 Bad Request.
- If re-validation produces BLOCK (e.g. trajectory escalates to HIGH or scope is revoked),
  human approval CANNOT override and execution is denied (NOT_EXECUTED).
- Permitted re-validations execute exclusively through the ToolExecutionGate.
- Replay/double-execution protection ensures actions execute at most once.
- Approver identity validation (non-empty string required).
- Preserves original action_id and forwarded parameters.
- Fail-closed on session mismatches, missing sessions, or unknown tool metadata.
"""

from datetime import datetime, timezone
import pytest
from fastapi import status

from app.db.models import AuditEventModel, PrincipalModel, SessionModel
from app.models.enums import Decision, RiskBand
from app.security.execution_gate import (
    ExecutionContext,
    ToolExecutionGate,
    get_execution_gate,
)
from app.security.mock_tools import MockToolExecutionRecorder
from app.security.tool_registry import default_tool_registry


class TestConfirmationEndpointEligibilityAndValidation:
    """Tests verifying input validation and eligibility checking on the confirmation endpoint."""

    def test_confirmation_nonexistent_action_returns_404(self, client_with_db):
        """Confirming a non-existent action_id returns 404 Not Found."""
        response = client_with_db.post(
            "/api/v1/actions/action_nonexistent_123/confirm",
            json={"approved_by": "admin_001"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()

    def test_confirmation_empty_approved_by_returns_422(self, client_with_db, db_session):
        """Confirmation request with empty or whitespace approved_by returns 422 Unprocessable Entity."""
        # Create session and principal
        principal = PrincipalModel(
            id="user_val_01",
            scope="customer:read,permissions:write",
            trajectory_score=0.1,
        )
        session = SessionModel(
            id="sess_val_01",
            principal_id="user_val_01",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # Propose action that requires confirmation (change_permissions is DESTRUCTIVE -> CONFIRM)
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_val_01",
                "session_id": "sess_val_01",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {"user": "alice", "role": "admin"},
            },
        )
        assert prop_res.status_code == status.HTTP_200_OK
        action_id = prop_res.json()["action_id"]

        # Attempt confirmation with empty string
        res_empty = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": ""},
        )
        assert res_empty.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Attempt confirmation with whitespace only
        res_ws = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "   "},
        )
        assert res_ws.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Attempt confirmation with missing field
        res_missing = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={},
        )
        assert res_missing.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_confirmation_rejected_for_allow_action(self, client_with_db, db_session):
        """Action that evaluated to ALLOW cannot be confirmed (400 Bad Request)."""
        principal = PrincipalModel(
            id="user_allow_test",
            scope="logs:read",
            trajectory_score=0.0,
        )
        session = SessionModel(
            id="sess_allow_test",
            principal_id="user_allow_test",
            agent_id="agent_01",
            trajectory_score=0.0,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # Propose READ action -> ALLOW
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_allow_test",
                "session_id": "sess_allow_test",
                "agent_id": "agent_01",
                "action": "read_logs",
                "resource": "logs:app_logs",
                "parameters": {"limit": 10},
            },
        )
        assert prop_res.status_code == status.HTTP_200_OK
        assert prop_res.json()["decision"] == "ALLOW"
        action_id = prop_res.json()["action_id"]

        # Attempt confirmation
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_400_BAD_REQUEST
        assert "already allowed" in conf_res.json()["detail"].lower()

    def test_confirmation_rejected_for_blocked_action(self, client_with_db, db_session):
        """Action that evaluated to BLOCK cannot be confirmed (400 Bad Request)."""
        principal = PrincipalModel(
            id="user_block_test",
            scope="logs:read",  # Lacks schema:admin
            trajectory_score=0.0,
        )
        session = SessionModel(
            id="sess_block_test",
            principal_id="user_block_test",
            agent_id="agent_01",
            trajectory_score=0.0,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # Propose unauthorized action -> BLOCK
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_block_test",
                "session_id": "sess_block_test",
                "agent_id": "agent_01",
                "action": "drop_table",
                "resource": "db_schema:core",
                "parameters": {"table_name": "core"},
            },
        )
        assert prop_res.status_code == status.HTTP_200_OK
        assert prop_res.json()["decision"] == "BLOCK"
        action_id = prop_res.json()["action_id"]

        # Attempt confirmation
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_400_BAD_REQUEST
        assert "was blocked" in conf_res.json()["detail"].lower()


class TestConfirmationSuccessAndExecution:
    """Tests verifying successful confirmation, re-validation, and execution through ExecutionGate."""

    def test_confirm_destructive_action_success_and_execution(self, client_with_db, db_session):
        """Authorized destructive action requiring CONFIRM executes upon valid human approval."""
        principal = PrincipalModel(
            id="user_confirm_01",
            scope="permissions:write",
            trajectory_score=0.1,
        )
        session = SessionModel(
            id="sess_confirm_01",
            principal_id="user_confirm_01",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # 1. Propose action
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_confirm_01",
                "session_id": "sess_confirm_01",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {"user": "bob", "role": "editor"},
            },
        )
        assert prop_res.status_code == status.HTTP_200_OK
        prop_data = prop_res.json()
        action_id = prop_data["action_id"]
        assert prop_data["decision"] in ("CONFIRM", "HARD_CONFIRM")

        # 2. Confirm action
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "sec_admin_99"},
        )
        assert conf_res.status_code == status.HTTP_200_OK
        conf_data = conf_res.json()

        assert conf_data["action_id"] == action_id
        assert conf_data["decision"] == "ALLOW"
        assert conf_data["approved_by"] == "sec_admin_99"
        assert conf_data["execution_status"] == "EXECUTED"

        # 3. Verify audit persistence state
        event = db_session.query(AuditEventModel).filter(AuditEventModel.action_id == action_id).first()
        assert event is not None
        assert event.execution_status == "EXECUTED"
        assert event.approved_by == "sec_admin_99"
        assert event.executed_at is not None
        assert event.parameters_dict == {"user": "bob", "role": "editor"}

    def test_confirm_hard_confirm_action_success_and_execution(self, client_with_db, db_session):
        """Authorized destructive action requiring HARD_CONFIRM executes upon valid human approval."""
        principal = PrincipalModel(
            id="user_hard_confirm_01",
            scope="schema:admin",
            trajectory_score=0.45,  # MEDIUM risk
        )
        session = SessionModel(
            id="sess_hard_confirm_01",
            principal_id="user_hard_confirm_01",
            agent_id="agent_01",
            trajectory_score=0.45,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # Propose drop_table (MEDIUM risk DESTRUCTIVE -> HARD_CONFIRM)
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_hard_confirm_01",
                "session_id": "sess_hard_confirm_01",
                "agent_id": "agent_01",
                "action": "drop_table",
                "resource": "db_schema:temp_table",
                "parameters": {"table_name": "temp_table"},
            },
        )
        assert prop_res.status_code == status.HTTP_200_OK
        assert prop_res.json()["decision"] == "HARD_CONFIRM"
        action_id = prop_res.json()["action_id"]

        # Confirm
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "db_admin_01"},
        )
        assert conf_res.status_code == status.HTTP_200_OK
        assert conf_res.json()["decision"] == "ALLOW"
        assert conf_res.json()["execution_status"] == "EXECUTED"
        assert conf_res.json()["approved_by"] == "db_admin_01"

    def test_confirm_with_recorder_verifies_handler_parameters(self, client_with_db, db_session):
        """Custom execution gate recorder proves mock tool received original proposal parameters."""
        recorder = MockToolExecutionRecorder()
        test_gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)

        # Override execution gate dependency
        from app.main import app
        app.dependency_overrides[get_execution_gate] = lambda: test_gate

        try:
            principal = PrincipalModel(
                id="user_rec_01",
                scope="permissions:write",
                trajectory_score=0.1,
            )
            session = SessionModel(
                id="sess_rec_01",
                principal_id="user_rec_01",
                agent_id="agent_01",
                trajectory_score=0.1,
            )
            db_session.add_all([principal, session])
            db_session.commit()

            prop_res = client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_rec_01",
                    "session_id": "sess_rec_01",
                    "agent_id": "agent_01",
                    "action": "change_permissions",
                    "resource": "permissions:admin_role",
                    "parameters": {"user": "target_user", "role": "readonly_viewer"},
                },
            )
            action_id = prop_res.json()["action_id"]

            # Before confirmation: tool was NOT called
            assert recorder.call_count == 0

            # Confirm
            conf_res = client_with_db.post(
                f"/api/v1/actions/{action_id}/confirm",
                json={"approved_by": "auditor_1"},
            )
            assert conf_res.status_code == status.HTTP_200_OK

            # After confirmation: tool WAS called exactly once with forwarded parameters
            assert recorder.call_count == 1
            assert recorder.was_called("change_permissions") is True
            recorded_call = recorder.records[0]
            assert recorded_call.parameters == {"user": "target_user", "role": "readonly_viewer"}
        finally:
            if get_execution_gate in app.dependency_overrides:
                del app.dependency_overrides[get_execution_gate]


class TestConfirmationRevalidationAndSecurityOverrides:
    """Tests verifying that human approval CANNOT override security invariants during re-validation."""

    def test_revalidation_fails_when_trajectory_escalates_to_high(self, client_with_db, db_session):
        """If trajectory escalates to HIGH (> 0.65) before confirmation, confirmation is BLOCKED."""
        principal = PrincipalModel(
            id="user_escalated_high",
            scope="permissions:write",
            trajectory_score=0.2,
        )
        session = SessionModel(
            id="sess_esc_01",
            principal_id="user_escalated_high",
            agent_id="agent_01",
            trajectory_score=0.2,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # 1. Propose action when risk is LOW -> CONFIRM
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_escalated_high",
                "session_id": "sess_esc_01",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {"user": "charlie", "role": "admin"},
            },
        )
        action_id = prop_res.json()["action_id"]
        assert prop_res.json()["decision"] in ("CONFIRM", "HARD_CONFIRM")

        # 2. Simulate external escalation: Principal trajectory score jumps to HIGH (0.75)
        principal.trajectory_score = 0.75
        db_session.commit()

        # 3. Submit confirmation with valid human approval
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "security_officer_01"},
        )
        assert conf_res.status_code == status.HTTP_200_OK
        conf_data = conf_res.json()

        # Invariant 4/5: HIGH risk blocks; human approval CANNOT override
        assert conf_data["decision"] == "BLOCK"
        assert conf_data["execution_status"] == "NOT_EXECUTED"

        # Verify audit record reflects NOT_EXECUTED
        event = db_session.query(AuditEventModel).filter(AuditEventModel.action_id == action_id).first()
        assert event.execution_status == "NOT_EXECUTED"

    def test_revalidation_fails_when_scope_revoked(self, client_with_db, db_session):
        """If principal's authorization scope is revoked before confirmation, confirmation is BLOCKED."""
        principal = PrincipalModel(
            id="user_scope_revoked",
            scope="permissions:write",
            trajectory_score=0.1,
        )
        session = SessionModel(
            id="sess_revoked_01",
            principal_id="user_scope_revoked",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        # Propose action
        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_scope_revoked",
                "session_id": "sess_revoked_01",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {"user": "dave", "role": "admin"},
            },
        )
        action_id = prop_res.json()["action_id"]

        # Revoke scope in DB
        principal.scope = "customer:read"
        db_session.commit()

        # Submit confirmation
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "security_officer_01"},
        )
        assert conf_res.status_code == status.HTTP_200_OK
        assert conf_res.json()["decision"] == "BLOCK"
        assert conf_res.json()["execution_status"] == "NOT_EXECUTED"


class TestReplayAndSessionIdentityProtection:
    """Tests verifying replay protection, double-execution prevention, and identity integrity."""

    def test_replay_protection_double_confirmation_does_not_reexecute(self, client_with_db, db_session):
        """Submitting confirmation on an already EXECUTED action returns idempotent response without re-executing."""
        recorder = MockToolExecutionRecorder()
        test_gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)

        from app.main import app
        app.dependency_overrides[get_execution_gate] = lambda: test_gate

        try:
            principal = PrincipalModel(
                id="user_replay_01",
                scope="permissions:write",
                trajectory_score=0.1,
            )
            session = SessionModel(
                id="sess_replay_01",
                principal_id="user_replay_01",
                agent_id="agent_01",
                trajectory_score=0.1,
            )
            db_session.add_all([principal, session])
            db_session.commit()

            prop_res = client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_replay_01",
                    "session_id": "sess_replay_01",
                    "agent_id": "agent_01",
                    "action": "change_permissions",
                    "resource": "permissions:admin_role",
                    "parameters": {"user": "eve", "role": "admin"},
                },
            )
            action_id = prop_res.json()["action_id"]

            # First confirmation -> Executes
            first_conf = client_with_db.post(
                f"/api/v1/actions/{action_id}/confirm",
                json={"approved_by": "admin_first"},
            )
            assert first_conf.status_code == status.HTTP_200_OK
            assert first_conf.json()["execution_status"] == "EXECUTED"
            assert recorder.call_count == 1

            # Second confirmation (replay attempt) -> Idempotent, DOES NOT re-execute
            second_conf = client_with_db.post(
                f"/api/v1/actions/{action_id}/confirm",
                json={"approved_by": "admin_second"},
            )
            assert second_conf.status_code == status.HTTP_200_OK
            assert second_conf.json()["execution_status"] == "EXECUTED"
            assert second_conf.json()["approved_by"] == "admin_first"
            assert recorder.call_count == 1  # Still 1!
        finally:
            if get_execution_gate in app.dependency_overrides:
                del app.dependency_overrides[get_execution_gate]

    def test_confirmation_fails_if_session_deleted(self, client_with_db, db_session):
        """Confirmation fails with 404 if the session associated with the action was deleted."""
        principal = PrincipalModel(
            id="user_sess_del",
            scope="permissions:write",
            trajectory_score=0.1,
        )
        session = SessionModel(
            id="sess_to_del",
            principal_id="user_sess_del",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_sess_del",
                "session_id": "sess_to_del",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {},
            },
        )
        action_id = prop_res.json()["action_id"]

        # Delete session using query delete without nullifying related objects
        db_session.query(SessionModel).filter(SessionModel.id == "sess_to_del").delete(synchronize_session=False)
        db_session.commit()

        # Confirmation attempt
        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_404_NOT_FOUND
        assert "session" in conf_res.json()["detail"].lower()

    def test_confirmation_fails_if_session_principal_mismatch(self, client_with_db, db_session):
        """Confirmation fails with 403 Forbidden if session principal was reassigned."""
        principal_1 = PrincipalModel(id="user_p1", scope="permissions:write", trajectory_score=0.1)
        principal_2 = PrincipalModel(id="user_p2", scope="permissions:write", trajectory_score=0.1)
        session = SessionModel(
            id="sess_mismatch_p",
            principal_id="user_p1",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal_1, principal_2, session])
        db_session.commit()

        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_p1",
                "session_id": "sess_mismatch_p",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {},
            },
        )
        action_id = prop_res.json()["action_id"]

        # Change session's principal_id to user_p2
        session.principal_id = "user_p2"
        db_session.commit()

        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_403_FORBIDDEN
        assert "principal" in conf_res.json()["detail"].lower()

    def test_confirmation_fails_if_session_agent_mismatch(self, client_with_db, db_session):
        """Confirmation fails with 403 Forbidden if session agent was reassigned."""
        principal = PrincipalModel(id="user_agent_m", scope="permissions:write", trajectory_score=0.1)
        session = SessionModel(
            id="sess_mismatch_a",
            principal_id="user_agent_m",
            agent_id="agent_01",
            trajectory_score=0.1,
        )
        db_session.add_all([principal, session])
        db_session.commit()

        prop_res = client_with_db.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_agent_m",
                "session_id": "sess_mismatch_a",
                "agent_id": "agent_01",
                "action": "change_permissions",
                "resource": "permissions:admin_role",
                "parameters": {},
            },
        )
        action_id = prop_res.json()["action_id"]

        # Change session's agent_id to agent_02
        session.agent_id = "agent_02"
        db_session.commit()

        conf_res = client_with_db.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_403_FORBIDDEN
        assert "agent" in conf_res.json()["detail"].lower()

    def test_confirmation_fails_closed_on_unknown_or_modified_tool_metadata(self, client_with_db, db_session):
        """If tool metadata in audit does not match registry or is unknown, confirmation fails closed (BLOCK / NOT_EXECUTED)."""
        principal = PrincipalModel(id="user_tamper", scope="permissions:write", trajectory_score=0.1)
        session = SessionModel(id="sess_tamper", principal_id="user_tamper", agent_id="agent_01", trajectory_score=0.1)
        db_session.add_all([principal, session])
        db_session.commit()

        # Manually create audit event with unknown action
        audit_event = AuditEventModel(
            action_id="act_tampered_tool",
            principal_id="user_tamper",
            session_id="sess_tamper",
            agent_id="agent_01",
            action="unknown_malicious_tool",
            resource="system:unknown",
            reversibility="DESTRUCTIVE",
            trajectory_score=0.1,
            risk_band="LOW",
            decision="CONFIRM",
            reason="Simulated confirm record with unknown tool",
            execution_status="NOT_EXECUTED",
        )
        db_session.add(audit_event)
        db_session.commit()

        conf_res = client_with_db.post(
            "/api/v1/actions/act_tampered_tool/confirm",
            json={"approved_by": "admin_001"},
        )
        assert conf_res.status_code == status.HTTP_200_OK
        assert conf_res.json()["decision"] == "BLOCK"
        assert conf_res.json()["execution_status"] == "NOT_EXECUTED"

    def test_confirmation_execution_gate_failure_sets_not_executed(self, client_with_db, db_session):
        """If tool execution gate fails during handler execution, outcome is NOT_EXECUTED in response and audit."""
        from unittest.mock import MagicMock
        from app.security.execution_gate import ToolExecutionResult
        from app.main import app

        mock_gate = MagicMock(spec=ToolExecutionGate)
        mock_gate.execute.return_value = ToolExecutionResult(
            action_id="act_fail_gate",
            action="change_permissions",
            executed=False,
            decision=Decision.ALLOW,
            reason="Tool execution failed: Simulated system error",
            error="Simulated error",
        )

        app.dependency_overrides[get_execution_gate] = lambda: mock_gate
        try:
            principal = PrincipalModel(id="user_gate_fail", scope="permissions:write", trajectory_score=0.1)
            session = SessionModel(id="sess_gate_fail", principal_id="user_gate_fail", agent_id="agent_01", trajectory_score=0.1)
            db_session.add_all([principal, session])
            db_session.commit()

            prop_res = client_with_db.post(
                "/api/v1/actions/propose",
                json={
                    "principal_id": "user_gate_fail",
                    "session_id": "sess_gate_fail",
                    "agent_id": "agent_01",
                    "action": "change_permissions",
                    "resource": "permissions:admin_role",
                    "parameters": {},
                },
            )
            action_id = prop_res.json()["action_id"]

            conf_res = client_with_db.post(
                f"/api/v1/actions/{action_id}/confirm",
                json={"approved_by": "admin_001"},
            )
            assert conf_res.status_code == status.HTTP_200_OK
            assert conf_res.json()["execution_status"] == "NOT_EXECUTED"

            # Audit check
            event = db_session.query(AuditEventModel).filter(AuditEventModel.action_id == action_id).first()
            assert event.execution_status == "NOT_EXECUTED"
        finally:
            if get_execution_gate in app.dependency_overrides:
                del app.dependency_overrides[get_execution_gate]

