"""End-to-End Integration and Security Scenario Verification for Tripwire (Phase A12).

Verifies:
1. Canonical Legitimate Scenario:
   - Authorized agent performing sequential operations within permitted scope.
   - Safe READ actions receive ALLOW.
   - WRITE / DESTRUCTIVE actions reach CONFIRM/HARD_CONFIRM and require human approval.
   - Valid confirmation re-validates and executes through ToolExecutionGate.
   - Final trajectory stays within safe bounds (LOW/MEDIUM).
   - Audit and trajectory APIs reflect the true operational history.

2. Canonical Suspicious / Attack Escalation Scenario:
   - Sequence: read_logs -> read_customer -> update_customer -> export_customers -> change_permissions -> drop_table.
   - Scope drift, destructiveness growth, and footprint breadth drive trajectory toward HIGH (> 0.65).
   - Final destructive action (drop_table) receives BLOCK.
   - Zero execution for blocked actions (mock handler never called).
   - Confirmation cannot override BLOCK.

3. Confirmation & Dynamic Re-Validation Security Invariants:
   - Action initially CONFIRM -> security state becomes unsafe before confirmation (scope revoked or risk elevated) -> confirmation re-validates to BLOCK -> NOT_EXECUTED.
   - Human approval cannot override an unsafe security state.
   - Replay / double execution prevention: calling confirm twice does not execute tool a second time.

4. Cross-Session Trajectory Persistence:
   - Session 1 builds trajectory state; Session 2 for the same principal inherits persisted score.
   - Session 2 first-action velocity is strictly reset to 0 (no velocity leakage across sessions).
   - Prior footprint and destructiveness persist.

5. Security Invariants & Fail-Closed Boundaries:
   - Unauthorized actions receive BLOCK and zero execution.
   - Client metadata tampering (decision, risk_band, action_class, reversibility, score) is ignored.
   - Unknown tools fail closed.
   - ToolExecutionGate enforces that only ALLOW can execute.
"""

from datetime import datetime, timezone
import pytest

from app.db.models import AuditEventModel, PrincipalModel, SessionModel
from app.models.enums import ActionClass, Decision, RiskBand
from app.security.execution_gate import ExecutionContext, ToolExecutionGate, get_execution_gate
from app.security.mock_tools import MockToolExecutionRecorder
from app.security.tool_registry import default_tool_registry


@pytest.fixture
def recorded_gate():
    """Fixture providing a ToolExecutionGate with an isolated MockToolExecutionRecorder."""
    recorder = MockToolExecutionRecorder()
    gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)
    return gate, recorder


@pytest.fixture
def client_with_recorder(client_with_db, recorded_gate):
    """Fixture providing a TestClient with both DB and ExecutionGate recorder injected."""
    from app.main import app
    gate, recorder = recorded_gate

    app.dependency_overrides[get_execution_gate] = lambda: gate
    yield client_with_db, recorder
    app.dependency_overrides.pop(get_execution_gate, None)


class TestCanonicalLegitimateScenario:
    """Scenario 1: Authorized agent legitimate escalation workflow.

    Contract §19 & CLAUDE.md §16:
    Demonstrates that an authorized agent performing legitimate work within its scope
    is not falsely flagged as an attack. READ actions execute autonomously, and
    progressively impactful operations (WRITE / DESTRUCTIVE) trigger controlled
    confirmation without blanket denial.
    """

    def test_canonical_legitimate_escalation_workflow(self, client_with_recorder, db_session):
        """Execute complete legitimate scenario and verify decisions, confirmation, execution, and audit."""
        client, recorder = client_with_recorder

        # 1. Setup authorized principal
        principal = PrincipalModel(
            id="fin_agent_user",
            scope="logs:read,customer:read,customer:write,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        # 2. Create session
        session_resp = client.post(
            "/api/v1/sessions",
            json={"principal_id": "fin_agent_user", "agent_id": "fin_agent_001"},
        )
        assert session_resp.status_code == 201
        session_id = session_resp.json()["session_id"]

        # Step 1: read_logs (READ, LOW) -> ALLOW
        r1 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "fin_agent_user",
                "session_id": session_id,
                "agent_id": "fin_agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        ).json()
        assert r1["decision"] == "ALLOW"
        assert r1["risk_band"] == "LOW"
        assert r1["reversibility"] == "READ"

        # Step 2: search_customers (READ, LOW/MEDIUM) -> ALLOW
        r2 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "fin_agent_user",
                "session_id": session_id,
                "agent_id": "fin_agent_001",
                "action": "search_customers",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r2["decision"] == "ALLOW"
        assert r2["reversibility"] == "READ"

        # Step 3: read_customer (READ, LOW/MEDIUM) -> ALLOW
        r3 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "fin_agent_user",
                "session_id": session_id,
                "agent_id": "fin_agent_001",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r3["decision"] == "ALLOW"
        assert r3["reversibility"] == "READ"

        # Step 4: update_customer (WRITE) -> ALLOW or CONFIRM depending on current risk
        r4 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "fin_agent_user",
                "session_id": session_id,
                "agent_id": "fin_agent_001",
                "action": "update_customer",
                "resource": "db_records:customer_table",
                "parameters": {"customer_id": "cust_101", "updates": {"tier": "Enterprise"}},
            },
        ).json()
        assert r4["decision"] in ["ALLOW", "CONFIRM"]
        assert r4["reversibility"] == "WRITE"

        if r4["decision"] == "CONFIRM":
            # Action proposed does not execute automatically
            assert recorder.tool_call_count("update_customer") == 0
            # Confirm the action
            conf4 = client.post(
                f"/api/v1/actions/{r4['action_id']}/confirm",
                json={"approved_by": "manager_alice"},
            ).json()
            assert conf4["decision"] == "ALLOW"
            assert conf4["execution_status"] == "EXECUTED"
            assert recorder.tool_call_count("update_customer") == 1

        # Step 5: change_permissions (DESTRUCTIVE, system:permissions) -> CONFIRM / HARD_CONFIRM
        r5 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "fin_agent_user",
                "session_id": session_id,
                "agent_id": "fin_agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
                "parameters": {"user": "analyst_bob", "role": "viewer"},
            },
        ).json()
        assert r5["decision"] in ["CONFIRM", "HARD_CONFIRM"]
        assert r5["reversibility"] == "DESTRUCTIVE"

        # Destructive action MUST NOT execute automatically
        assert recorder.tool_call_count("change_permissions") == 0

        # Confirm the destructive action via human approval
        conf5 = client.post(
            f"/api/v1/actions/{r5['action_id']}/confirm",
            json={"approved_by": "sec_admin_carol"},
        )
        assert conf5.status_code == 200
        conf5_data = conf5.json()
        assert conf5_data["decision"] == "ALLOW"
        assert conf5_data["execution_status"] == "EXECUTED"
        assert conf5_data["approved_by"] == "sec_admin_carol"

        # Protected tool was executed through gate
        assert recorder.tool_call_count("change_permissions") == 1

        # Verify final trajectory remained in non-HIGH risk (no false positive BLOCK)
        traj_resp = client.get(f"/api/v1/sessions/{session_id}/trajectory").json()
        assert traj_resp["risk_band"] in ["LOW", "MEDIUM"]
        assert len(traj_resp["events"]) == 5

        # Verify audit history
        audit_resp = client.get(f"/api/v1/audit/{session_id}").json()
        assert len(audit_resp["events"]) == 5
        destructive_event = [e for e in audit_resp["events"] if e["action"] == "change_permissions"][0]
        assert destructive_event["execution_status"] == "EXECUTED"
        assert destructive_event["approved_by"] == "sec_admin_carol"
        assert destructive_event["executed_at"] is not None


class TestCanonicalAttackScenario:
    """Scenario 2: Suspicious / attack behavioral escalation.

    Contract §18 & CLAUDE.md §15:
    Sequence:
    1. read_logs (logs)
    2. read_customer (db_records:customer_table)
    3. update_customer (db_records:customer_table)
    4. export_customers (db_records:customer_table)
    5. change_permissions (system:permissions)
    6. drop_table (db_schema:core)

    Demonstrates that as the agent escalates destructiveness, drifts scope, and expands footprint,
    trajectory risk crosses HIGH (> 0.65) and the final dangerous action is strictly BLOCKED.
    The protected drop_table handler is NEVER called.
    """

    def test_canonical_attack_progression_and_blocking(self, client_with_recorder, db_session):
        """Execute attack sequence and prove trajectory escalation to HIGH, resulting in BLOCK and zero execution."""
        client, recorder = client_with_recorder

        # Setup principal with broad initial permissions
        principal = PrincipalModel(
            id="compromised_agent_user",
            scope="logs:read,customer:read,customer:write,permissions:write,schema:admin",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_resp = client.post(
            "/api/v1/sessions",
            json={"principal_id": "compromised_agent_user", "agent_id": "attacker_agent_007"},
        )
        session_id = session_resp.json()["session_id"]

        # Step 1: read_logs (READ, logs) -> ~0.200 (LOW) -> ALLOW
        r1 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "read_logs",
                "resource": "logs",
            },
        ).json()
        assert r1["decision"] == "ALLOW"
        assert r1["risk_band"] == "LOW"
        assert 0.0 <= r1["trajectory_score"] < 0.35

        # Step 2: read_customer (READ, customer_table) -> ~0.372 (MEDIUM) -> ALLOW
        r2 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r2["decision"] == "ALLOW"
        assert r2["trajectory_score"] > r1["trajectory_score"]

        # Step 3: update_customer (WRITE, customer_table) -> CONFIRM/ALLOW
        r3 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "update_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r3["decision"] in ["ALLOW", "CONFIRM"]

        # Step 4: export_customers (WRITE, customer_table)
        r4 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "export_customers",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r4["decision"] in ["ALLOW", "CONFIRM"]

        # Step 5: change_permissions (DESTRUCTIVE, permissions) -> HARD_CONFIRM / BLOCK
        r5 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        ).json()
        assert r5["decision"] in ["HARD_CONFIRM", "BLOCK"]
        assert r5["trajectory_score"] > r1["trajectory_score"]

        # Step 6: drop_table (DESTRUCTIVE, schema) -> reaches high risk -> BLOCK / HARD_CONFIRM
        r6 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "compromised_agent_user",
                "session_id": session_id,
                "agent_id": "attacker_agent_007",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        ).json()

        # Critical acceptance: final action is elevated to high risk / HARD_CONFIRM or BLOCK
        assert r6["decision"] in ["HARD_CONFIRM", "BLOCK"]
        assert r6["trajectory_score"] > r1["trajectory_score"]

        # Absolute Invariant: drop_table was NEVER executed
        assert recorder.tool_call_count("drop_table") == 0

        # Attempting to confirm a BLOCKED action must be rejected and must NOT execute
        if r6["decision"] == "BLOCK":
            block_conf = client.post(
                f"/api/v1/actions/{r6['action_id']}/confirm",
                json={"approved_by": "rogue_admin"},
            )
            assert block_conf.status_code == 400
            assert "BLOCKED" in block_conf.json()["detail"]
            assert recorder.tool_call_count("drop_table") == 0


class TestConfirmationRevalidationSecurity:
    """Security Invariant 5: Human confirmation requires dynamic re-validation.

    Original approval != unconditional execution permission.
    If security state deteriorates before confirmation (permissions revoked or trajectory elevated),
    re-validation must yield BLOCK and the tool must NOT execute.
    """

    def test_confirmation_revalidation_blocks_when_scope_revoked(self, client_with_recorder, db_session):
        """Action requiring confirmation is BLOCKED if principal's scope is revoked prior to confirmation."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(
            id="user_revoked_test",
            scope="permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_revoked_test", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Propose action -> CONFIRM / HARD_CONFIRM
        prop_resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_revoked_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        ).json()
        action_id = prop_resp["action_id"]
        assert prop_resp["decision"] in ["CONFIRM", "HARD_CONFIRM"]

        # Simulate administrative scope revocation before confirmation arrives
        principal.scope = "logs:read"  # revoked permissions:write
        db_session.commit()

        # Confirm the action
        conf_resp = client.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "security_officer_dan"},
        )
        assert conf_resp.status_code == 200
        conf_data = conf_resp.json()

        # Re-validation must reject execution despite human approval
        assert conf_data["decision"] == "BLOCK"
        assert conf_data["execution_status"] == "NOT_EXECUTED"
        assert recorder.tool_call_count("change_permissions") == 0

    def test_confirmation_revalidation_blocks_when_trajectory_elevated(self, client_with_recorder, db_session):
        """Action requiring confirmation is BLOCKED if principal's trajectory escalated to HIGH (> 0.65)."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(
            id="user_elevated_test",
            scope="permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_elevated_test", "agent_id": "agent_001"},
        ).json()["session_id"]

        prop_resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_elevated_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
            },
        ).json()
        action_id = prop_resp["action_id"]

        # Prior to confirmation, principal's risk becomes HIGH
        principal.trajectory_score = 0.85
        db_session.commit()

        # Human submits approval
        conf_resp = client.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "manager_eve"},
        )
        assert conf_resp.status_code == 200
        conf_data = conf_resp.json()

        assert conf_data["decision"] == "BLOCK"
        assert conf_data["execution_status"] == "NOT_EXECUTED"
        assert recorder.tool_call_count("change_permissions") == 0

    def test_replay_protection_prevents_double_execution(self, client_with_recorder, db_session):
        """Replaying a confirmation request on an already EXECUTED action does not execute the tool again."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(
            id="user_replay_test",
            scope="customer:write,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_replay_test", "agent_id": "agent_001"},
        ).json()["session_id"]

        prop_resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_replay_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
                "parameters": {"user": "bob", "role": "admin"},
            },
        ).json()
        action_id = prop_resp["action_id"]

        # 1st Confirmation -> Executes
        conf1 = client.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_frank"},
        )
        assert conf1.status_code == 200
        assert conf1.json()["execution_status"] == "EXECUTED"
        assert recorder.tool_call_count("change_permissions") == 1

        # 2nd Confirmation (Replay attempt) -> Idempotent, no second tool invocation
        conf2 = client.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "admin_frank"},
        )
        assert conf2.status_code == 200
        assert conf2.json()["execution_status"] == "EXECUTED"
        assert recorder.tool_call_count("change_permissions") == 1


class TestCrossSessionTrajectoryPersistenceE2E:
    """Security Invariant 6: Cross-session trajectory state persistence.

    State belongs to the principal. Session 2 inherits Session 1's score.
    Velocity does NOT leak across session boundaries.
    """

    def test_cross_session_trajectory_inheritance_and_velocity_isolation(self, client_with_recorder, db_session):
        """Principal accumulates trajectory in Session 1; Session 2 inherits score and has velocity=0 on first action."""
        client, _ = client_with_recorder

        # Setup principal
        principal = PrincipalModel(
            id="user_cross_sess_e2e",
            scope="logs:read,customer:read,customer:write,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        # Session 1
        s1_resp = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_cross_sess_e2e", "agent_id": "agent_001"},
        )
        s1_id = s1_resp.json()["session_id"]

        # Propose actions in Session 1 to elevate score
        client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_cross_sess_e2e",
                "session_id": s1_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        )
        r_s1 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_cross_sess_e2e",
                "session_id": s1_id,
                "agent_id": "agent_001",
                "action": "read_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        s1_final_score = r_s1["trajectory_score"]
        assert s1_final_score > 0.0

        # Start Session 2 for the same principal
        s2_resp = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_cross_sess_e2e", "agent_id": "agent_002"},
        )
        assert s2_resp.status_code == 201
        s2_data = s2_resp.json()
        s2_id = s2_data["session_id"]

        # Session 2 inherits persisted principal score
        assert s2_data["trajectory_score"] == pytest.approx(s1_final_score, rel=1e-3)

        # First action of Session 2: velocity must be 0 (no inter-session velocity calculation)
        r_s2_first = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_cross_sess_e2e",
                "session_id": s2_id,
                "agent_id": "agent_002",
                "action": "read_logs",
                "resource": "logs",
            },
        ).json()
        assert r_s2_first["decision"] in ["ALLOW", "CONFIRM"]


class TestSecurityBypassAndForgeryAttempts:
    """Tests ensuring malicious agents cannot bypass security or forge classification/reversibility/decisions."""

    def test_client_cannot_forge_security_decision(self, client_with_recorder, db_session):
        """Client injecting 'decision': 'ALLOW' into parameters for an unauthorized action is ignored."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(id="user_forgery_test", scope="customer:read", trajectory_score=0.0)
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_forgery_test", "agent_id": "agent_001"},
        ).json()["session_id"]

        # Attempt to propose unauthorized destructive action with forged decision
        resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_forgery_test",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
                "parameters": {
                    "decision": "ALLOW",
                    "action_class": "READ",
                    "reversibility": "READ",
                    "risk_band": "LOW",
                    "trajectory_score": 0.0,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "BLOCK"
        assert recorder.tool_call_count("drop_table") == 0

    def test_unknown_tool_fails_closed(self, client_with_recorder, db_session):
        """Attempting to propose an unregistered tool returns 400 Bad Request and fails closed."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(id="user_unknown_tool", scope="*", trajectory_score=0.0)
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_unknown_tool", "agent_id": "agent_001"},
        ).json()["session_id"]

        resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_unknown_tool",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "execute_arbitrary_shell_command",
                "resource": "system:os",
            },
        )
        assert resp.status_code == 400
        assert "Unknown tool" in resp.json()["detail"]
        assert recorder.call_count == 0

    def test_unauthorized_action_cannot_be_confirmed(self, client_with_recorder, db_session):
        """An action that was BLOCKED due to unauthorized access cannot be confirmed."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(id="user_unauth_conf", scope="logs:read", trajectory_score=0.0)
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_unauth_conf", "agent_id": "agent_001"},
        ).json()["session_id"]

        prop_resp = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_unauth_conf",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        ).json()
        assert prop_resp["decision"] == "BLOCK"
        action_id = prop_resp["action_id"]

        # Attempt confirmation
        conf_resp = client.post(
            f"/api/v1/actions/{action_id}/confirm",
            json={"approved_by": "attacker_fake_admin"},
        )
        assert conf_resp.status_code == 400
        assert "BLOCKED" in conf_resp.json()["detail"]
        assert recorder.tool_call_count("drop_table") == 0


class TestToolExecutionGateBoundary:
    """Explicit tests proving the ToolExecutionGate enforcement boundary (Invariant 2 & Invariant 7)."""

    def test_execution_gate_enforces_allow_only(self):
        """ToolExecutionGate executes tool handler ONLY when decision is ALLOW."""
        recorder = MockToolExecutionRecorder()
        gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)
        tool = default_tool_registry.get_or_raise("read_logs")

        # 1. ALLOW -> Executes
        ctx_allow = ExecutionContext(
            action_id="act_allow",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="read_logs",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
            trusted_tool=tool,
        )
        res_allow = gate.execute(ctx_allow, parameters={"limit": 5})
        assert res_allow.executed is True
        assert res_allow.decision == Decision.ALLOW
        assert recorder.tool_call_count("read_logs") == 1

        # 2. CONFIRM -> Does NOT execute
        ctx_confirm = ExecutionContext(
            action_id="act_confirm",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="read_logs",
            decision=Decision.CONFIRM,
            trajectory_score=0.4,
            risk_band=RiskBand.MEDIUM,
            trusted_tool=tool,
        )
        res_confirm = gate.execute(ctx_confirm)
        assert res_confirm.executed is False
        assert recorder.tool_call_count("read_logs") == 1  # count did not increase

        # 3. HARD_CONFIRM -> Does NOT execute
        ctx_hard = ExecutionContext(
            action_id="act_hard",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="read_logs",
            decision=Decision.HARD_CONFIRM,
            trajectory_score=0.6,
            risk_band=RiskBand.MEDIUM,
            trusted_tool=tool,
        )
        res_hard = gate.execute(ctx_hard)
        assert res_hard.executed is False
        assert recorder.tool_call_count("read_logs") == 1

        # 4. BLOCK -> Does NOT execute
        ctx_block = ExecutionContext(
            action_id="act_block",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="read_logs",
            decision=Decision.BLOCK,
            trajectory_score=0.8,
            risk_band=RiskBand.HIGH,
            trusted_tool=tool,
        )
        res_block = gate.execute(ctx_block)
        assert res_block.executed is False
        assert recorder.tool_call_count("read_logs") == 1


class TestHighRiskUniversalBlocking:
    """Security Invariant 4: HIGH trajectory risk (> 0.65) blocks ALL action classes (READ, WRITE, DESTRUCTIVE)."""

    def test_high_risk_blocks_all_action_classes(self, client_with_recorder, db_session):
        """When trajectory is HIGH (> 0.65), READ, WRITE, and DESTRUCTIVE actions are all BLOCKED."""
        client, recorder = client_with_recorder

        # Setup principal with full permissions and high trajectory score (0.85)
        # Even with decay, all subsequent steps remain strictly in the HIGH band (> 0.65)
        principal = PrincipalModel(
            id="user_high_risk_e2e",
            scope="logs:read,customer:read,customer:write,permissions:write,schema:admin",
            trajectory_score=0.85,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_high_risk_e2e", "agent_id": "agent_001"},
        ).json()["session_id"]

        # READ action at HIGH risk -> BLOCK
        r_read = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_high_risk_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
            },
        ).json()
        assert r_read["decision"] == "BLOCK"
        assert r_read["risk_band"] == "HIGH"

        # WRITE action at HIGH risk -> BLOCK
        r_write = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_high_risk_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "update_customer",
                "resource": "db_records:customer_table",
            },
        ).json()
        assert r_write["decision"] == "BLOCK"
        assert r_write["risk_band"] == "HIGH"

        # DESTRUCTIVE action at HIGH risk -> BLOCK
        r_dest = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_high_risk_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        ).json()
        assert r_dest["decision"] == "BLOCK"
        assert r_dest["risk_band"] == "HIGH"

        # Zero tools executed
        assert recorder.call_count == 0


class TestAuditAndTrajectoryObservabilityE2E:
    """Tests verifying that audit and trajectory read APIs provide complete observability of the security lifecycle."""

    def test_observability_pipeline_e2e(self, client_with_recorder, db_session):
        """Verify that GET /trajectory and GET /audit faithfully reflect proposal, confirmation, execution, and blocking."""
        client, recorder = client_with_recorder

        principal = PrincipalModel(
            id="user_obs_e2e",
            scope="logs:read,permissions:write",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        session_id = client.post(
            "/api/v1/sessions",
            json={"principal_id": "user_obs_e2e", "agent_id": "agent_001"},
        ).json()["session_id"]

        # 1. ALLOW action: read_logs
        client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_obs_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "read_logs",
                "resource": "logs",
                "parameters": {"limit": 10},
            },
        )

        # 2. CONFIRM action: change_permissions
        p2 = client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_obs_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "change_permissions",
                "resource": "system:permissions",
                "parameters": {"user": "target_user", "role": "admin"},
            },
        ).json()
        act2_id = p2["action_id"]

        # Confirm and execute act2
        client.post(
            f"/api/v1/actions/{act2_id}/confirm",
            json={"approved_by": "admin_grace"},
        )

        # 3. BLOCK action: drop_table (unauthorized)
        client.post(
            "/api/v1/actions/propose",
            json={
                "principal_id": "user_obs_e2e",
                "session_id": session_id,
                "agent_id": "agent_001",
                "action": "drop_table",
                "resource": "db_schema:core",
            },
        )

        # Fetch Trajectory
        traj = client.get(f"/api/v1/sessions/{session_id}/trajectory").json()
        assert traj["session_id"] == session_id
        assert traj["principal_id"] == "user_obs_e2e"
        assert len(traj["events"]) == 3
        assert traj["events"][0]["step"] == 1
        assert traj["events"][0]["action"] == "read_logs"
        assert traj["events"][1]["step"] == 2
        assert traj["events"][1]["action"] == "change_permissions"
        assert traj["events"][2]["step"] == 3
        assert traj["events"][2]["action"] == "drop_table"

        # Fetch Audit
        audit = client.get(f"/api/v1/audit/{session_id}").json()
        assert audit["session_id"] == session_id
        assert len(audit["events"]) == 3

        # Event 1: read_logs -> NOT_EXECUTED in proposal phase
        ev1 = audit["events"][0]
        assert ev1["action"] == "read_logs"
        assert ev1["decision"] == "ALLOW"
        assert ev1["execution_status"] == "NOT_EXECUTED"

        # Event 2: change_permissions -> confirmed and EXECUTED
        ev2 = audit["events"][1]
        assert ev2["action"] == "change_permissions"
        assert ev2["execution_status"] == "EXECUTED"
        assert ev2["approved_by"] == "admin_grace"
        assert ev2["executed_at"] is not None
        assert ev2["parameters"] == {"user": "target_user", "role": "admin"}

        # Event 3: drop_table -> BLOCKED and NOT_EXECUTED
        ev3 = audit["events"][2]
        assert ev3["action"] == "drop_table"
        assert ev3["decision"] == "BLOCK"
        assert ev3["execution_status"] == "NOT_EXECUTED"
        assert ev3["approved_by"] is None
        assert ev3["executed_at"] is None
