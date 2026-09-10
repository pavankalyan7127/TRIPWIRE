"""Unit and integration tests for the Tripwire Tool Execution Gate (Phase A9).

Tests verify:
- ALLOW is the ONLY decision that permits protected tool execution.
- BLOCK, CONFIRM, and HARD_CONFIRM strictly prevent tool handler execution.
- Handlers and metadata are resolved exclusively from the trusted ToolRegistry.
- Client/agent input cannot forge, override, or downgrade security decisions.
- Deterministic and safe behavior for all 7 contract-defined mock tools.
- drop_table and change_permissions never cause real destructive changes.
- Fail-closed behavior on invalid contexts, unknown tools, and malformed inputs.
- End-to-end integration: Proposal -> A4 -> A5 -> A6 -> A7 -> A9 execution gate.
"""

from unittest.mock import MagicMock

import pytest

from app.db.models import PrincipalModel
from app.models.enums import ActionClass, Decision, RiskBand
from app.security.authorization import AuthorizationContext, AuthorizationService
from app.security.decision_engine import DecisionEngine, classify_risk_band
from app.security.execution_gate import (
    ExecutionContext,
    ToolExecutionGate,
    ToolExecutionResult,
    create_execution_context,
)
from app.security.mock_tools import (
    MockToolExecutionRecorder,
    mock_change_permissions,
    mock_drop_table,
    mock_export_customers,
    mock_read_customer,
    mock_read_logs,
    mock_search_customers,
    mock_update_customer,
)
from app.security.tool_registry import (
    CONTRACT_TOOLS,
    ToolDefinition,
    ToolRegistry,
    default_tool_registry,
)
from app.trajectory.engine import TrajectoryEngine


class TestExecutionGateDecisionEnforcement:
    """Tests verifying decision-based execution gating (ALLOW vs BLOCK/CONFIRM/HARD_CONFIRM)."""

    @pytest.fixture
    def recorder(self):
        return MockToolExecutionRecorder()

    @pytest.fixture
    def gate(self, recorder):
        return ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)

    def test_allow_executes_correct_handler(self, gate, recorder):
        """Decision.ALLOW executes the tool handler and records execution."""
        ctx = create_execution_context(
            action_id="act_001",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="read_logs",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
        )

        result = gate.execute(ctx, parameters={"limit": 2})

        assert result.executed is True
        assert result.decision == Decision.ALLOW
        assert result.action == "read_logs"
        assert result.result is not None
        assert result.result["tool"] == "read_logs"
        assert recorder.was_called("read_logs") is True
        assert recorder.call_count == 1

    def test_block_never_executes_handler(self, gate, recorder):
        """Decision.BLOCK strictly denies execution and never calls the handler."""
        ctx = create_execution_context(
            action_id="act_002",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="drop_table",
            decision=Decision.BLOCK,
            trajectory_score=0.8,
            risk_band=RiskBand.HIGH,
        )

        result = gate.execute(ctx, parameters={"table_name": "core"})

        assert result.executed is False
        assert result.decision == Decision.BLOCK
        assert "BLOCKED" in result.reason
        assert result.result is None
        assert recorder.was_called() is False
        assert recorder.call_count == 0

    def test_confirm_never_executes_handler(self, gate, recorder):
        """Decision.CONFIRM strictly denies execution in A9 (requires A10 human confirmation)."""
        ctx = create_execution_context(
            action_id="act_003",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="change_permissions",
            decision=Decision.CONFIRM,
            trajectory_score=0.2,
            risk_band=RiskBand.LOW,
        )

        result = gate.execute(ctx, parameters={"user": "test_user"})

        assert result.executed is False
        assert result.decision == Decision.CONFIRM
        assert "requires human confirmation" in result.reason
        assert result.result is None
        assert recorder.was_called() is False

    def test_hard_confirm_never_executes_handler(self, gate, recorder):
        """Decision.HARD_CONFIRM strictly denies execution in A9 (requires A10 human confirmation)."""
        ctx = create_execution_context(
            action_id="act_004",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="drop_table",
            decision=Decision.HARD_CONFIRM,
            trajectory_score=0.55,
            risk_band=RiskBand.MEDIUM,
        )

        result = gate.execute(ctx, parameters={"table_name": "orders"})

        assert result.executed is False
        assert result.decision == Decision.HARD_CONFIRM
        assert "requires human confirmation" in result.reason
        assert result.result is None
        assert recorder.was_called() is False


class TestTrustedMetadataAndTamperResistance:
    """Tests verifying client cannot tamper with handlers, metadata, or decisions."""

    @pytest.fixture
    def gate(self):
        return ToolExecutionGate(tool_registry=default_tool_registry)

    def test_handler_resolved_from_trusted_registry(self, gate):
        """The tool handler executed is strictly from the server-side ToolRegistry."""
        ctx = create_execution_context(
            action_id="act_005",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="search_customers",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
        )

        result = gate.execute(ctx, parameters={"query": "Acme"})
        assert result.executed is True
        assert result.result["tool"] == "search_customers"

    def test_unknown_tool_fails_closed(self, gate):
        """Unknown tool name cannot be executed even if context claims ALLOW."""
        # Create dummy ToolDefinition not in default registry
        untrusted_tool = ToolDefinition(
            name="malicious_shell_tool",
            resource="system:shell",
            action_class=ActionClass.READ,
            required_scope="shell:read",
        )
        ctx = ExecutionContext(
            action_id="act_006",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="malicious_shell_tool",
            decision=Decision.ALLOW,
            trajectory_score=0.0,
            risk_band=RiskBand.LOW,
            trusted_tool=untrusted_tool,
        )

        result = gate.execute(ctx)
        assert result.executed is False
        assert "unknown tool" in result.reason

    def test_mismatched_tool_definition_fails_closed(self, gate):
        """Context claiming a known tool name but forged resource target fails closed."""
        forged_tool = ToolDefinition(
            name="read_logs",
            resource="forged:secrets_vault",
            action_class=ActionClass.READ,
            required_scope="logs:read",
        )
        ctx = ExecutionContext(
            action_id="act_007",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="read_logs",
            decision=Decision.ALLOW,
            trajectory_score=0.0,
            risk_band=RiskBand.LOW,
            trusted_tool=forged_tool,
        )

        result = gate.execute(ctx)
        assert result.executed is False
        assert "does not match trusted registry" in result.reason

    def test_block_decision_cannot_be_downgraded_by_parameters(self, gate):
        """Parameters claiming ALLOW or safe status cannot override Decision.BLOCK."""
        ctx = create_execution_context(
            action_id="act_008",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="drop_table",
            decision=Decision.BLOCK,
            trajectory_score=0.75,
            risk_band=RiskBand.HIGH,
        )

        # Inject fake decision in parameters
        result = gate.execute(ctx, parameters={"decision": "ALLOW", "override": True})
        assert result.executed is False
        assert result.decision == Decision.BLOCK

    def test_non_dict_parameters_fail_safely(self, gate):
        """Invalid parameter types fail safely without executing or crashing."""
        ctx = create_execution_context(
            action_id="act_009",
            principal_id="user_001",
            session_id="sess_001",
            agent_id="agent_001",
            action="read_logs",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
        )

        result = gate.execute(ctx, parameters="invalid_string_parameters")  # type: ignore[arg-type]
        assert result.executed is False
        assert "parameters must be a dictionary" in result.reason


class TestMockProtectedToolBehaviors:
    """Tests verifying safe, deterministic behavior of all 7 mock tools (Contract §10, §11)."""

    def test_read_logs_mock_behavior(self):
        """mock_read_logs returns deterministic log records."""
        res = mock_read_logs(limit=2, service="auth-service")
        assert res["tool"] == "read_logs"
        assert res["status"] == "success"
        assert res["service"] == "auth-service"
        assert len(res["logs"]) == 2
        assert all("timestamp" in l and "message" in l for l in res["logs"])

    def test_search_customers_mock_behavior(self):
        """mock_search_customers returns deterministic customer listings."""
        res = mock_search_customers(query="Acme")
        assert res["tool"] == "search_customers"
        assert res["status"] == "success"
        assert res["query"] == "Acme"
        assert len(res["customers"]) == 3
        assert res["customers"][0]["id"] == "cust_101"

    def test_read_customer_mock_behavior(self):
        """mock_read_customer returns a single customer detail record."""
        res = mock_read_customer(customer_id="cust_999")
        assert res["tool"] == "read_customer"
        assert res["status"] == "success"
        assert res["customer"]["id"] == "cust_999"
        assert res["customer"]["email"] == "security@acme.example.com"

    def test_export_customers_mock_behavior(self):
        """mock_export_customers simulates export without external side effects."""
        res = mock_export_customers(format="json")
        assert res["tool"] == "export_customers"
        assert res["status"] == "success"
        assert res["format"] == "json"
        assert res["record_count"] == 150
        assert "mock buffer" in res["message"]

    def test_update_customer_mock_behavior(self):
        """mock_update_customer performs safe in-memory simulation."""
        res = mock_update_customer(customer_id="cust_101", updates={"name": "New Name"})
        assert res["tool"] == "update_customer"
        assert res["status"] == "success"
        assert res["customer_id"] == "cust_101"
        assert "name" in res["updated_fields"]

    def test_change_permissions_mock_behavior(self):
        """mock_change_permissions performs safe simulation without modifying OS/DB permissions."""
        res = mock_change_permissions(user="test_admin", role="superuser")
        assert res["tool"] == "change_permissions"
        assert res["status"] == "success"
        assert res["user"] == "test_admin"
        assert "No real OS permissions were modified" in res["message"]

    def test_drop_table_mock_behavior(self):
        """mock_drop_table simulates drop and NEVER runs real SQL DROP TABLE."""
        res = mock_drop_table(table_name="temp_data")
        assert res["tool"] == "drop_table"
        assert res["status"] == "mock_executed"
        assert res["table"] == "temp_data"
        assert "Real database was NOT modified" in res["message"]


class TestEndToEndPipelineIntegration:
    """Integration tests connecting Authorization -> Registry -> Trajectory -> Decision -> ExecutionGate."""

    def test_allow_pipeline_executes_tool(self, db_session):
        """End-to-end pipeline for authorized LOW risk READ action executes tool handler."""
        # 1. Setup principal in DB with logs:read scope
        principal = PrincipalModel(
            id="user_pipeline_allow",
            scope="logs:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        # 2. Authorization (A4)
        auth_context = AuthorizationContext(
            principal_id="user_pipeline_allow",
            session_id="session_allow",
            agent_id="agent_001",
        )
        auth_service = AuthorizationService(db_session)
        auth_res = auth_service.authorize(
            context=auth_context,
            action="read_logs",
            resource="logs",
        )
        assert auth_res.authorized is True

        # 3. Tool Registry (A5)
        tool = default_tool_registry.get_or_raise("read_logs")
        assert tool.action_class == ActionClass.READ

        # 4. Trajectory (A6)
        traj_engine = TrajectoryEngine(db_session, tool_registry=default_tool_registry)
        traj_res = traj_engine.evaluate_action(
            principal_id="user_pipeline_allow",
            session_id="session_allow",
            action="read_logs",
        )

        # 5. Decision Engine (A7)
        dec_engine = DecisionEngine()
        dec_res = dec_engine.evaluate(
            authorized=auth_res.authorized,
            trajectory_score=traj_res.new_score,
            action_class=tool.action_class,
        )
        assert dec_res.decision == Decision.ALLOW

        # 6. Execution Gate (A9)
        recorder = MockToolExecutionRecorder()
        gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)
        exec_context = create_execution_context(
            action_id="act_allow_e2e",
            principal_id="user_pipeline_allow",
            session_id="session_allow",
            agent_id="agent_001",
            action="read_logs",
            decision=dec_res.decision,
            trajectory_score=dec_res.trajectory_score,
            risk_band=dec_res.risk_band,
        )

        exec_result = gate.execute(exec_context, parameters={"limit": 5})

        assert exec_result.executed is True
        assert exec_result.result is not None
        assert exec_result.result["tool"] == "read_logs"
        assert recorder.was_called("read_logs") is True

    def test_unauthorized_pipeline_blocks_and_prevents_execution(self, db_session):
        """End-to-end pipeline for unauthorized action produces BLOCK and prevents tool execution."""
        # 1. Setup principal with customer:read only
        principal = PrincipalModel(
            id="user_pipeline_block",
            scope="customer:read",
            trajectory_score=0.0,
        )
        db_session.add(principal)
        db_session.commit()

        # 2. Authorization (A4) - drop_table is unauthorized
        auth_context = AuthorizationContext(
            principal_id="user_pipeline_block",
            session_id="session_block",
            agent_id="agent_001",
        )
        auth_service = AuthorizationService(db_session)
        auth_res = auth_service.authorize(
            context=auth_context,
            action="drop_table",
            resource="db_schema:core",
        )
        assert auth_res.authorized is False

        # 3. Tool Registry (A5)
        tool = default_tool_registry.get_or_raise("drop_table")

        # 4. Trajectory (A6)
        traj_engine = TrajectoryEngine(db_session, tool_registry=default_tool_registry)
        traj_res = traj_engine.evaluate_action(
            principal_id="user_pipeline_block",
            session_id="session_block",
            action="drop_table",
        )

        # 5. Decision Engine (A7) - Unauthorized produces BLOCK
        dec_engine = DecisionEngine()
        dec_res = dec_engine.evaluate(
            authorized=auth_res.authorized,
            trajectory_score=traj_res.new_score,
            action_class=tool.action_class,
        )
        assert dec_res.decision == Decision.BLOCK

        # 6. Execution Gate (A9) - BLOCK strictly prevents execution
        recorder = MockToolExecutionRecorder()
        gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)
        exec_context = create_execution_context(
            action_id="act_block_e2e",
            principal_id="user_pipeline_block",
            session_id="session_block",
            agent_id="agent_001",
            action="drop_table",
            decision=dec_res.decision,
            trajectory_score=dec_res.trajectory_score,
            risk_band=dec_res.risk_band,
        )

        exec_result = gate.execute(exec_context, parameters={"table_name": "core"})

        assert exec_result.executed is False
        assert exec_result.decision == Decision.BLOCK
        assert exec_result.result is None
        assert recorder.was_called("drop_table") is False
        assert recorder.call_count == 0

    def test_canonical_attack_sequence_eventual_block_prevents_execution(self, db_session):
        """Canonical database escalation attack: drop_table is blocked and not executed."""
        principal = PrincipalModel(
            id="attacker_e2e",
            scope="logs:read,customer:read,customer:write,permissions:write,schema:admin",
            trajectory_score=0.75,  # High risk accumulated
        )
        db_session.add(principal)
        db_session.commit()

        # Action: drop_table
        tool = default_tool_registry.get_or_raise("drop_table")
        auth_service = AuthorizationService(db_session)
        auth_res = auth_service.authorize(
            context=AuthorizationContext("attacker_e2e", "sess_atk", "agent_atk"),
            action="drop_table",
            resource=tool.resource,
        )

        # High risk trajectory
        dec_engine = DecisionEngine()
        dec_res = dec_engine.evaluate(
            authorized=auth_res.authorized,
            trajectory_score=0.75,
            action_class=tool.action_class,
        )
        assert dec_res.decision == Decision.BLOCK

        # Execution gate
        recorder = MockToolExecutionRecorder()
        gate = ToolExecutionGate(tool_registry=default_tool_registry, recorder=recorder)
        exec_context = create_execution_context(
            action_id="act_atk_final",
            principal_id="attacker_e2e",
            session_id="sess_atk",
            agent_id="agent_atk",
            action="drop_table",
            decision=dec_res.decision,
            trajectory_score=0.75,
            risk_band=RiskBand.HIGH,
        )

        exec_result = gate.execute(exec_context, parameters={"table_name": "core"})

        assert exec_result.executed is False
        assert recorder.was_called("drop_table") is False


class TestExecutionContextValidationAndEdgeCases:
    """Tests for ExecutionContext validation, handler errors, and edge case fail-closed behaviors."""

    def test_context_validation_empty_fields_raise(self):
        """ExecutionContext validates that required string fields are non-empty."""
        tool = default_tool_registry.get_or_raise("read_logs")

        with pytest.raises(ValueError, match="non-empty action_id"):
            ExecutionContext(
                action_id="",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

        with pytest.raises(ValueError, match="non-empty principal_id"):
            ExecutionContext(
                action_id="act_1",
                principal_id="   ",
                session_id="sess_1",
                agent_id="agent_1",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

        with pytest.raises(ValueError, match="non-empty session_id"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="",
                agent_id="agent_1",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

        with pytest.raises(ValueError, match="non-empty agent_id"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

        with pytest.raises(ValueError, match="non-empty action name"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

    def test_context_validation_type_checks(self):
        """ExecutionContext type checks decision, risk_band, and trusted_tool."""
        tool = default_tool_registry.get_or_raise("read_logs")

        with pytest.raises(TypeError, match="Decision enum"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="read_logs",
                decision="ALLOW",  # type: ignore[arg-type]
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool=tool,
            )

        with pytest.raises(TypeError, match="RiskBand enum"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band="LOW",  # type: ignore[arg-type]
                trusted_tool=tool,
            )

        with pytest.raises(TypeError, match="ToolDefinition"):
            ExecutionContext(
                action_id="act_1",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="read_logs",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
                trusted_tool={"name": "read_logs"},  # type: ignore[arg-type]
            )

    def test_create_execution_context_unknown_tool_raises(self):
        """create_execution_context raises KeyError if action is not in registry."""
        with pytest.raises(KeyError, match="not registered"):
            create_execution_context(
                action_id="act_unknown",
                principal_id="user_1",
                session_id="sess_1",
                agent_id="agent_1",
                action="unknown_action_tool",
                decision=Decision.ALLOW,
                trajectory_score=0.0,
                risk_band=RiskBand.LOW,
            )

    def test_execute_with_invalid_context_object_returns_block(self):
        """Passing non-ExecutionContext object returns fail-closed ToolExecutionResult."""
        gate = ToolExecutionGate()
        res = gate.execute("not_a_context")  # type: ignore[arg-type]
        assert res.executed is False
        assert res.decision == Decision.BLOCK
        assert "invalid execution context" in res.reason

    def test_execute_handler_raising_exception_fails_safely(self):
        """If a tool handler raises an exception during execution, gate catches it and fails safely."""
        def faulty_handler(**kwargs):
            raise RuntimeError("Database connection timed out during mock read")

        custom_tool = ToolDefinition(
            name="faulty_tool",
            resource="system:custom",
            action_class=ActionClass.READ,
            required_scope="custom:read",
            handler=faulty_handler,
        )
        custom_registry = ToolRegistry(tools=[custom_tool])
        gate = ToolExecutionGate(tool_registry=custom_registry)

        ctx = ExecutionContext(
            action_id="act_faulty",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="faulty_tool",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
            trusted_tool=custom_tool,
        )

        res = gate.execute(ctx)
        assert res.executed is False
        assert res.decision == Decision.ALLOW
        assert "Database connection timed out" in (res.error or "")
        assert "Tool execution failed" in res.reason

    def test_execute_tool_with_missing_handler_fails_closed(self):
        """Tool registered with None handler fails closed gracefully."""
        custom_tool = ToolDefinition(
            name="handlerless_tool",
            resource="system:custom",
            action_class=ActionClass.READ,
            required_scope="custom:read",
            handler=None,
        )
        custom_registry = ToolRegistry(tools=[custom_tool])
        gate = ToolExecutionGate(tool_registry=custom_registry)

        ctx = ExecutionContext(
            action_id="act_no_handler",
            principal_id="user_1",
            session_id="sess_1",
            agent_id="agent_1",
            action="handlerless_tool",
            decision=Decision.ALLOW,
            trajectory_score=0.1,
            risk_band=RiskBand.LOW,
            trusted_tool=custom_tool,
        )

        res = gate.execute(ctx)
        assert res.executed is False
        assert "no trusted handler registered" in res.reason

