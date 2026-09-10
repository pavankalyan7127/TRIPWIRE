"""
TRIPWIRE — Phase 4 Tool Enforcement Test Suite
Verifies:
1. ALLOW -> Tool executes immediately (execution_count += 1)
2. CONFIRM -> Tool execution is delayed / held
3. CONFIRM + APPROVE -> Tool executes after human sign-off
4. CONFIRM + DENY -> Tool NEVER executes (execution_count == 0)
5. BLOCK -> Tool NEVER executes under any circumstance (execution_count == 0)
6. Multi-tool isolation across 7 contract tools
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tool_registry import ToolRegistry
from agent.demo_agent import DemoAgent


class TestPhase4ToolEnforcement(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        self.agent = DemoAgent(base_url="http://mock-tripwire/api/v1", tool_registry=self.registry)

    def test_enforcement_read_tool_allowed(self):
        """Invariant: When Tripwire allows a READ tool, handler executes and returns payload."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_read_01",
            "decision": "ALLOW",
            "trajectory_score": 0.10,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Authorized read within normal scope",
        }

        result = self.agent.propose_and_execute(
            principal_id="user_001",
            action="read_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101"},
        )

        self.assertTrue(result["tool_executed"])
        self.assertEqual(result["decision"]["decision"], "ALLOW")
        self.assertIsNotNone(result["tool_result"])
        self.assertEqual(result["tool_result"]["result"]["customer"]["id"], "cust_101")
        self.assertEqual(self.registry.get("read_customer").execution_count, 1)

    def test_enforcement_write_tool_confirm_wait(self):
        """Invariant: When Tripwire returns CONFIRM without auto-approval, tool handler does not execute."""
        self.agent.auto_approve_confirm = False
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_write_01",
            "decision": "CONFIRM",
            "trajectory_score": 0.40,
            "risk_band": "MEDIUM",
            "reversibility": "WRITE",
            "reason": "State write in medium risk context requires confirmation",
        }

        result = self.agent.propose_and_execute(
            principal_id="user_001",
            action="update_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101", "status": "FLAGGED"},
        )

        self.assertFalse(result["tool_executed"])
        self.assertIsNone(result["tool_result"])
        self.assertEqual(self.registry.get("update_customer").execution_count, 0)

    def test_enforcement_write_tool_confirm_approved(self):
        """Invariant: When human approves CONFIRM, tool handler executes and increments count."""
        self.agent.auto_approve_confirm = True
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_write_02",
            "decision": "CONFIRM",
            "trajectory_score": 0.40,
            "risk_band": "MEDIUM",
            "reversibility": "WRITE",
            "reason": "State write in medium risk context requires confirmation",
        }
        self.agent.confirm_action = lambda action_id, approved_by, approve: {
            "action_id": action_id,
            "decision": "ALLOW",
            "approved_by": approved_by,
            "execution_status": "EXECUTED",
        }

        result = self.agent.propose_and_execute(
            principal_id="user_001",
            action="update_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101", "status": "APPROVED_UPDATE"},
        )

        self.assertTrue(result["tool_executed"])
        self.assertEqual(self.registry.get("update_customer").execution_count, 1)

    def test_enforcement_destructive_tool_denied(self):
        """Invariant: When human denies CONFIRM for a destructive action, tool handler NEVER executes."""
        self.agent.auto_approve_confirm = True
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_dest_01",
            "decision": "HARD_CONFIRM",
            "trajectory_score": 0.60,
            "risk_band": "MEDIUM",
            "reversibility": "DESTRUCTIVE",
            "reason": "Destructive permission change requires verification",
        }
        # Deny approval
        self.agent.confirm_action = lambda action_id, approved_by, approve: {
            "action_id": action_id,
            "decision": "BLOCK",
            "approved_by": approved_by,
            "execution_status": "NOT_EXECUTED",
        }

        result = self.agent.propose_and_execute(
            principal_id="user_001",
            action="change_permissions",
            resource="system:permissions",
            parameters={"role": "admin", "rules": ["*"]},
        )

        self.assertFalse(result["tool_executed"])
        self.assertEqual(self.registry.get("change_permissions").execution_count, 0)

    def test_enforcement_destructive_tool_blocked(self):
        """Invariant: When Tripwire returns BLOCK (score > 0.65), drop_table is NEVER executed."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_dest_02",
            "decision": "BLOCK",
            "trajectory_score": 0.82,
            "risk_band": "HIGH",
            "reversibility": "DESTRUCTIVE",
            "reason": "Trajectory score 0.82 exceeds high-risk threshold (0.65)",
        }

        result = self.agent.propose_and_execute(
            principal_id="adversary_001",
            action="drop_table",
            resource="db_schema:core",
            parameters={"table": "customer_table"},
        )

        # CRITICAL TEST ASSERTION:
        self.assertEqual(result["decision"]["decision"], "BLOCK")
        self.assertFalse(result["tool_executed"])
        self.assertIsNone(result["tool_result"])
        self.assertEqual(self.registry.get("drop_table").execution_count, 0)

    def test_all_seven_tools_isolation(self):
        """Ensures all 7 contract tools maintain separate isolated counters."""
        for tool_name in [
            "read_logs",
            "search_customers",
            "read_customer",
            "export_customers",
            "update_customer",
            "change_permissions",
            "drop_table",
        ]:
            tool = self.registry.get(tool_name)
            self.assertIsNotNone(tool)
            self.assertEqual(tool.execution_count, 0)


if __name__ == "__main__":
    unittest.main()
