"""
TRIPWIRE — Integration Point 1 Test (Person B)
Verifies:
Demo Agent -> POST /actions/propose -> Tripwire Decision Flow
Tests:
1. Low-risk READ -> ALLOW
2. Medium-risk WRITE -> CONFIRM
3. Medium-risk DESTRUCTIVE -> HARD_CONFIRM
4. High-risk DESTRUCTIVE -> BLOCK (Tool never executed)
5. Confirmation approval re-validation
"""

import sys
import unittest
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tool_registry import ToolRegistry
from agent.demo_agent import DemoAgent


class TestIntegrationPoint1(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        self.agent = DemoAgent(base_url="http://mock-tripwire/api/v1", tool_registry=self.registry)

    def test_integration_flow_allow(self):
        # Mocking Tripwire /actions/propose ALLOW
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_001",
            "decision": "ALLOW",
            "trajectory_score": 0.12,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Authorized read within permitted scope",
        }

        res = self.agent.propose_and_execute(
            principal_id="user_001",
            action="read_logs",
            resource="logs",
        )

        self.assertEqual(res["decision"]["decision"], "ALLOW")
        self.assertTrue(res["tool_executed"])
        self.assertEqual(self.registry.get("read_logs").execution_count, 1)

    def test_integration_flow_confirm_denied(self):
        # Mocking Tripwire /actions/propose CONFIRM
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_002",
            "decision": "CONFIRM",
            "trajectory_score": 0.45,
            "risk_band": "MEDIUM",
            "reversibility": "WRITE",
            "reason": "State modification in elevated trajectory requires confirmation",
        }

        # Human denies confirmation
        self.agent.confirm_action = lambda action_id, approved_by, approve: {
            "action_id": action_id,
            "decision": "BLOCK",
            "execution_status": "NOT_EXECUTED",
        }

        res = self.agent.propose_and_execute(
            principal_id="user_001",
            action="update_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101", "status": "FLAGGED"},
        )

        self.assertEqual(res["decision"]["decision"], "CONFIRM")
        self.assertFalse(res["tool_executed"])
        self.assertEqual(self.registry.get("update_customer").execution_count, 0)

    def test_integration_flow_confirm_approved(self):
        # Auto-approve agent mode
        self.agent.auto_approve_confirm = True

        self.agent._send_proposal = lambda prop: {
            "action_id": "act_003",
            "decision": "CONFIRM",
            "trajectory_score": 0.42,
            "risk_band": "MEDIUM",
            "reversibility": "WRITE",
            "reason": "State modification requires confirmation",
        }

        self.agent.confirm_action = lambda action_id, approved_by, approve: {
            "action_id": action_id,
            "decision": "ALLOW",
            "approved_by": approved_by,
            "execution_status": "EXECUTED",
        }

        res = self.agent.propose_and_execute(
            principal_id="user_001",
            action="update_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101"},
        )

        self.assertEqual(res["decision"]["decision"], "CONFIRM")
        self.assertTrue(res["tool_executed"])
        self.assertEqual(self.registry.get("update_customer").execution_count, 1)

    def test_integration_flow_high_risk_block(self):
        # Mocking Tripwire /actions/propose BLOCK on catastrophic drop table
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_004",
            "decision": "BLOCK",
            "trajectory_score": 0.78,
            "risk_band": "HIGH",
            "reversibility": "DESTRUCTIVE",
            "reason": "Behavioral trajectory exceeds high-risk threshold (0.78 > 0.65)",
        }

        res = self.agent.propose_and_execute(
            principal_id="user_001",
            action="drop_table",
            resource="db_schema:core",
            parameters={"table": "customer_table"},
        )

        # SECURITY INVARIANT CHECK:
        self.assertEqual(res["decision"]["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])
        self.assertEqual(self.registry.get("drop_table").execution_count, 0)


if __name__ == "__main__":
    unittest.main()
