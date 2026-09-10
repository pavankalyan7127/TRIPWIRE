"""
TRIPWIRE — Phase 8: Master End-to-End Test Suite (Person B)
Comprehensive testing covering all 6 MVP security invariants and scenarios:
1. Authorization & Scope Interception
2. Reversibility Gate (READ, WRITE, DESTRUCTIVE)
3. Trajectory Score Progression & Thresholds (LOW, MED, HIGH)
4. Cross-Session Behavioral Memory Persistence
5. Zero-Bypass Tool Enforcement (0 Invocations on BLOCK)
6. Tamper-evident Audit Trail Generation
7. Attack Scenario & Legitimate Scenario End-to-End Execution
"""

import sys
import json
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tool_registry import ToolRegistry
from agent.demo_agent import DemoAgent
from scripts.run_attack_demo import run_attack_demo
from scripts.run_legitimate_demo import run_legitimate_demo
from scripts.run_cross_session_demo import run_cross_session_demo


class TestPhase8E2EMaster(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        self.agent = DemoAgent(base_url="http://mock-tripwire/api/v1", tool_registry=self.registry)

    # 1. AUTHORIZATION TESTS
    def test_e2e_authorization_scope_allowed(self):
        """Authorized action with valid principal scope executes successfully."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_auth_01",
            "decision": "ALLOW",
            "trajectory_score": 0.10,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Authorized read within user_001 scope",
        }
        res = self.agent.propose_and_execute(
            principal_id="user_001",
            action="read_customer",
            resource="db_records:customer_table",
            parameters={"id": "cust_101"},
        )
        self.assertEqual(res["decision"]["decision"], "ALLOW")
        self.assertTrue(res["tool_executed"])
        self.assertEqual(self.registry.get("read_customer").execution_count, 1)

    def test_e2e_authorization_scope_denied(self):
        """Unauthorized action is blocked and underlying tool never executes."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_auth_02",
            "decision": "BLOCK",
            "trajectory_score": 0.10,
            "risk_band": "LOW",
            "reversibility": "DESTRUCTIVE",
            "reason": "Principal lacks db:admin scope for drop_table",
        }
        res = self.agent.propose_and_execute(
            principal_id="restricted_user",
            action="drop_table",
            resource="db_schema:core",
        )
        self.assertEqual(res["decision"]["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])
        self.assertEqual(self.registry.get("drop_table").execution_count, 0)

    # 2. REVERSIBILITY GATE TESTS
    def test_e2e_reversibility_read_zero_friction(self):
        """READ action in low risk band requires no confirmation."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_rev_01",
            "decision": "ALLOW",
            "trajectory_score": 0.05,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Safe read operation",
        }
        res = self.agent.propose_and_execute("user_001", "read_logs", "logs")
        self.assertEqual(res["decision"]["decision"], "ALLOW")
        self.assertTrue(res["tool_executed"])

    def test_e2e_reversibility_destructive_gate(self):
        """DESTRUCTIVE action in medium risk requires HARD_CONFIRM."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_rev_02",
            "decision": "HARD_CONFIRM",
            "trajectory_score": 0.55,
            "risk_band": "MEDIUM",
            "reversibility": "DESTRUCTIVE",
            "reason": "Destructive permission change requires human approval",
        }
        res = self.agent.propose_and_execute("user_001", "change_permissions", "system:permissions")
        self.assertEqual(res["decision"]["decision"], "HARD_CONFIRM")
        self.assertFalse(res["tool_executed"])

    # 3. TRAJECTORY & EMA THRESHOLD TESTS
    def test_e2e_attack_scenario_blocked(self):
        """Full Boiling Frog Attack Scenario must be intercepted on drop_table."""
        results = run_attack_demo(verbose=False)
        self.assertEqual(len(results), 6)
        self.assertEqual(results[-1]["decision"]["decision"], "BLOCK")
        self.assertGreater(results[-1]["decision"]["trajectory_score"], 0.65)
        self.assertFalse(results[-1]["tool_executed"])

    def test_e2e_legitimate_scenario_succeeds(self):
        """Full Legitimate Scenario must complete 100% with 0 false blocks."""
        results = run_legitimate_demo(verbose=False)
        self.assertEqual(len(results), 4)
        for r in results:
            self.assertNotEqual(r["decision"]["decision"], "BLOCK")
            self.assertTrue(r["tool_executed"])

    # 4. CROSS-SESSION MEMORY TESTS
    def test_e2e_cross_session_memory(self):
        """Cross-session state persists and terminates dangerous execution in session 2."""
        # This function executes both sessions and verifies assertions
        run_cross_session_demo()

    # 5. AUDIT TRAIL LOGGING
    def test_e2e_audit_trail_history(self):
        """Demo agent records full proposal history and decision parameters."""
        self.agent._send_proposal = lambda prop: {
            "action_id": "act_audit_01",
            "decision": "ALLOW",
            "trajectory_score": 0.15,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Audit test",
        }
        self.agent.propose_and_execute("audit_user", "search_customers", "db_records:customer_table", {"tier": "Pro"})
        self.assertEqual(len(self.agent.history), 1)
        self.assertEqual(self.agent.history[0]["proposal"]["principal_id"], "audit_user")
        self.assertEqual(self.agent.history[0]["proposal"]["action"], "search_customers")


if __name__ == "__main__":
    unittest.main()
