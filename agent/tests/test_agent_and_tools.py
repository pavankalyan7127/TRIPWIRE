"""
TRIPWIRE — Unit & Integration Tests (Person B)
Built with standard unittest for zero-dependency test execution.
"""

import os
import json
import unittest
from pathlib import Path
from agent.tool_registry import ToolRegistry, ToolDefinition
from agent.demo_agent import DemoAgent


class TestToolRegistry(unittest.TestCase):
    def test_default_tools_registered(self):
        reg = ToolRegistry()
        tools = reg.list_tools()
        expected = [
            'read_logs',
            'search_customers',
            'read_customer',
            'export_customers',
            'update_customer',
            'change_permissions',
            'drop_table',
        ]
        for t in expected:
            self.assertIn(t, tools, f"Missing tool: {t}")

    def test_reversibility_classes(self):
        reg = ToolRegistry()
        self.assertEqual(reg.get('read_logs').reversibility, 'READ')
        self.assertEqual(reg.get('search_customers').reversibility, 'READ')
        self.assertEqual(reg.get('read_customer').reversibility, 'READ')
        self.assertEqual(reg.get('export_customers').reversibility, 'WRITE')
        self.assertEqual(reg.get('update_customer').reversibility, 'WRITE')
        self.assertEqual(reg.get('change_permissions').reversibility, 'DESTRUCTIVE')
        self.assertEqual(reg.get('drop_table').reversibility, 'DESTRUCTIVE')

    def test_execution_counter_safety(self):
        reg = ToolRegistry()
        self.assertEqual(reg.get('read_logs').execution_count, 0)
        res = reg.execute_tool('read_logs', {})
        self.assertEqual(res['status'], 'SUCCESS')
        self.assertEqual(reg.get('read_logs').execution_count, 1)

        reg.reset_execution_counts()
        self.assertEqual(reg.get('read_logs').execution_count, 0)


class TestScenarios(unittest.TestCase):
    def test_attack_scenario_file(self):
        scenario_path = Path(__file__).resolve().parent.parent / 'scenarios' / 'attack.json'
        self.assertTrue(scenario_path.exists())
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data['scenario_name'], 'database_escalation_attack')
        self.assertEqual(len(data['steps']), 6)
        self.assertEqual(data['steps'][0]['action'], 'read_logs')
        self.assertEqual(data['steps'][-1]['action'], 'drop_table')

    def test_legitimate_scenario_file(self):
        scenario_path = Path(__file__).resolve().parent.parent / 'scenarios' / 'legitimate.json'
        self.assertTrue(scenario_path.exists())
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data['scenario_name'], 'monthly_finance_report')
        self.assertGreaterEqual(len(data['steps']), 4)

    def test_cross_session_scenario_files(self):
        p1 = Path(__file__).resolve().parent.parent / 'scenarios' / 'cross_session_1.json'
        p2 = Path(__file__).resolve().parent.parent / 'scenarios' / 'cross_session_2.json'
        self.assertTrue(p1.exists())
        self.assertTrue(p2.exists())


class TestDemoAgentSecurityInvariants(unittest.TestCase):
    def test_blocked_action_never_executes_tool(self):
        reg = ToolRegistry()
        agent = DemoAgent(base_url='http://mock-tripwire/api/v1', tool_registry=reg)

        # Mock Tripwire response to BLOCK
        agent._send_proposal = lambda prop: {
            'action_id': 'act_test_block',
            'decision': 'BLOCK',
            'trajectory_score': 0.85,
            'risk_band': 'HIGH',
            'reversibility': 'DESTRUCTIVE',
            'reason': 'Trajectory score exceeds safety threshold',
        }

        res = agent.propose_and_execute(
            principal_id='attacker_01',
            action='drop_table',
            resource='db_schema:core',
            parameters={'table': 'customers'},
        )

        # CRITICAL SECURITY INVARIANT:
        self.assertEqual(res['decision']['decision'], 'BLOCK')
        self.assertFalse(res['tool_executed'])
        self.assertEqual(reg.get('drop_table').execution_count, 0)

    def test_allowed_action_executes_tool(self):
        reg = ToolRegistry()
        agent = DemoAgent(base_url='http://mock-tripwire/api/v1', tool_registry=reg)

        # Mock Tripwire response to ALLOW
        agent._send_proposal = lambda prop: {
            'action_id': 'act_test_allow',
            'decision': 'ALLOW',
            'trajectory_score': 0.15,
            'risk_band': 'LOW',
            'reversibility': 'READ',
            'reason': 'Authorized read operation',
        }

        res = agent.propose_and_execute(
            principal_id='user_001',
            action='read_logs',
            resource='logs',
        )

        self.assertEqual(res['decision']['decision'], 'ALLOW')
        self.assertTrue(res['tool_executed'])
        self.assertEqual(reg.get('read_logs').execution_count, 1)


if __name__ == '__main__':
    unittest.main()
