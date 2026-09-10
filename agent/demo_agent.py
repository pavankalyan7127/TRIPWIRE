"""
TRIPWIRE — Demo Agent
Person B: Agent / Tools / Frontend Foundation

The Demo Agent coordinates simulated or real scenario execution against the Tripwire security harness.
Crucial Invariant: The agent does NOT have a direct route to tools. Every tool invocation must pass through Tripwire.
"""

import json
import os
import requests
from typing import Dict, Any, List, Optional
from agent.tool_registry import ToolRegistry, default_tool_registry


class DemoAgent:
    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        tool_registry: Optional[ToolRegistry] = None,
        auto_approve_confirm: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.tools = tool_registry or default_tool_registry
        self.auto_approve_confirm = auto_approve_confirm
        self.session_id: Optional[str] = None
        self.history: List[Dict[str, Any]] = []

    def create_session(self, principal_id: str, agent_id: str) -> Dict[str, Any]:
        """
        Calls POST /api/v1/sessions to initialize session context.
        """
        url = f"{self.base_url}/sessions"
        payload = {
            "principal_id": principal_id,
            "agent_id": agent_id,
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code in [200, 201]:
                data = resp.json()
                self.session_id = data.get("session_id")
                return data
            else:
                raise RuntimeError(f"Failed to create session: HTTP {resp.status_code} - {resp.text}")
        except requests.exceptions.RequestException as e:
            # Fallback placeholder session if backend is not yet running
            self.session_id = f"session_mock_{principal_id}"
            return {
                "session_id": self.session_id,
                "principal_id": principal_id,
                "agent_id": agent_id,
                "trajectory_score": 0.0,
                "risk_band": "LOW",
                "mock_fallback": True,
                "error": str(e),
            }

    def propose_and_execute(
        self,
        principal_id: str,
        action: str,
        resource: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        The Core Security Flow:
        1. Agent sends ActionProposal to Tripwire harness.
        2. Tripwire evaluates (Auth, Reversibility, Trajectory) -> returns Decision.
        3. If ALLOW: execute tool.
        4. If CONFIRM: request confirmation, execute only if approved.
        5. If BLOCK: do NOT execute tool. Tool execution count = 0.
        """
        if not self.session_id:
            self.create_session(principal_id=principal_id, agent_id=agent_id or "agent_001")

        params = parameters or {}
        proposal = {
            "principal_id": principal_id,
            "session_id": self.session_id,
            "agent_id": agent_id or "agent_001",
            "action": action,
            "resource": resource,
            "parameters": params,
        }

        # Step 1: Send proposal to Tripwire
        decision_data = self._send_proposal(proposal)

        decision = decision_data.get("decision", "BLOCK")
        action_id = decision_data.get("action_id", "act_unknown")
        
        step_result = {
            "proposal": proposal,
            "decision": decision_data,
            "tool_executed": False,
            "tool_result": None,
            "confirmation": None,
        }

        # Step 2: Handle Tripwire Decision
        if decision == "ALLOW":
            tool_res = self.tools.execute_tool(action, params)
            step_result["tool_executed"] = True
            step_result["tool_result"] = tool_res

        elif decision in ["CONFIRM", "HARD_CONFIRM"]:
            if self.auto_approve_confirm:
                confirm_res = self.confirm_action(action_id, approved_by=f"admin_{principal_id}", approve=True)
                step_result["confirmation"] = confirm_res
                if confirm_res.get("decision") == "ALLOW":
                    tool_res = self.tools.execute_tool(action, params)
                    step_result["tool_executed"] = True
                    step_result["tool_result"] = tool_res
            else:
                step_result["tool_executed"] = False
                step_result["reason"] = f"Action {action} held in {decision} state awaiting human approval"

        elif decision == "BLOCK":
            # SECURITY INVARIANT: Tool handler is NEVER invoked
            step_result["tool_executed"] = False
            step_result["blocked_reason"] = decision_data.get("reason", "Blocked by Tripwire security harness")

        self.history.append(step_result)
        return step_result

    def _send_proposal(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/actions/propose"
        try:
            resp = requests.post(url, json=proposal, timeout=5)
            if resp.status_code == 200:
                return resp.json()
            else:
                return {
                    "action_id": "err_resp",
                    "decision": "BLOCK",
                    "trajectory_score": 1.0,
                    "risk_band": "HIGH",
                    "reversibility": "DESTRUCTIVE",
                    "reason": f"Tripwire rejected proposal: HTTP {resp.status_code} - {resp.text}",
                }
        except requests.exceptions.RequestException as e:
            return {
                "action_id": "err_net",
                "decision": "BLOCK",
                "trajectory_score": 0.0,
                "risk_band": "LOW",
                "reversibility": "READ",
                "reason": f"Connection error to Tripwire backend ({self.base_url}): {e}",
            }

    def confirm_action(self, action_id: str, approved_by: str = "admin_001", approve: bool = True) -> Dict[str, Any]:
        """
        Sends human confirmation decision to POST /api/v1/actions/{action_id}/confirm
        """
        url = f"{self.base_url}/actions/{action_id}/confirm"
        payload = {
            "approved_by": approved_by,
            "approve": approve,
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                return resp.json()
            return {
                "action_id": action_id,
                "decision": "BLOCK",
                "execution_status": "NOT_EXECUTED",
                "error": resp.text,
            }
        except requests.exceptions.RequestException as e:
            return {
                "action_id": action_id,
                "decision": "ALLOW" if approve else "BLOCK",
                "execution_status": "EXECUTED" if approve else "NOT_EXECUTED",
                "mock_fallback": True,
            }

    def load_and_run_scenario(self, scenario_path: str) -> List[Dict[str, Any]]:
        """
        Loads a scenario JSON and executes each step in sequence through Tripwire.
        """
        if not os.path.exists(scenario_path):
            raise FileNotFoundError(f"Scenario file not found: {scenario_path}")

        with open(scenario_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        principal_id = data.get("principal_id", "user_001")
        agent_id = data.get("agent_id", "agent_001")
        steps = data.get("steps", [])

        # Reset session
        self.create_session(principal_id=principal_id, agent_id=agent_id)
        results = []

        for step in steps:
            action = step["action"]
            resource = step["resource"]
            params = step.get("parameters", {})
            res = self.propose_and_execute(
                principal_id=principal_id,
                action=action,
                resource=resource,
                parameters=params,
                agent_id=agent_id,
            )
            results.append(res)

        return results
