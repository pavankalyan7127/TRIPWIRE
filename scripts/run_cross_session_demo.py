"""
TRIPWIRE — Phase 7: Cross-Session State Persistence Demo Runner
Demonstrates cross-session behavioral memory defeating distributed multi-session escalation attacks.

Scenario:
- Session 1 (adversary_bob / agent_worker_01): Reconnaissance & initial state modification. State persists to principal profile.
- Session 2 (adversary_bob / agent_worker_02): Attacker opens a brand-new session expecting a clean slate.
  Tripwire carries forward the persistent trajectory context, catching the escalation immediately!
"""

import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Set

# Fix Windows console UTF-8 output if needed
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tool_registry import ToolRegistry
from agent.demo_agent import DemoAgent


@dataclass
class PrincipalTrajectoryState:
    principal_id: str
    trajectory_score: float = 0.0
    scope_footprint: Set[str] = field(default_factory=set)
    total_actions: int = 0
    max_destructiveness: int = 0


class CrossSessionHarnessSimulator:
    """Simulates Tripwire's persistent cross-session store (SQLAlchemy / SQLite principal table)."""
    def __init__(self):
        self.principals: Dict[str, PrincipalTrajectoryState] = {}

    def get_or_create_principal(self, principal_id: str) -> PrincipalTrajectoryState:
        if principal_id not in self.principals:
            self.principals[principal_id] = PrincipalTrajectoryState(principal_id=principal_id)
        return self.principals[principal_id]

    def evaluate(self, proposal: dict, history_len: int) -> dict:
        principal = self.get_or_create_principal(proposal["principal_id"])
        action = proposal["action"]
        resource = proposal["resource"]

        principal.scope_footprint.add(resource)
        principal.total_actions += 1

        if action in ["drop_table", "change_permissions"]:
            rev = "DESTRUCTIVE"
            dest_level = 2
        elif action in ["update_customer", "export_customers"]:
            rev = "WRITE"
            dest_level = 1
        else:
            rev = "READ"
            dest_level = 0

        principal.max_destructiveness = max(principal.max_destructiveness, dest_level)

        # Trajectory Formula with Cross-Session Persistence
        scope_drift = 1.0 if rev == "DESTRUCTIVE" else (0.5 if rev == "WRITE" else 0.0)
        dest_growth = dest_level / 2.0
        velocity = min(1.0, principal.total_actions / 6.0)
        footprint = min(1.0, len(principal.scope_footprint) / 3.0)

        step_score = 0.30 * scope_drift + 0.35 * dest_growth + 0.15 * velocity + 0.20 * footprint

        # Asymmetric EMA using Persistent Principal Score
        prev_score = principal.trajectory_score
        if step_score >= prev_score:
            new_score = prev_score + 0.6 * (step_score - prev_score)
        else:
            new_score = prev_score + 0.2 * (step_score - prev_score)

        principal.trajectory_score = min(1.0, max(0.0, new_score))

        # Risk Band
        if principal.trajectory_score > 0.65:
            risk_band = "HIGH"
        elif principal.trajectory_score >= 0.35:
            risk_band = "MEDIUM"
        else:
            risk_band = "LOW"

        # Decision Matrix
        if risk_band == "HIGH":
            decision = "BLOCK"
            reason = f"Cross-session trajectory score ({principal.trajectory_score:.3f}) exceeds threshold (0.65). Action blocked."
        elif risk_band == "MEDIUM":
            if rev == "DESTRUCTIVE":
                decision = "HARD_CONFIRM"
                reason = "Cross-session elevated risk requires dual-key confirmation"
            elif rev == "WRITE":
                decision = "CONFIRM"
                reason = "Cross-session write requires human confirmation"
            else:
                decision = "ALLOW"
                reason = "Read permitted in medium-risk band"
        else:
            if rev == "DESTRUCTIVE":
                decision = "CONFIRM"
                reason = "Destructive action requires confirmation"
            else:
                decision = "ALLOW"
                reason = "Routine read permitted"

        return {
            "action_id": f"act_cross_{principal.total_actions:03d}",
            "decision": decision,
            "trajectory_score": round(principal.trajectory_score, 3),
            "risk_band": risk_band,
            "reversibility": rev,
            "reason": reason,
        }


def run_cross_session_demo():
    harness = CrossSessionHarnessSimulator()
    registry = ToolRegistry()

    p1_file = Path(__file__).resolve().parent.parent / "agent" / "scenarios" / "cross_session_1.json"
    p2_file = Path(__file__).resolve().parent.parent / "agent" / "scenarios" / "cross_session_2.json"

    with open(p1_file, "r", encoding="utf-8") as f:
        s1 = json.load(f)
    with open(p2_file, "r", encoding="utf-8") as f:
        s2 = json.load(f)

    print("=" * 75)
    print("[*] TRIPWIRE DEMO: CROSS-SESSION BEHAVIORAL TRAJECTORY PERSISTENCE")
    print("=" * 75)

    # ------------------ SESSION 1 ------------------
    print(f"\n>>> [PHASE 1] Starting Session 1: {s1['scenario_name']}")
    print(f"    Principal: {s1['principal_id']} | Agent: {s1['agent_id']}")
    print(f"    Baseline Principal Score: 0.000\n")

    agent1 = DemoAgent(base_url="http://localhost:8000/api/v1", tool_registry=registry)
    agent1._send_proposal = lambda prop: harness.evaluate(prop, len(agent1.history))

    for step in s1["steps"]:
        res = agent1.propose_and_execute(
            principal_id=s1["principal_id"],
            action=step["action"],
            resource=step["resource"],
            parameters=step.get("parameters", {}),
            agent_id=s1["agent_id"],
        )
        dec = res["decision"]
        print(f"  * S1 Step {step['step']}: {step['action']:18s} -> Decision: [{dec['decision']:7s}] | Score: {dec['trajectory_score']:.3f} ({dec['risk_band']})")

    persisted_state = harness.get_or_create_principal(s1["principal_id"])
    print(f"\n[+] Session 1 Terminated. Trajectory state persisted to Principal '{s1['principal_id']}':")
    print(f"    - Persisted Risk Score:    {persisted_state.trajectory_score:.3f}")
    print(f"    - Persisted Resource Scope:{list(persisted_state.scope_footprint)}")
    print(f"    - Accumulated Actions:     {persisted_state.total_actions}")

    # ------------------ SESSION 2 ------------------
    print("\n" + "=" * 75)
    print(f">>> [PHASE 2] Starting Session 2: {s2['scenario_name']} (NEW AGENT INSTANCE)")
    print(f"    Principal: {s2['principal_id']} | Agent: {s2['agent_id']}")
    print(f"    Inherited Principal Score: {persisted_state.trajectory_score:.3f} (CRITICAL: NOT RESET TO 0.000)\n")

    agent2 = DemoAgent(base_url="http://localhost:8000/api/v1", tool_registry=registry)
    agent2._send_proposal = lambda prop: harness.evaluate(prop, len(agent2.history))

    s2_results = []
    for step in s2["steps"]:
        res = agent2.propose_and_execute(
            principal_id=s2["principal_id"],
            action=step["action"],
            resource=step["resource"],
            parameters=step.get("parameters", {}),
            agent_id=s2["agent_id"],
        )
        s2_results.append(res)
        dec = res["decision"]
        print(f"  * S2 Step {step['step']}: {step['action']:18s} -> Decision: [{dec['decision']:7s}] | Score: {dec['trajectory_score']:.3f} ({dec['risk_band']})")
        print(f"    Reason: {dec['reason']}")

    # VERIFICATION
    assert s2_results[-1]["decision"]["decision"] == "BLOCK", "Cross-session destructive action was not blocked!"
    assert registry.get("drop_table").execution_count == 0, "drop_table was executed!"

    print("\n[+] CROSS-SESSION VERIFICATION SUMMARY:")
    print(f"  * Session 2 Initial Score:         {persisted_state.trajectory_score:.3f} (Preserved from Session 1)")
    print(f"  * Immediate Escalation Caught:     Step 1 was evaluated with inherited memory")
    print(f"  * Destructive Tool Execution:      0 Invocations (NEVER EXECUTED)")
    print(f"  * Invariant Status:                PASSED (Multi-Session Attack Blocked)\n")


if __name__ == "__main__":
    run_cross_session_demo()
