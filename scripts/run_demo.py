"""
TRIPWIRE — CLI Demo Runner
Person B: Scenario Execution & Verification Script
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tool_registry import default_tool_registry
from agent.demo_agent import DemoAgent


def main():
    parser = argparse.ArgumentParser(description="TRIPWIRE Scenario Runner")
    parser.add_argument(
        "--scenario",
        type=str,
        choices=["attack", "legitimate", "cross_session_1", "cross_session_2"],
        default="attack",
        help="Scenario to run",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="http://localhost:8000/api/v1",
        help="Tripwire backend API base URL",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto approve CONFIRM decisions (for automated CI testing)",
    )
    args = parser.parse_args()

    scenario_file = Path(__file__).resolve().parent.parent / "agent" / "scenarios" / f"{args.scenario}.json"
    if not scenario_file.exists():
        print(f"[!] Error: Scenario file {scenario_file} not found.")
        sys.exit(1)

    print("=" * 60)
    print(f"[*] TRIPWIRE DEMO RUNNER — Running Scenario: {args.scenario}")
    print(f"[*] Target Backend: {args.base_url}")
    print("=" * 60)

    agent = DemoAgent(
        base_url=args.base_url,
        tool_registry=default_tool_registry,
        auto_approve_confirm=args.auto_approve,
    )

    results = agent.load_and_run_scenario(str(scenario_file))

    print(f"\n[+] Finished running {len(results)} steps.\n")
    for idx, r in enumerate(results, 1):
        prop = r["proposal"]
        decision = r["decision"]
        print(f"Step {idx}: {prop['action']} on {prop['resource']}")
        print(f"  -> Decision: {decision.get('decision')} | Risk: {decision.get('risk_band')} | Score: {decision.get('trajectory_score')}")
        print(f"  -> Reason: {decision.get('reason')}")
        print(f"  -> Tool Executed: {r['tool_executed']}")
        print("-" * 40)

    print("\n[*] Final Tool Execution Statistics:")
    for tool_name, info in default_tool_registry.list_tools().items():
        print(f"  - {tool_name:20s}: executed {info['execution_count']} times")


if __name__ == "__main__":
    main()
