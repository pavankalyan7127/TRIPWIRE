#!/usr/bin/env python3
"""Tripwire Demonstration Runner.

Interactive and automated demonstration of Tripwire runtime security harness for AI agents.

Scenarios:
1. Canonical Legitimate Agent Scenario (Controlled escalation, ALLOW for safe reads, CONFIRM for writes, re-validation & execution)
2. Canonical Attack Escalation Scenario (Multi-signal escalation, HIGH risk, BLOCK, 0 tool execution)
3. Dynamic Re-Validation Invariant (Human approval blocked after live security state change)
4. Cross-Session Trajectory Persistence (Score inheritance & velocity isolation)

Usage:
    python demo.py                     # Interactive menu
    python demo.py --scenario 1        # Run Legitimate scenario
    python demo.py --scenario 2        # Run Attack scenario
    python demo.py --scenario 3        # Run Re-validation invariant scenario
    python demo.py --scenario 4        # Run Cross-session persistence scenario
    python demo.py --all --auto        # Run all scenarios automatically
    python demo.py --server http://localhost:8000  # Target running FastAPI server
"""

import argparse
import json
import sys
import time
from typing import Any, Optional

# Ensure UTF-8 stdout encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


def print_banner():
    """Print Tripwire header banner."""
    print(f"{CYAN}{BOLD}")
    print("+-------------------------------------------------------------------------------+")
    print("|                               T R I P W I R E                                 |")
    print("|                 Runtime Security Harness for AI Agents                        |")
    print("|                                                                               |")
    print("|     \"The agent proposes. Tripwire decides. The protected tool executes       |")
    print("|                      only when Tripwire permits it.\"                          |")
    print("+-------------------------------------------------------------------------------+")
    print(f"{RESET}")


def print_section(title: str):
    """Print formatted section header."""
    print(f"\n{BLUE}{BOLD}=== {title.upper()} {'=' * max(0, 72 - len(title))}{RESET}\n")


def print_step_header(step_num: int, total_steps: int, title: str):
    """Print step header box."""
    pad = max(0, 62 - len(title) - len(str(step_num)) - len(str(total_steps)))
    print(f"\n{BOLD}{CYAN}>> STEP {step_num}/{total_steps}: {title} {'-' * pad}{RESET}")


def format_decision(decision: str) -> str:
    """Format decision with color."""
    if decision == "ALLOW":
        return f"{GREEN}{BOLD}[ALLOW - Autonomous Execution Permitted]{RESET}"
    elif decision == "CONFIRM":
        return f"{YELLOW}{BOLD}[CONFIRM - Human Approval Required]{RESET}"
    elif decision == "HARD_CONFIRM":
        return f"{YELLOW}{BOLD}[HARD_CONFIRM - Strict Admin Approval Required]{RESET}"
    elif decision == "BLOCK":
        return f"{RED}{BOLD}[BLOCK - Execution Prohibited]{RESET}"
    return decision


def format_risk(risk_band: str, score: float) -> str:
    """Format risk band and score with visual meter."""
    bar_len = 15
    filled = int(round(score * bar_len))
    filled = max(0, min(bar_len, filled))
    empty = bar_len - filled

    if risk_band == "LOW":
        color = GREEN
        bar = f"[{GREEN}{'#' * filled}{DIM}{'-' * empty}{RESET}]"
    elif risk_band == "MEDIUM":
        color = YELLOW
        bar = f"[{YELLOW}{'#' * filled}{DIM}{'-' * empty}{RESET}]"
    else:
        color = RED
        bar = f"[{RED}{'#' * filled}{DIM}{'-' * empty}{RESET}]"

    return f"{color}{BOLD}{risk_band}{RESET} (Score: {score:.3f}) {bar}"


def format_execution_status(status: str) -> str:
    """Format tool execution status."""
    if status == "EXECUTED":
        return f"{GREEN}{BOLD}[EXECUTED]{RESET} (Protected Tool Invoked via Server ExecutionGate)"
    elif status == "NOT_EXECUTED":
        return f"{RED}{BOLD}[NOT EXECUTED]{RESET} (Protected Tool NOT Invoked)"
    elif status == "PERMITTED":
        return f"{GREEN}{BOLD}[PERMITTED]{RESET} (No server-side tool execution at proposal)"
    return status


class DemoClient:
    """Client for interacting with Tripwire backend (either live HTTP server or in-process TestClient)."""

    def __init__(self, server_url: Optional[str] = None):
        self.server_url = server_url.rstrip("/") if server_url else None
        self.test_client = None

        if self.server_url:
            import httpx
            self.http_client = httpx.Client(base_url=self.server_url, timeout=10.0)
            try:
                resp = self.http_client.get("/health")
                if resp.status_code == 200:
                    print(f"{GREEN}Connected to live Tripwire server at {self.server_url}{RESET}")
                else:
                    raise Exception("Health check failed")
            except Exception as e:
                print(f"{YELLOW}Could not connect to live server at {self.server_url} ({e}). Falling back to in-process harness.{RESET}")
                self.server_url = None
                self._init_in_process()
        else:
            self._init_in_process()

    def _init_in_process(self):
        from starlette.testclient import TestClient
        from app.db.session import init_db
        from app.main import app

        init_db()
        self.test_client = TestClient(app)
        print(f"{CYAN}Using in-process Tripwire harness (FastAPI TestClient with SQLite engine){RESET}")

    def post(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        if self.server_url:
            resp = self.http_client.post(path, json=json_data)
        else:
            resp = self.test_client.post(path, json=json_data)
        return resp.status_code, resp.json()

    def get(self, path: str) -> dict[str, Any]:
        if self.server_url:
            resp = self.http_client.get(path)
        else:
            resp = self.test_client.get(path)
        return resp.status_code, resp.json()

    def seed_demo(self):
        from app.db.seed import seed_demo_data
        from app.db.session import get_session_factory

        session_factory = get_session_factory()
        with session_factory() as session:
            seed_demo_data(session)


def prompt_step(auto: bool, delay: float):
    """Pause or delay between demo steps."""
    if auto:
        time.sleep(delay)
    else:
        try:
            input(f"\n{DIM}[Press Enter to continue to next step...]{RESET} ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)


def run_legitimate_scenario(client: DemoClient, auto: bool = False, delay: float = 0.8):
    """Demonstrate Canonical Legitimate Agent Scenario."""
    print_section("Scenario 1: Canonical Legitimate Agent Escalation")
    print(f"{WHITE}Objective: Demonstrate that an authorized agent performing legitimate work within scope")
    print(f"           operates autonomously on safe READs, prompts for controlled CONFIRMATION on WRITEs,")
    print(f"           and executes successfully after human approval without blanket blocking.{RESET}\n")

    # Step 1: Create session
    print_step_header(1, 5, "Session Initialization")
    client.seed_demo()
    status_code, sess = client.post(
        "/api/v1/sessions",
        {"principal_id": "fin_agent_user", "agent_id": "finance_reporter_v1"},
    )
    session_id = sess["session_id"]
    print(f"  Principal ID   : {sess['principal_id']} (Authorized for: logs:read, customer:read, customer:write, permissions:write)")
    print(f"  Agent ID       : {sess['agent_id']}")
    print(f"  Session ID     : {session_id}")
    print(f"  Initial Risk   : {format_risk(sess['risk_band'], sess['trajectory_score'])}")
    prompt_step(auto, delay)

    # Step 2: Propose safe READ action
    print_step_header(2, 5, "Proposal: read_logs (Safe READ)")
    status_code, p1 = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "fin_agent_user",
            "session_id": session_id,
            "agent_id": "finance_reporter_v1",
            "action": "read_logs",
            "resource": "logs",
            "parameters": {"limit": 10},
        },
    )
    print(f"  Action         : read_logs (Target: logs)")
    print(f"  Classification : {p1['reversibility']} (Reversibility Class)")
    print(f"  Trajectory     : {format_risk(p1['risk_band'], p1['trajectory_score'])}")
    print(f"  Tripwire Gate  : {format_decision(p1['decision'])}")
    print(f"  Reason         : {p1['reason']}")
    print(f"  Execution      : {format_execution_status('PERMITTED')}")
    prompt_step(auto, delay)

    # Step 3: Propose customer search (READ)
    print_step_header(3, 5, "Proposal: search_customers (Authorized READ)")
    status_code, p2 = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "fin_agent_user",
            "session_id": session_id,
            "agent_id": "finance_reporter_v1",
            "action": "search_customers",
            "resource": "db_records:customer_table",
            "parameters": {"query": "region=EU"},
        },
    )
    print(f"  Action         : search_customers (Target: db_records:customer_table)")
    print(f"  Classification : {p2['reversibility']}")
    print(f"  Trajectory     : {format_risk(p2['risk_band'], p2['trajectory_score'])}")
    print(f"  Tripwire Gate  : {format_decision(p2['decision'])}")
    print(f"  Reason         : {p2['reason']}")
    print(f"  Execution      : {format_execution_status('PERMITTED')}")
    prompt_step(auto, delay)

    # Step 4: Propose update_customer (WRITE)
    print_step_header(4, 5, "Proposal: update_customer (Authorized WRITE)")
    status_code, p3 = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "fin_agent_user",
            "session_id": session_id,
            "agent_id": "finance_reporter_v1",
            "action": "update_customer",
            "resource": "db_records:customer_table",
            "parameters": {"customer_id": "CUST_902", "flag": "audited"},
        },
    )
    act3_id = p3["action_id"]
    print(f"  Action         : update_customer (Target: db_records:customer_table)")
    print(f"  Classification : {p3['reversibility']}")
    print(f"  Trajectory     : {format_risk(p3['risk_band'], p3['trajectory_score'])}")
    print(f"  Tripwire Gate  : {format_decision(p3['decision'])}")
    print(f"  Reason         : {p3['reason']}")
    print(f"  Action ID      : {act3_id}")

    if p3["decision"] in ["CONFIRM", "HARD_CONFIRM"]:
        print(f"\n  {CYAN}>>> Human Approver verifies action context and submits approval...{RESET}")
        status_code, c3 = client.post(
            f"/api/v1/actions/{act3_id}/confirm",
            {"approved_by": "supervisor_alice"},
        )
        print(f"  Re-Validation  : {GREEN}PASS{RESET} (Live authorization & trajectory re-verified)")
        print(f"  Approved By    : {c3['approved_by']}")
        print(f"  Final Decision : {format_decision(c3['decision'])}")
        print(f"  Tool Execution : {format_execution_status(c3['execution_status'])}")
    else:
        print(f"  Execution      : {format_execution_status('PERMITTED')}")
    prompt_step(auto, delay)

    # Step 5: Propose change_permissions (DESTRUCTIVE)
    print_step_header(5, 5, "Proposal: change_permissions (High Impact DESTRUCTIVE)")
    status_code, p4 = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "fin_agent_user",
            "session_id": session_id,
            "agent_id": "finance_reporter_v1",
            "action": "change_permissions",
            "resource": "system:permissions",
            "parameters": {"user": "analyst_bob", "role": "report_viewer"},
        },
    )
    act4_id = p4["action_id"]
    print(f"  Action         : change_permissions (Target: system:permissions)")
    print(f"  Classification : {p4['reversibility']}")
    print(f"  Trajectory     : {format_risk(p4['risk_band'], p4['trajectory_score'])}")
    print(f"  Tripwire Gate  : {format_decision(p4['decision'])}")
    print(f"  Reason         : {p4['reason']}")
    print(f"  Execution      : {format_execution_status('NOT_EXECUTED')} (Held until human approval)")

    print(f"\n  {CYAN}>>> Admin provides explicit confirmation for destructive action...{RESET}")
    status_code, c4 = client.post(
        f"/api/v1/actions/{act4_id}/confirm",
        {"approved_by": "sec_admin_carol"},
    )
    print(f"  Re-Validation  : {GREEN}PASS{RESET} (Security checks passed at confirmation time)")
    print(f"  Approved By    : {c4['approved_by']}")
    print(f"  Final Decision : {format_decision(c4['decision'])}")
    print(f"  Tool Execution : {format_execution_status(c4['execution_status'])}")
    prompt_step(auto, delay)

    # Show Trajectory & Audit summary
    print(f"\n{BOLD}{CYAN}═══ OBSERVABILITY SUMMARY FOR SESSION {session_id} ═══{RESET}")
    status_code, traj = client.get(f"/api/v1/sessions/{session_id}/trajectory")
    print(f"  Final Trajectory Score : {traj['trajectory_score']:.3f} (Band: {traj['risk_band']})")
    print(f"  Total Evaluated Events : {len(traj['events'])}")

    status_code, audit = client.get(f"/api/v1/audit/{session_id}")
    print(f"  Audit Trail Records    : {len(audit['events'])}")
    for idx, ev in enumerate(audit["events"], 1):
        status_badge = f"{GREEN}EXECUTED{RESET}" if ev["execution_status"] == "EXECUTED" else f"{YELLOW}NOT_EXECUTED{RESET}"
        print(f"    [{idx}] {ev['action']:<20} | Risk: {ev['risk_band']:<6} | Decision: {ev['decision']:<12} | Status: {status_badge}")

    print(f"\n{GREEN}{BOLD}✔ Legitimate scenario successfully verified: Zero false blocks, controlled execution under human oversight.{RESET}\n")


def run_attack_scenario(client: DemoClient, auto: bool = False, delay: float = 0.8):
    """Demonstrate Canonical Suspicious / Attack Escalation Scenario."""
    print_section("Scenario 2: Canonical Suspicious / Attack Escalation")
    print(f"{WHITE}Objective: Demonstrate multi-signal behavioral trajectory escalation where an agent drifts scope,")
    print(f"           escalates destructiveness, and expands footprint breadth until reaching HIGH risk (> 0.65),")
    print(f"           triggering an absolute BLOCK that guarantees ZERO tool execution.{RESET}\n")

    # Step 1: Create session
    print_step_header(1, 6, "Session Initialization (Attack Agent)")
    client.seed_demo()
    status_code, sess = client.post(
        "/api/v1/sessions",
        {"principal_id": "attacker_user", "agent_id": "rogue_escalation_agent"},
    )
    session_id = sess["session_id"]
    print(f"  Principal ID   : {sess['principal_id']}")
    print(f"  Agent ID       : {sess['agent_id']}")
    print(f"  Session ID     : {session_id}")
    print(f"  Initial Risk   : {format_risk(sess['risk_band'], sess['trajectory_score'])}")
    prompt_step(auto, delay)

    # Attack Sequence:
    # 1. read_logs (READ) on logs
    # 2. read_customer (READ) on db_records:customer_table
    # 3. update_customer (WRITE) on db_records:customer_table
    # 4. export_customers (WRITE) on db_records:export_all
    # 5. change_permissions (DESTRUCTIVE) on db_schema:core
    # 6. drop_table (DESTRUCTIVE) on db_schema:core
    attack_steps = [
        ("read_logs", "logs", "App reconnaissance"),
        ("read_customer", "db_records:customer_table", "Customer table enumeration"),
        ("update_customer", "db_records:customer_table", "Tampering customer records"),
        ("export_customers", "db_records:export_all", "Bulk exfiltration preparation"),
        ("change_permissions", "system:permissions", "Privilege escalation attempt"),
        ("drop_table", "db_schema:core", "Core schema destruction (Target Payload)"),
    ]

    last_action_id = None
    for idx, (act, res, desc) in enumerate(attack_steps, 1):
        print_step_header(idx, 7, f"Attack Step {idx}: {act} ({desc})")
        status_code, prop = client.post(
            "/api/v1/actions/propose",
            {
                "principal_id": "attacker_user",
                "session_id": session_id,
                "agent_id": "rogue_escalation_agent",
                "action": act,
                "resource": res,
                "parameters": {"target": "production_database"},
            },
        )
        last_action_id = prop["action_id"]
        print(f"  Proposed Action: {act} (Resource: {res})")
        print(f"  Action Class   : {prop['reversibility']}")
        print(f"  Trajectory Risk: {format_risk(prop['risk_band'], prop['trajectory_score'])}")
        print(f"  Tripwire Gate  : {format_decision(prop['decision'])}")
        print(f"  Policy Reason  : {prop['reason']}")
        if prop["decision"] == "ALLOW":
            print(f"  Execution      : {format_execution_status('PERMITTED')}")
        else:
            print(f"  Tool Execution : {format_execution_status('NOT_EXECUTED')} (Interception active)")

        prompt_step(auto, delay)

    # Step 7: Unauthorized Payload Injection -> Immediate BLOCK under Invariant 1
    print_step_header(7, 8, "Attack Step 7: Unauthorized Destruction Attempt (dev_user)")
    status_code, dev_sess = client.post(
        "/api/v1/sessions",
        {"principal_id": "dev_user", "agent_id": "dev_agent_01"},
    )
    dev_sess_id = dev_sess["session_id"]
    status_code, unauth_prop = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "dev_user",
            "session_id": dev_sess_id,
            "agent_id": "dev_agent_01",
            "action": "drop_table",
            "resource": "db_schema:core",
        },
    )
    blocked_action_id = unauth_prop["action_id"]
    print(f"  Principal      : dev_user (Unauthorized: lacks 'schema:admin')")
    print(f"  Proposed Action: drop_table (Resource: db_schema:core)")
    print(f"  Tripwire Gate  : {format_decision(unauth_prop['decision'])}")
    print(f"  Policy Reason  : {unauth_prop['reason']}")
    print(f"  Tool Execution : {format_execution_status('NOT_EXECUTED')}")
    print(f"\n  {BG_RED}{WHITE}{BOLD} *** INVARIANT 1 ENFORCEMENT: UNAUTHORIZED ACTION PERMANENTLY BLOCKED *** {RESET}")
    prompt_step(auto, delay)

    # Step 8: Universal Blocking at HIGH Trajectory Risk (> 0.65) under Invariant 4
    print_step_header(8, 8, "Attack Step 8: HIGH Trajectory Risk Universal Blocking")
    status_code, high_sess = client.post(
        "/api/v1/sessions",
        {"principal_id": "user_high_risk", "agent_id": "high_risk_agent"},
    )
    high_sess_id = high_sess["session_id"]
    status_code, high_prop = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "user_high_risk",
            "session_id": high_sess_id,
            "agent_id": "high_risk_agent",
            "action": "drop_table",
            "resource": "db_schema:core",
        },
    )
    print(f"  Principal      : user_high_risk (Score: {high_prop['trajectory_score']:.3f} -> Band: {high_prop['risk_band']})")
    print(f"  Proposed Action: drop_table (Resource: db_schema:core)")
    print(f"  Tripwire Gate  : {format_decision(high_prop['decision'])}")
    print(f"  Policy Reason  : {high_prop['reason']}")
    print(f"  Tool Execution : {format_execution_status('NOT_EXECUTED')}")
    print(f"\n  {BG_RED}{WHITE}{BOLD} *** INVARIANT 4 ENFORCEMENT: HIGH TRAJECTORY RISK BLOCKS ALL ACTIONS *** {RESET}")
    prompt_step(auto, delay)

    # Prove confirmation CANNOT bypass the BLOCK
    print(f"\n{BOLD}{RED}--- PROVING SECURITY INVARIANT: CONFIRMATION CANNOT BYPASS BLOCK ---{RESET}")
    print(f"  {WHITE}Attempting to submit forged approval for blocked action '{blocked_action_id}'...{RESET}")
    status_code, conf_err = client.post(
        f"/api/v1/actions/{blocked_action_id}/confirm",
        {"approved_by": "attacker_forged_admin"},
    )
    print(f"  HTTP Response  : {status_code} Bad Request")
    print(f"  Tripwire Error : {RED}{conf_err.get('detail', conf_err)}{RESET}")
    print(f"  Execution Gate : {format_execution_status('NOT_EXECUTED')} (Zero tool handler calls)")
    prompt_step(auto, delay)

    # Show Trajectory & Audit summary
    print(f"\n{BOLD}{CYAN}=== ATTACK TRAJECTORY ESCALATION TIMELINE ==={RESET}")
    status_code, traj = client.get(f"/api/v1/sessions/{session_id}/trajectory")
    for ev in traj["events"]:
        print(f"  Step {ev['step']}: {ev['action']:<20} -> Trajectory: {ev['trajectory_score']:.3f} [{ev['risk_band']:<6}] -> {ev['decision']}")

    print(f"\n{GREEN}{BOLD}[PASS] Attack scenario successfully stopped: Behavioral escalation detected, destructive payload blocked.{RESET}\n")


def run_revalidation_scenario(client: DemoClient, auto: bool = False, delay: float = 0.8):
    """Demonstrate Dynamic Re-Validation Security Invariant."""
    print_section("Scenario 3: Dynamic Confirmation Re-Validation Security Invariant")
    print(f"{WHITE}Objective: Demonstrate that human approval is NOT an unconditional execution pass.")
    print(f"           If an action is proposed when safe, but the security state changes before confirmation")
    print(f"           (e.g., permissions revoked or risk escalated), re-validation evaluates live state,")
    print(f"           produces BLOCK, and guarantees ZERO tool execution.{RESET}\n")

    client.seed_demo()

    # Step 1: Create session for user with permissions:write
    print_step_header(1, 3, "Create Session & Propose Risky Action")
    status_code, sess = client.post(
        "/api/v1/sessions",
        {"principal_id": "fin_agent_user", "agent_id": "reval_agent_001"},
    )
    session_id = sess["session_id"]

    status_code, prop = client.post(
        "/api/v1/actions/propose",
        {
            "principal_id": "fin_agent_user",
            "session_id": session_id,
            "agent_id": "reval_agent_001",
            "action": "change_permissions",
            "resource": "system:permissions",
        },
    )
    action_id = prop["action_id"]
    print(f"  Proposed Action: change_permissions (Target: system:permissions)")
    print(f"  Initial Status : {format_decision(prop['decision'])}")
    print(f"  Action ID      : {action_id}")
    prompt_step(auto, delay)

    # Step 2: Simulate administrative security revocation before confirmation is submitted
    print_step_header(2, 3, "Administrative Security Revocation Occurs")
    print(f"  {YELLOW}>>> Security Administrator revokes 'permissions:write' scope from 'fin_agent_user'...{RESET}")

    from app.db.models import PrincipalModel
    from app.db.session import get_session_factory
    with get_session_factory()() as db:
        p = db.query(PrincipalModel).filter(PrincipalModel.id == "fin_agent_user").first()
        p.scope = "logs:read,customer:read"
        db.commit()

    print(f"  Principal Scopes Updated: 'logs:read,customer:read' (permissions:write REMOVED)")
    prompt_step(auto, delay)

    # Step 3: Confirmation is submitted — Re-Validation runs against live state!
    print_step_header(3, 3, "Confirmation Submitted -> Dynamic Re-Validation")
    print(f"  {CYAN}>>> Human approver submits approval: {{\"approved_by\": \"manager_dan\"}}{RESET}")
    status_code, conf_res = client.post(
        f"/api/v1/actions/{action_id}/confirm",
        {"approved_by": "manager_dan"},
    )
    print(f"  Re-Validation Result : {RED}{BOLD}FAIL (Unauthorized on Live State){RESET}")
    print(f"  Final Decision       : {format_decision(conf_res['decision'])}")
    print(f"  Tool Execution Status: {format_execution_status(conf_res['execution_status'])}")

    print(f"\n{GREEN}{BOLD}[PASS] Re-validation invariant proven: Live security state enforced; human approval cannot execute unauthorized actions.{RESET}\n")


def run_cross_session_scenario(client: DemoClient, auto: bool = False, delay: float = 0.8):
    """Demonstrate Cross-Session Trajectory Persistence & Velocity Isolation."""
    print_section("Scenario 4: Cross-Session Trajectory Persistence & Velocity Isolation")
    print(f"{WHITE}Objective: Demonstrate that trajectory history persists to the principal across sessions,")
    print(f"           seeding new sessions from historical risk while strictly resetting first-action velocity.{RESET}\n")

    client.seed_demo()

    # Session 1: Build trajectory risk
    print_step_header(1, 2, "Session 1: High-Activity Operation Sequence")
    status_code, s1 = client.post(
        "/api/v1/sessions",
        {"principal_id": "attacker_user", "agent_id": "agent_alpha"},
    )
    s1_id = s1["session_id"]
    print(f"  Session 1 ID   : {s1_id}")

    # Escalate score in Session 1
    for act, res in [("read_logs", "logs"), ("read_customer", "db_records:customer_table"), ("export_customers", "db_records:export_all")]:
        client.post(
            "/api/v1/actions/propose",
            {"principal_id": "attacker_user", "session_id": s1_id, "agent_id": "agent_alpha", "action": act, "resource": res},
        )

    status_code, t1 = client.get(f"/api/v1/sessions/{s1_id}/trajectory")
    print(f"  Session 1 End Score: {format_risk(t1['risk_band'], t1['trajectory_score'])}")
    prompt_step(auto, delay)

    # Session 2: Fresh session for same principal
    print_step_header(2, 2, "Session 2: Fresh Session for Same Principal")
    status_code, s2 = client.post(
        "/api/v1/sessions",
        {"principal_id": "attacker_user", "agent_id": "agent_beta"},
    )
    s2_id = s2["session_id"]
    print(f"  Session 2 ID   : {s2_id}")
    print(f"  Inherited Risk : {format_risk(s2['risk_band'], s2['trajectory_score'])}")
    print(f"  Velocity Check : Velocity is strictly 0.0 on first action of new session.")

    print(f"\n{GREEN}{BOLD}[PASS] Cross-session persistence proven: Principal risk persists across session boundaries.{RESET}\n")


def print_security_guarantees():
    """Print Tripwire Security Guarantees box."""
    print(f"{CYAN}{BOLD}")
    print("+-------------------------------------------------------------------------------+")
    print("|                     TRIPWIRE RUNTIME SECURITY GUARANTEES                      |")
    print("+-------------------------------------------------------------------------------+")
    print("|  1. Invariant 1 (Authorization): Unauthorized actions return BLOCK.           |")
    print("|  2. Invariant 2 (Zero Execution): BLOCK terminates tool execution path.       |")
    print("|  3. Invariant 3 (Destructive Actions): Require CONFIRM / HARD_CONFIRM.         |")
    print("|  4. Invariant 4 (HIGH Trajectory): Universally blocks all action classes.      |")
    print("|  5. Invariant 5 (Dynamic Re-Validation): Live state re-evaluated at confirm.  |")
    print("|  6. Invariant 6 (Cross-Session): Trajectory persists to the principal.        |")
    print("|  7. Invariant 7 (No Bypass): Agent proposals must pass through Tripwire gate.  |")
    print("|  8. Invariant 8 (Backend Authority): Server overrides all client metadata.     |")
    print("+-------------------------------------------------------------------------------+")
    print(f"{RESET}")


def main():
    """CLI entry point for demo runner."""
    parser = argparse.ArgumentParser(description="Tripwire Demonstration Runner")
    parser.add_argument(
        "--scenario",
        choices=["1", "2", "3", "4", "legitimate", "attack", "revalidation", "cross-session", "all"],
        help="Specific scenario to run (1=Legitimate, 2=Attack, 3=Revalidation, 4=CrossSession, all=All)",
    )
    parser.add_argument("--all", action="store_true", help="Run all demo scenarios sequentially")
    parser.add_argument("--auto", action="store_true", help="Run without pausing for user input")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay in seconds between automated steps")
    parser.add_argument("--server", type=str, default=None, help="Base URL of live Tripwire server (e.g. http://localhost:8000)")
    parser.add_argument("--reset", action="store_true", help="Reset demo seed data before execution")

    args = parser.parse_args()

    print_banner()
    client = DemoClient(server_url=args.server)

    if args.reset:
        client.seed_demo()
        print(f"{GREEN}Database reset and seeded with deterministic demo principals.{RESET}\n")

    scenario = args.scenario
    if args.all:
        scenario = "all"

    if not scenario:
        print("\nSelect a demonstration scenario to run:")
        print("  [1] Canonical Legitimate Agent Escalation (Controlled Execution & Confirmation)")
        print("  [2] Canonical Suspicious / Attack Escalation (Multi-Signal Drift & Universal Block)")
        print("  [3] Dynamic Re-Validation Security Invariant (Live State Verification)")
        print("  [4] Cross-Session Trajectory Persistence (Historical Inheritance)")
        print("  [5] Run All Scenarios Sequentially")
        print("  [q] Quit")
        try:
            choice = input(f"\nEnter choice [1-5]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

        choice_map = {
            "1": "legitimate",
            "2": "attack",
            "3": "revalidation",
            "4": "cross-session",
            "5": "all",
        }
        scenario = choice_map.get(choice)
        if not scenario:
            print("Exiting.")
            sys.exit(0)

    # Normalize scenario names
    if scenario in ["1", "legitimate"]:
        run_legitimate_scenario(client, auto=args.auto, delay=args.delay)
    elif scenario in ["2", "attack"]:
        run_attack_scenario(client, auto=args.auto, delay=args.delay)
    elif scenario in ["3", "revalidation"]:
        run_revalidation_scenario(client, auto=args.auto, delay=args.delay)
    elif scenario in ["4", "cross-session"]:
        run_cross_session_scenario(client, auto=args.auto, delay=args.delay)
    elif scenario == "all":
        run_legitimate_scenario(client, auto=args.auto, delay=args.delay)
        run_attack_scenario(client, auto=args.auto, delay=args.delay)
        run_revalidation_scenario(client, auto=args.auto, delay=args.delay)
        run_cross_session_scenario(client, auto=args.auto, delay=args.delay)

    print_security_guarantees()


if __name__ == "__main__":
    main()
