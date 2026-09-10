# TRIPWIRE — Final MVP Implementation Plan

## PS1: Runtime Security Harness for AI Agents

> Build a runtime security harness, a model-agnostic middleware layer that wraps AI agents and enforces authorization boundaries, action reversibility gates, and cross-session behavioral trajectory monitoring.

---

## 1. Executive Summary

### Problem

AI agents can perform multi-step actions where every individual action appears legitimate, while the overall behavioral trajectory gradually escalates into a dangerous attack. The model itself cannot reliably enforce cross-session memory, real-world reversibility, or complete authorization boundaries.

### Solution

**Tripwire** is a model-agnostic runtime security harness that sits between an AI agent and its tools.

It enforces:

1. Authorization context propagation
2. Action reversibility gates
3. Cross-session behavioral trajectory monitoring

Tripwire evaluates every proposed action and returns:

- `ALLOW`
- `CONFIRM`
- `HARD_CONFIRM`
- `BLOCK`

The protected tool executes only when Tripwire permits it.

### Core principle

```text
AI Agent proposes
       ↓
Tripwire evaluates
       ↓
Tripwire decides
       ↓
Tool executes only if permitted
```

---

# 2. What We Are Building

We are **not** building another AI agent.

We are building a middleware/security layer that wraps an AI agent:

```text
USER
  ↓
REQUEST / IDENTITY CONTEXT
  ↓
AI AGENT
  ↓
ACTION PROPOSAL
  ↓
TRIPWIRE SECURITY HARNESS
  ├── Authorization
  ├── Reversibility
  ├── Trajectory Monitoring
  ├── Decision Gate
  └── Audit
  ↓
ALLOW / CONFIRM / BLOCK
  ↓
TOOL ADAPTER
  ↓
PROTECTED TOOL / MOCK DB
```

The agent must not have a direct path to protected tools.

---

# 3. MVP Requirements

## P0 — Mandatory

### Authorization

- Principal identity
- Role/scope context
- Action/resource authorization
- Unauthorized action blocking

### Reversibility

Classify actions as:

```text
READ
WRITE
DESTRUCTIVE
```

Destructive actions require explicit human confirmation when otherwise permitted.

### Trajectory

Track:

- Scope drift
- Destructiveness growth
- Velocity
- Footprint breadth
- Current-session history
- Cross-session history

### Decision Gate

Support:

```text
ALLOW
CONFIRM
HARD_CONFIRM
BLOCK
```

### Runtime Connector

The agent sends action proposals through Tripwire before tool execution.

### Audit

Record every relevant action attempt, decision, reason, risk score, principal, session, and timestamp.

### Demonstrations

1. Suspicious escalation attack is stopped.
2. Legitimate escalating work is handled correctly.
3. Cross-session trajectory state affects later decisions.

---

# 4. Non-Goals

Do not spend MVP time on:

- Full enterprise IAM
- Full organization-management platform
- Support for every agent framework
- Complex ML anomaly detection
- Chain-of-thought inspection
- Hundreds of tools
- Kubernetes/microservices
- Redis unless genuinely required
- Production-grade identity-provider integration
- Complex policy-authoring UI

The architecture should be extensible, but the hackathon MVP must remain focused on runtime security.

---

# 5. Technology Stack

## Backend

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic

## Frontend

- React
- Simple dashboard
- REST API integration

## Agent

- Python demo agent
- Scripted attack scenario
- Scripted legitimate scenario

## Tools

Deterministic mock tools:

```text
read_logs
search_customers
read_customer
export_customers
update_customer
change_permissions
drop_table
```

---

# 6. Frozen Domain Model

## 6.1 Principal

```text
principal_id
role
scope
persistent_trajectory_state
```

Example:

```json
{
  "principal_id": "user_001",
  "role": "database_operator",
  "scope": [
    "logs:read",
    "customer:read",
    "customer:write"
  ]
}
```

## 6.2 Session

```text
session_id
principal_id
agent_id
started_at
ended_at
trajectory_score
```

## 6.3 Action Proposal

```json
{
  "principal_id": "user_001",
  "session_id": "session_001",
  "agent_id": "agent_001",
  "action": "read_customer",
  "resource": "db_records:customer_table",
  "parameters": {}
}
```

## 6.4 Action Classification

| Action | Classification |
|---|---|
| read_logs | READ |
| search_customers | READ |
| read_customer | READ |
| export_customers | WRITE |
| update_customer | WRITE |
| change_permissions | DESTRUCTIVE |
| drop_table | DESTRUCTIVE |

---

# 7. Decision Model

## Authorization

```text
Unauthorized
    ↓
BLOCK
```

The protected tool must not execute.

## Authorized non-destructive action

```text
LOW      → ALLOW
MEDIUM   → ALLOW or CONFIRM according to policy
HIGH     → BLOCK
```

## Authorized destructive action

```text
LOW/MEDIUM
    ↓
CONFIRM / HARD_CONFIRM
    ↓
Human approval
    ↓
Tool execution
```

## High-risk destructive action

```text
HIGH + DESTRUCTIVE
        ↓
BLOCK
```

---

# 8. Final Decision Matrix

| Authorization | Trajectory | Reversibility | Decision |
|---|---|---|---|
| DENIED | Any | Any | BLOCK |
| ALLOWED | LOW | READ | ALLOW |
| ALLOWED | LOW | WRITE | ALLOW |
| ALLOWED | LOW | DESTRUCTIVE | CONFIRM |
| ALLOWED | MEDIUM | READ | ALLOW |
| ALLOWED | MEDIUM | WRITE | CONFIRM |
| ALLOWED | MEDIUM | DESTRUCTIVE | HARD_CONFIRM |
| ALLOWED | HIGH | READ | BLOCK |
| ALLOWED | HIGH | WRITE | BLOCK |
| ALLOWED | HIGH | DESTRUCTIVE | BLOCK |

---

# 9. Trajectory Engine

The trajectory engine evaluates behavior over time rather than judging each action independently.

## Signals

### Scope Drift

```text
scope_drift ∈ {0,1}
```

### Destructiveness Growth

Tracks progression:

```text
READ → WRITE → DESTRUCTIVE
```

### Velocity

```text
velocity ∈ [0,1]
```

### Footprint Breadth

```text
footprint_breadth ∈ [0,1]
```

---

# 10. Step Score

```text
step_score =
    0.30 * scope_drift
  + 0.35 * destructiveness_growth
  + 0.15 * velocity
  + 0.20 * footprint_breadth
```

Keep this deterministic and explainable.

---

# 11. Asymmetric EMA

If risk increases:

```text
new_score =
    previous_score
    + 0.6 * (step_score - previous_score)
```

If risk decreases:

```text
new_score =
    previous_score
    + 0.2 * (step_score - previous_score)
```

Desired behavior:

```text
Risk rises quickly.
Risk decays slowly.
```

---

# 12. Risk Bands

```text
LOW
< 0.35

MEDIUM
0.35 - 0.65

HIGH
> 0.65
```

Thresholds must be centralized in configuration.

---

# 13. Cross-Session Monitoring

Trajectory state must survive the end of a session.

Example:

```text
SESSION 1
READ logs
READ customers
WRITE orders
        ↓
Persist trajectory state
        ↓
SESSION 2
ACCESS sensitive resource
CHANGE permissions
DELETE
```

Session 2 must not automatically start from a completely clean security state.

Persist at least:

```text
principal_id
trajectory_score
scope_footprint
max_destructiveness_level
action_counts
last_session_at
```

---

# 14. Database Design

Use SQLAlchemy.

## principals

```text
id
role
scope
trajectory_score
scope_footprint
max_destructiveness
action_counts
last_session_at
```

## sessions

```text
id
principal_id
agent_id
started_at
ended_at
trajectory_score
```

## audit_events

```text
id
principal_id
session_id
agent_id
action
resource
reversibility
trajectory_score
risk_band
decision
reason
timestamp
```

Use repositories/services instead of putting database logic directly into route handlers.

---

# 15. API Contract

Freeze this contract before parallel implementation.

## POST /sessions

Creates an agent session.

Response:

```json
{
  "session_id": "session_001"
}
```

## POST /actions/propose

Main security boundary.

Request:

```json
{
  "principal_id": "user_001",
  "session_id": "session_001",
  "agent_id": "agent_001",
  "action": "read_customer",
  "resource": "db_records:customer_table",
  "parameters": {}
}
```

Response:

```json
{
  "action_id": "action_001",
  "decision": "ALLOW",
  "trajectory_score": 0.372,
  "risk_band": "MEDIUM",
  "reversibility": "READ",
  "reason": "Authorized read within current trajectory"
}
```

## POST /actions/confirm

Request:

```json
{
  "action_id": "action_001",
  "approved_by": "admin_001"
}
```

The action may execute only after valid approval and re-validation.

## GET /sessions/{session_id}/trajectory

Returns trajectory history.

## GET /audit/{session_id}

Returns the audit trail.

---

# 16. Repository Structure

```text
tripwire/
│
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   ├── classifier.py
│   ├── trajectory.py
│   ├── gate.py
│   ├── audit.py
│   │
│   ├── services/
│   │   ├── action_service.py
│   │   └── session_service.py
│   │
│   └── tests/
│       ├── test_auth.py
│       ├── test_classifier.py
│       ├── test_trajectory.py
│       ├── test_gate.py
│       ├── test_sessions.py
│       └── test_audit.py
│
├── agent/
│   ├── demo_agent.py
│   ├── tool_registry.py
│   └── scenarios/
│       ├── attack.json
│       └── legitimate.json
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── api/
│   │   └── styles/
│   └── package.json
│
├── scripts/
│   └── run_demo.py
│
├── docs/
│   ├── API_CONTRACT.md
│   ├── ARCHITECTURE.md
│   └── DEMO_SCRIPT.md
│
├── README.md
└── .gitignore
```

---

# 17. TWO-PERSON DEVELOPMENT RULE

The project is split into two independent workstreams.

## PERSON A

**Security Core / Backend**

Owns:

```text
backend/
docs/API_CONTRACT.md
```

Primary responsibility:

```text
Authorization
Reversibility
Trajectory
Decision Gate
Persistence
Audit
Runtime API
Backend Tests
```

## PERSON B

**Agent / Tools / Frontend / Demo**

Owns:

```text
agent/
frontend/
scripts/
```

Primary responsibility:

```text
Mock Tools
Tool Registry
Demo Agent
Attack Scenario
Legitimate Scenario
Dashboard
Trajectory Visualization
Confirmation UI
Scenario Replay
Frontend Integration
```

### Important

Person A should not modify Person B's directories.

Person B should not modify Person A's backend files.

Shared changes must be discussed before implementation.

---

# 18. GIT BRANCHES

Both start from the latest development branch.

```bash
git checkout develop
git pull origin develop
```

## Person A

```bash
git checkout -b develop/tripwire-backend
```

## Person B

```bash
git checkout -b develop/tripwire-frontend-demo
```

---

# 19. PHASE 0 — ARCHITECTURE FREEZE

## Both developers

Before coding, finalize:

- API contract
- JSON schemas
- Decision matrix
- Action classifications
- Trajectory formula
- Database fields
- Tool registry
- Attack scenario
- Legitimate scenario
- Folder ownership

Deliverable:

```text
docs/API_CONTRACT.md
```

No implementation should depend on undocumented assumptions.

---

# 20. PHASE 1 — FOUNDATION

## PERSON A

### Tasks

1. Create FastAPI application.
2. Create configuration.
3. Configure SQLAlchemy.
4. Configure SQLite.
5. Create database session handling.
6. Create Pydantic schemas.
7. Create initial models.
8. Add health endpoint.
9. Add backend test setup.

### Acceptance criteria

```text
Server starts
Database initializes
Health endpoint works
Tests execute
```

## PERSON B

### Tasks

1. Create React application.
2. Create dashboard shell.
3. Create mock tool registry.
4. Create attack scenario JSON.
5. Create legitimate scenario JSON.
6. Create demo-agent skeleton.

### Acceptance criteria

```text
Frontend starts
Scenario files load
Mock tools can be invoked through the local agent abstraction
Agent does not directly bypass Tripwire
```

Both work independently.

---

# 21. PHASE 2 — SECURITY CORE + AGENT EXPERIENCE

## PERSON A

Implement:

```text
Authorization Engine
Action Classifier
Reversibility Classification
Trajectory Engine
```

Functions should include:

```text
check_authorization()
classify_action()
calculate_scope_drift()
calculate_destructiveness_growth()
calculate_velocity()
calculate_footprint_breadth()
calculate_step_score()
calculate_trajectory_score()
calculate_risk_band()
```

### Tests

- Authorized action
- Unauthorized action
- READ classification
- WRITE classification
- DESTRUCTIVE classification
- Scope drift
- Destructiveness growth
- Velocity
- Footprint breadth
- Step score
- EMA
- Risk thresholds

## PERSON B

Implement:

```text
Attack Scenario
Legitimate Scenario
Agent HTTP/API client
Scenario runner
Static dashboard
Action timeline
```

The agent must use the frozen API contract.

---

# 22. PHASE 3 — DECISION + EXPERIENCE

## PERSON A

Implement:

```text
Decision Gate
Cross-session Persistence
Audit
Session APIs
Action Proposal API
Confirmation API
Trajectory API
Audit API
```

Critical execution flow:

```text
Agent
  ↓
/actions/propose
  ↓
Authorization
  ↓
Classification
  ↓
Trajectory
  ↓
Decision
  ├── BLOCK → no tool execution
  ├── CONFIRM → pending approval
  └── ALLOW → tool adapter
```

## PERSON B

Implement:

```text
Trajectory chart
Risk indicator
Decision card
Confirmation modal
Approval queue
Audit table
Attack replay
Legitimate replay
Cross-session display
```

---

# 23. INTEGRATION POINT 1

Connect:

```text
Demo Agent
      ↓
POST /actions/propose
      ↓
Tripwire
      ↓
Decision
```

Test from the terminal before integrating the full UI.

Verify:

```text
ALLOW
CONFIRM
BLOCK
```

---

# 24. PHASE 4 — TOOL ENFORCEMENT

## Both

Connect the real mock tools.

Required behavior:

```text
ALLOW
  ↓
Tool executes

CONFIRM
  ↓
Tool waits

Human APPROVE
  ↓
Re-validate
  ↓
Tool executes

BLOCK
  ↓
Tool NEVER executes
```

This is a critical security test.

---

# 25. PHASE 5 — ATTACK DEMO

Run:

```text
READ logs
    ↓
READ customers
    ↓
WRITE orders
    ↓
EXPORT data
    ↓
CHANGE permissions
    ↓
DROP table
```

Expected conceptual behavior:

```text
LOW
 ↓
MEDIUM
 ↓
MEDIUM
 ↓
MEDIUM/HIGH
 ↓
HIGH
 ↓
BLOCK
```

The dangerous tool must not execute.

Dashboard should show the complete trajectory and the exact reason for blocking.

---

# 26. PHASE 6 — LEGITIMATE DEMO

Run:

```text
READ invoices
    ↓
ANALYZE
    ↓
CREATE report
    ↓
WRITE report
    ↓
SEND report
```

Expected:

```text
LOW
 ↓
LOW
 ↓
LOW/MEDIUM
```

If a destructive action is legitimately required:

```text
CONFIRM
   ↓
Human approval
   ↓
Execution
```

The demo must prove that Tripwire is not simply a system that blocks everything.

---

# 27. PHASE 7 — CROSS-SESSION DEMO

## Session 1

```text
READ
READ
WRITE
```

Persist the state.

## Session 2

```text
ACCESS sensitive resource
CHANGE permissions
DELETE
```

Tripwire must load the previous trajectory state.

Show:

```text
Session 1
   ↓
Persistent trajectory
   ↓
Session 2
   ↓
Elevated current risk
```

This is a key PS requirement.

---

# 28. PHASE 8 — END-TO-END TESTING

## Authorization

```text
authorized action -> permitted
unauthorized action -> blocked
```

## Reversibility

```text
destructive action -> confirmation required
```

## Trajectory

```text
attack sequence -> HIGH
legitimate sequence -> LOW/MEDIUM
```

## Cross-session

```text
session 1 state -> available in session 2
```

## Enforcement

```text
BLOCK -> protected tool is never called
```

## Audit

Every action attempt produces the expected audit information.

---

# 29. PHASE 9 — DASHBOARD INTEGRATION

Connect frontend to:

```text
POST /actions/propose
POST /actions/confirm
GET /sessions/{id}/trajectory
GET /audit/{id}
```

Dashboard should contain:

### Current Run

```text
Principal
Session
Current Action
Trajectory Score
Risk Band
Decision
```

### Trajectory

Display score progression.

### Timeline

```text
✓ READ logs
✓ READ customers
✓ WRITE orders
⚠ EXPORT
⚠ CHANGE PERMISSIONS
🚫 DROP TABLE
```

### Approval

```text
Action requires confirmation

[ APPROVE ]
[ DENY ]
```

### Audit

Show decision and reason for every relevant action.

---

# 30. PHASE 10 — SECURITY INTEGRITY CHECK

Verify that the agent cannot bypass Tripwire through the intended application architecture.

Expected:

```text
Agent
  ↓
Tripwire
  ↓
Tool
```

Not:

```text
Agent
  ↓
Tool
```

A blocked action must result in:

```text
Decision = BLOCK
Tool invocation = 0
```

---

# 31. PHASE 11 — DEMO POLISH

Only after the security engine and end-to-end flow are stable.

Add:

- Live trajectory score
- Risk badges
- Action timeline
- Attack replay
- Legitimate replay
- Confirmation modal
- Audit explanations
- Clear block reason
- Architecture visualization

Do not prioritize visual polish over security correctness.

---

# 32. PHASE 12 — FINAL JUDGE DEMO

## Part 1 — Explain the problem

> AI agents can perform individually valid actions that become dangerous when viewed as a behavioral trajectory across sessions.

## Part 2 — Show legitimate work

```text
Prepare monthly finance report.
```

Show:

```text
READ
ANALYZE
CREATE
SEND
```

Tripwire allows legitimate work and introduces confirmation only when required.

## Part 3 — Show attack

```text
Clean up the database.
```

Then:

```text
READ
SEARCH
EXPORT
CHANGE PERMISSIONS
DELETE
```

Risk increases.

Finally:

```text
HIGH
BLOCKED
```

Show that the protected tool was never executed.

## Part 4 — Show cross-session memory

Demonstrate that the next session inherits relevant trajectory state.

## Part 5 — Explain the differentiator

> Traditional authorization can evaluate whether one action is permitted. Tripwire evaluates the authorization, reversibility, and behavioral trajectory surrounding that action.

---

# 33. Final Product Pitch

> **Tripwire is a model-agnostic runtime security harness that sits between AI agents and their tools. It verifies authorization for every action, enforces human confirmation for destructive operations, and tracks behavioral trajectories across sessions to detect scope and privilege escalation. Instead of blindly blocking agents, Tripwire dynamically allows legitimate work and blocks dangerous behavior before the tool executes.**

### One-line punchline

> **“The agent decides what it wants to do; Tripwire decides whether it is safe to let it happen.”**

---

# 34. Recommended Commit Structure

## Person A

```text
Add TRIPWIRE: backend foundation
Add TRIPWIRE: authorization engine
Add TRIPWIRE: action classifier
Add TRIPWIRE: trajectory engine
Add TRIPWIRE: decision gate
Add TRIPWIRE: persistence
Add TRIPWIRE: audit
Add TRIPWIRE: runtime API
Add TRIPWIRE: backend tests
```

## Person B

```text
Add TRIPWIRE: mock tool registry
Add TRIPWIRE: attack scenario
Add TRIPWIRE: legitimate scenario
Add TRIPWIRE: demo agent
Add TRIPWIRE: dashboard
Add TRIPWIRE: trajectory visualization
Add TRIPWIRE: confirmation UI
Add TRIPWIRE: scenario replay
```

---

# 35. Merge Strategy

Do not wait until the end.

## Merge Point 1

```text
API contract
+
Backend foundation
+
Agent skeleton
```

Verify:

```text
agent -> API
```

## Merge Point 2

```text
Authorization
+
Reversibility
+
Trajectory
+
Decision Gate
```

Run:

```text
attack
legitimate
```

from the terminal.

## Merge Point 3

```text
Backend
+
Agent
+
Tools
+
Frontend
+
Audit
+
Tests
```

Perform the complete demo.

---

# 36. Definition of Done

The MVP is complete only when all of these are true:

- [ ] Agent is wrapped by Tripwire.
- [ ] Agent cannot directly execute protected tools.
- [ ] Authorization is checked per action.
- [ ] Unauthorized actions are blocked.
- [ ] Actions are classified by reversibility.
- [ ] Destructive actions require confirmation.
- [ ] Trajectory is calculated from observable actions.
- [ ] Risk increases during suspicious escalation.
- [ ] Risk decays more slowly than it increases.
- [ ] Trajectory state persists across sessions.
- [ ] High-risk actions are blocked.
- [ ] Legitimate escalation is not automatically blocked.
- [ ] Human confirmation works.
- [ ] Every important decision is audited.
- [ ] Attack scenario reliably stops.
- [ ] Legitimate scenario reliably completes.
- [ ] Dashboard displays trajectory and decisions.
- [ ] Backend tests pass.
- [ ] Integration tests pass.
- [ ] End-to-end demo passes.
- [ ] README explains architecture and setup.
- [ ] Demo can be reproduced from a clean environment.

---

# 37. Implementation Rule for Both Developers

At every phase:

1. Read the relevant requirements.
2. Implement only the current phase.
3. Run tests.
4. Review the implementation.
5. Commit the working phase.
6. Do not silently change the API contract.
7. Do not expand MVP scope without agreement.
8. Keep security decisions in the backend, not the frontend.
9. Keep the agent independent from Tripwire internals.
10. Never allow a protected tool to execute without passing the Tripwire decision gate.

---

# 38. Build Order Summary

```text
PHASE 0
Architecture + API Freeze
        ↓
PHASE 1
Foundation
        ↓
PHASE 2
Security Core + Agent
        ↓
PHASE 3
Decision + Persistence + UI
        ↓
PHASE 4
Tool Enforcement
        ↓
PHASE 5
Attack Demo
        ↓
PHASE 6
Legitimate Demo
        ↓
PHASE 7
Cross-Session Demo
        ↓
PHASE 8
Testing
        ↓
PHASE 9
Dashboard Integration
        ↓
PHASE 10
Security Integrity
        ↓
PHASE 11
Demo Polish
        ↓
PHASE 12
Final Judge Demo
```

---

# 39. Ownership Summary

| Phase | Person A — Backend/Security | Person B — Agent/UI/Demo |
|---|---|---|
| 0 | API/domain contract | API/domain contract |
| 1 | Backend foundation | Frontend + tools + scenarios |
| 2 | Auth + classifier + trajectory | Agent + scenario runner + dashboard |
| 3 | Gate + persistence + API + audit | Timeline + confirmation + replay |
| 4 | Enforcement API | Tool integration |
| 5 | Attack scoring/decision | Attack demo/UI |
| 6 | Legitimate decision flow | Legitimate demo/UI |
| 7 | Cross-session persistence | Cross-session visualization |
| 8 | Backend/integration tests | Frontend/E2E tests |
| 9 | API stability | Dashboard integration |
| 10 | Security integrity | Bypass testing/demo |
| 11 | Backend polish | UI/demo polish |
| 12 | Technical demo support | Presentation/demo flow |

---

## Final principle

**Person A builds the security brain.**

**Person B builds the agent, tools, and experience around it.**

**Both integrate only at the defined merge points.**

This allows the two developers to work in parallel without continuously waiting for each other.
