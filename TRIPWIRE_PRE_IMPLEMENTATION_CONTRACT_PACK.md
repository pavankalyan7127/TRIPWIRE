# TRIPWIRE — PRE-IMPLEMENTATION CONTRACT PACK

## PS1: Runtime Security Harness for AI Agents

**Purpose:** Freeze the shared contracts and assumptions before Person A and Person B begin implementation.

This document is the **single source of truth** for the MVP contract. Both developers must agree on this pack before writing implementation code.

---

# 1. Shared Goal

Tripwire is a model-agnostic runtime security harness that sits between an AI agent and its tools.

```text
USER
  ↓
AI AGENT
  ↓
ACTION PROPOSAL
  ↓
TRIPWIRE
  ├── Authorization
  ├── Reversibility
  ├── Trajectory
  ├── Decision
  └── Audit
  ↓
ALLOW / CONFIRM / BLOCK
  ↓
TOOL
```

### Core rule

> The agent proposes. Tripwire decides. The protected tool executes only when Tripwire permits it.

The MVP must demonstrate:

1. Unauthorized action is blocked.
2. Destructive action requires human confirmation.
3. Suspicious behavioral escalation is blocked.
4. Legitimate escalation is handled without blindly blocking it.
5. Relevant trajectory state persists across sessions.

---

# 2. Technology Contract

## Backend

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic

## Frontend

- React
- REST API

## Demo Agent

- Python
- Scripted scenarios
- HTTP client to Tripwire

## Persistence

- SQLite for MVP
- SQLAlchemy abstraction should avoid unnecessary database-specific assumptions.

---

# 3. API CONTRACT

Base URL:

```text
http://localhost:8000
```

API version:

```text
/api/v1
```

All JSON requests/responses use:

```http
Content-Type: application/json
```

---

## 3.1 POST /api/v1/sessions

Creates a new agent session.

### Request

```json
{
  "principal_id": "user_001",
  "agent_id": "agent_001"
}
```

### Response — 201

```json
{
  "session_id": "session_001",
  "principal_id": "user_001",
  "agent_id": "agent_001",
  "trajectory_score": 0.0,
  "risk_band": "LOW"
}
```

---

## 3.2 POST /api/v1/actions/propose

This is the **primary security boundary**.

The agent proposes an action. Tripwire evaluates it before any protected tool executes.

### Request

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

### Response — ALLOW

```json
{
  "action_id": "action_001",
  "decision": "ALLOW",
  "trajectory_score": 0.22,
  "risk_band": "LOW",
  "reversibility": "READ",
  "reason": "Authorized read within permitted scope"
}
```

### Response — CONFIRM

```json
{
  "action_id": "action_002",
  "decision": "CONFIRM",
  "trajectory_score": 0.42,
  "risk_band": "MEDIUM",
  "reversibility": "DESTRUCTIVE",
  "reason": "Destructive action requires human confirmation"
}
```

### Response — BLOCK

```json
{
  "action_id": "action_003",
  "decision": "BLOCK",
  "trajectory_score": 0.71,
  "risk_band": "HIGH",
  "reversibility": "DESTRUCTIVE",
  "reason": "Behavioral trajectory exceeds the high-risk threshold"
}
```

### Security requirement

If the decision is `BLOCK`:

```text
Protected tool execution = 0
```

---

# 4. Confirmation API

## POST /api/v1/actions/{action_id}/confirm

Used for actions requiring human confirmation.

### Request

```json
{
  "approved_by": "admin_001"
}
```

### Response — approved

```json
{
  "action_id": "action_002",
  "decision": "ALLOW",
  "approved_by": "admin_001",
  "execution_status": "EXECUTED"
}
```

### Response — denied

```json
{
  "action_id": "action_002",
  "decision": "BLOCK",
  "approved_by": "admin_001",
  "execution_status": "NOT_EXECUTED"
}
```

### Important

Confirmation must **re-validate** the action before execution.

Do not assume that an old confirmation remains valid if the security state has changed.

---

# 5. Trajectory API

## GET /api/v1/sessions/{session_id}/trajectory

Returns the observable action trajectory.

### Response

```json
{
  "session_id": "session_001",
  "principal_id": "user_001",
  "trajectory_score": 0.57,
  "risk_band": "MEDIUM",
  "events": [
    {
      "step": 1,
      "action": "read_logs",
      "resource": "logs",
      "reversibility": "READ",
      "trajectory_score": 0.20,
      "risk_band": "LOW",
      "decision": "ALLOW"
    },
    {
      "step": 2,
      "action": "read_customer",
      "resource": "db_records:customer_table",
      "reversibility": "READ",
      "trajectory_score": 0.37,
      "risk_band": "MEDIUM",
      "decision": "ALLOW"
    }
  ]
}
```

---

# 6. Audit API

## GET /api/v1/audit/{session_id}

### Response

```json
{
  "session_id": "session_001",
  "events": [
    {
      "action_id": "action_001",
      "principal_id": "user_001",
      "agent_id": "agent_001",
      "action": "read_customer",
      "resource": "db_records:customer_table",
      "reversibility": "READ",
      "trajectory_score": 0.22,
      "risk_band": "LOW",
      "decision": "ALLOW",
      "reason": "Authorized read within permitted scope",
      "timestamp": "2026-09-10T10:00:00Z"
    }
  ]
}
```

---

# 7. JSON Schema Contract

## ActionProposal

```json
{
  "principal_id": "string",
  "session_id": "string",
  "agent_id": "string",
  "action": "string",
  "resource": "string",
  "parameters": {}
}
```

### Required

```text
principal_id
session_id
agent_id
action
resource
```

`parameters` defaults to `{}`.

---

## ActionDecision

```json
{
  "action_id": "string",
  "decision": "ALLOW | CONFIRM | HARD_CONFIRM | BLOCK",
  "trajectory_score": "number",
  "risk_band": "LOW | MEDIUM | HIGH",
  "reversibility": "READ | WRITE | DESTRUCTIVE",
  "reason": "string"
}
```

---

## TrajectoryEvent

```json
{
  "step": "integer",
  "action": "string",
  "resource": "string",
  "reversibility": "READ | WRITE | DESTRUCTIVE",
  "trajectory_score": "number",
  "risk_band": "LOW | MEDIUM | HIGH",
  "decision": "ALLOW | CONFIRM | HARD_CONFIRM | BLOCK"
}
```

---

## AuditEvent

```json
{
  "action_id": "string",
  "principal_id": "string",
  "session_id": "string",
  "agent_id": "string",
  "action": "string",
  "resource": "string",
  "reversibility": "READ | WRITE | DESTRUCTIVE",
  "trajectory_score": "number",
  "risk_band": "LOW | MEDIUM | HIGH",
  "decision": "ALLOW | CONFIRM | HARD_CONFIRM | BLOCK",
  "reason": "string",
  "timestamp": "datetime"
}
```

---

# 8. ENUM CONTRACT

## Decision

```text
ALLOW
CONFIRM
HARD_CONFIRM
BLOCK
```

## RiskBand

```text
LOW
MEDIUM
HIGH
```

## Reversibility

```text
READ
WRITE
DESTRUCTIVE
```

## Destructiveness Level

For trajectory calculations:

```text
READ = 0
WRITE = 1
DESTRUCTIVE = 2
```

---

# 9. DECISION MATRIX

| Authorization | Risk Band | Reversibility | Decision |
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

### Important distinction

`CONFIRM` and `HARD_CONFIRM` mean the action is not automatically executed.

```text
CONFIRM
   ↓
Human approval
   ↓
Re-validation
   ↓
Execution
```

`BLOCK` means the protected tool is never executed.

---

# 10. ACTION CLASSIFICATION CONTRACT

## READ

Examples:

```text
read_logs
search_customers
read_customer
```

Characteristics:

- Non-destructive
- No state destruction
- Normally low execution friction

---

## WRITE

Examples:

```text
export_customers
update_customer
create_report
send_report
```

Characteristics:

- Changes or creates external state
- Potentially reversible depending on tool
- May require confirmation at elevated trajectory risk

---

## DESTRUCTIVE

Examples:

```text
change_permissions
drop_table
delete_records
disable_backup
```

Characteristics:

- High impact
- Destructive or potentially irreversible
- Requires explicit human confirmation when otherwise permitted
- Must be blocked when trajectory reaches HIGH

---

# 11. TOOL REGISTRY CONTRACT

The demo registry must contain at least:

| Tool | Resource | Class |
|---|---|---|
| read_logs | logs | READ |
| search_customers | db_records:customer_table | READ |
| read_customer | db_records:customer_table | READ |
| export_customers | db_records:customer_table | WRITE |
| update_customer | db_records:customer_table | WRITE |
| change_permissions | system:permissions | DESTRUCTIVE |
| drop_table | db_schema:core | DESTRUCTIVE |

Every tool definition should contain:

```text
name
resource
reversibility
required_scope
handler
```

The agent must access tools through the Tripwire flow.

---

# 12. AUTHORIZATION CONTRACT

Authorization is based on:

```text
principal
+
scope
+
action
+
resource
```

Example:

```text
principal: user_001
scope:
  - customer:read
  - customer:write
```

Then:

```text
read_customer
→ allowed

update_customer
→ allowed

drop_table
→ denied
```

Authorization must be evaluated **per action**.

Do not rely only on the initial user request.

---

# 13. TRAJECTORY CONTRACT

The trajectory engine tracks:

```text
scope_drift
destructiveness_growth
velocity
footprint_breadth
```

Each signal is normalized to `[0,1]` unless otherwise specified.

---

# 14. TRAJECTORY FORMULA

```text
step_score =
    0.30 * scope_drift
  + 0.35 * destructiveness_growth
  + 0.15 * velocity
  + 0.20 * footprint_breadth
```

---

# 15. ASYMMETRIC EMA

If the current step increases risk:

```text
new_score =
    previous_score
    + 0.6 * (step_score - previous_score)
```

If the current step decreases risk:

```text
new_score =
    previous_score
    + 0.2 * (step_score - previous_score)
```

This intentionally makes:

```text
risk increase fast
risk decay slowly
```

---

# 16. RISK BANDS

```text
LOW
trajectory_score < 0.35

MEDIUM
0.35 <= trajectory_score <= 0.65

HIGH
trajectory_score > 0.65
```

Thresholds must be configurable.

---

# 17. CROSS-SESSION STATE CONTRACT

Persistent trajectory state belongs to the principal, not only to a session.

Minimum state:

```text
principal_id
trajectory_score
scope_footprint
max_destructiveness_level
action_counts
last_session_at
```

Example:

```text
Session 1
  READ logs
  READ customers
  WRITE orders
        ↓
Persist state
        ↓
Session 2
  ACCESS sensitive resource
  CHANGE permissions
        ↓
Previous state influences new score
```

A new session must not automatically reset all behavioral context.

---

# 18. ATTACK SCENARIO CONTRACT

Scenario name:

```text
database_escalation_attack
```

Sequence:

```text
1. read_logs
2. read_customer
3. update_customer
4. export_customers
5. change_permissions
6. drop_table
```

Expected behavior:

```text
Early actions
    ↓
ALLOW

Trajectory rises
    ↓
CONFIRM / elevated friction

High-risk escalation
    ↓
BLOCK
```

Critical acceptance criterion:

```text
drop_table handler must NOT execute after BLOCK.
```

---

# 19. LEGITIMATE SCENARIO CONTRACT

Scenario name:

```text
monthly_finance_report
```

Conceptual sequence:

```text
1. read invoices
2. analyze invoices
3. create report
4. write report
5. send report
```

Expected behavior:

```text
Actions remain aligned with original purpose.
Trajectory should remain LOW/MEDIUM.
Legitimate work should not be blindly blocked.
```

If a destructive action is genuinely required:

```text
CONFIRM
    ↓
Human approval
    ↓
Re-validation
    ↓
Execute
```

---

# 20. CROSS-SESSION SCENARIO

## Session 1

```text
read_logs
read_customer
update_customer
```

Persist the resulting trajectory state.

## Session 2

```text
export_customers
change_permissions
drop_table
```

Expected:

```text
Session 2 starts with persisted context.
Risk is not reset to zero.
Escalation is detected earlier than it would be with a fresh principal.
```

---

# 21. DATABASE CONTRACT

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
action_id
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

The database schema may include additional technical fields, but the above fields are part of the shared contract.

---

# 22. FRONTEND CONTRACT

The frontend is presentation only.

It must NOT calculate security decisions independently.

The backend is the authority.

Dashboard must show:

```text
Principal
Session
Current Action
Trajectory Score
Risk Band
Decision
Reason
```

Timeline:

```text
✓ READ logs
✓ READ customers
✓ WRITE orders
⚠ EXPORT
⚠ CHANGE PERMISSIONS
🚫 DROP TABLE
```

Approval UI:

```text
Action requires confirmation

[ APPROVE ]
[ DENY ]
```

---

# 23. FILE OWNERSHIP

## PERSON A — SECURITY CORE / BACKEND

### Owns

```text
backend/
```

### Responsible for

```text
FastAPI
SQLAlchemy
Database
Models
Schemas
Authorization
Classifier
Trajectory
Decision Gate
Persistence
Audit
Runtime APIs
Backend tests
```

### Must not modify

```text
frontend/
agent/
```

unless both developers agree on an integration change.

---

## PERSON B — AGENT / TOOLS / FRONTEND

### Owns

```text
agent/
frontend/
scripts/
```

### Responsible for

```text
Demo Agent
Tool Registry
Mock Tools
Attack Scenario
Legitimate Scenario
Scenario Runner
Dashboard
Trajectory Visualization
Confirmation UI
Frontend Integration
Frontend/E2E tests
```

### Must not modify

```text
backend/
```

unless both developers agree on an integration change.

---

# 24. SHARED FILES

These files require coordination:

```text
docs/API_CONTRACT.md
README.md
docs/ARCHITECTURE.md
docs/DEMO_SCRIPT.md
```

The API contract must not be changed unilaterally after implementation begins.

If an API change becomes necessary:

1. Discuss it.
2. Update the contract.
3. Update both implementations.
4. Test both sides.
5. Commit the change.

---

# 25. PRE-IMPLEMENTATION CHECKLIST

Both developers must confirm:

- [ ] We agree that Tripwire is middleware around an agent.
- [ ] We agree that the agent cannot directly bypass Tripwire.
- [ ] API endpoints are frozen.
- [ ] Request/response JSON structures are frozen.
- [ ] Decision enums are frozen.
- [ ] Risk bands are frozen.
- [ ] Reversibility classes are frozen.
- [ ] Decision matrix is frozen.
- [ ] Trajectory formula is frozen.
- [ ] Cross-session state requirements are understood.
- [ ] Tool registry is frozen.
- [ ] Attack scenario is frozen.
- [ ] Legitimate scenario is frozen.
- [ ] Database fields are agreed.
- [ ] Person A ownership is agreed.
- [ ] Person B ownership is agreed.
- [ ] Git branches are created from the same latest `develop`.
- [ ] No developer is depending on undocumented behavior.

---

# 26. GIT CONTRACT

Start from the same base:

```bash
git checkout develop
git pull origin develop
```

Person A:

```bash
git checkout -b develop/tripwire-backend
```

Person B:

```bash
git checkout -b develop/tripwire-frontend-demo
```

Suggested commit style:

```text
Add TRIPWIRE: <summary>
```

Keep commits small and focused.

---

# 27. INTEGRATION POINTS

## Integration 1 — API

Verify:

```text
Demo Agent
    ↓
POST /actions/propose
    ↓
Backend
    ↓
Decision
```

## Integration 2 — Tool Enforcement

Verify:

```text
ALLOW
  → tool executes

CONFIRM
  → tool waits

BLOCK
  → tool never executes
```

## Integration 3 — Full System

Verify:

```text
Agent
 ↓
Tripwire
 ↓
Trajectory
 ↓
Decision
 ↓
Tool
 ↓
Audit
 ↓
Dashboard
```

---

# 28. SECURITY INVARIANTS

These must always remain true.

### Invariant 1

```text
Unauthorized action
→ BLOCK
→ no protected tool execution
```

### Invariant 2

```text
Destructive action
→ confirmation required
```

### Invariant 3

```text
HIGH trajectory
→ dangerous action cannot execute automatically
```

### Invariant 4

```text
BLOCK
→ protected tool handler is never called
```

### Invariant 5

```text
Cross-session state
→ persisted
→ available to later sessions
```

### Invariant 6

```text
Frontend cannot override backend security decisions.
```

### Invariant 7

```text
Agent cannot directly bypass Tripwire.
```

---

# 29. Definition of Contract Completion

The pre-implementation stage is complete when:

```text
API
        ✓
JSON schemas
        ✓
Decision matrix
        ✓
Action classifications
        ✓
Trajectory formula
        ✓
Database fields
        ✓
Tool registry
        ✓
Attack scenario
        ✓
Legitimate scenario
        ✓
Cross-session scenario
        ✓
Folder ownership
        ✓
Security invariants
        ✓
```

Only after this checklist is approved should implementation begin.

---

# 30. FIRST IMPLEMENTATION STEP AFTER CONTRACT FREEZE

After both developers approve this contract:

## Person A starts

```text
PHASE A1
Backend Foundation
```

## Person B starts

```text
PHASE B1
Agent + Tool + Frontend Foundation
```

They can work in parallel because both are implementing against this frozen contract.

---

# 31. Final Shared Principle

> **Do not build two interpretations of Tripwire. Build two halves of the same contract.**

Person A builds the **security brain**.

Person B builds the **agent, tools, and user experience**.

The contract above is the boundary between them.
