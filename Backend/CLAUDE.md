# Tripwire Backend — Claude Code Instructions

## 1. Purpose

This file defines the implementation context and working rules for **Person A (Backend/Security Core)** of the Tripwire project.

Tripwire is a **model-agnostic runtime security harness for AI agents**. It sits between an AI agent and protected tools and evaluates every proposed tool action before execution.

The core security principle is:

> **The agent proposes. Tripwire decides. The protected tool executes only when Tripwire permits it.**

This file is specifically for Claude Code sessions working on the `Backend/` workstream.

---

## 2. Source-of-Truth Hierarchy

When making implementation decisions, use this order of authority:

1. **Hackathon PS / official problem statement**
2. **`docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md`**
3. Focused contract documents under `docs/`, when present
4. Existing repository architecture and conventions
5. Implementation details proposed by Claude

If two sources conflict:

- Do **not** silently choose one.
- Do **not** weaken a security requirement to make implementation easier.
- Report the conflict clearly.
- Explain the affected files/components.
- Wait for a decision when the conflict changes externally visible behavior or security semantics.

The pre-implementation contract is the master contract for the agreed MVP.

---

# 3. Tripwire Architecture

The intended runtime flow is:

```text
User
  ↓
Identity / Request Context
  ↓
AI Agent
  ↓
Action Proposal
  ↓
Tripwire Connector / Security Harness
  ├── Authorization
  ├── Action Classification
  ├── Reversibility Gate
  ├── Trajectory Monitoring
  ├── Decision Gate
  └── Audit
  ↓
ALLOW / CONFIRM / HARD_CONFIRM / BLOCK
  ↓
Tool Adapter
  ↓
Protected Tool / Mock Tool
  ↓
Result
  ↓
Audit
```

There must be **no direct Agent → Tool path** in the Tripwire architecture.

Every observable/protected tool action must pass through the Tripwire-controlled boundary.

The frontend is a presentation layer. It must never become the security authority.

---

# 4. Person A Ownership

Person A owns the backend/security core:

- FastAPI application
- API routes
- Pydantic request/response schemas
- Domain models
- SQLAlchemy models/repositories
- Database infrastructure
- Database migrations
- Authorization
- Identity/request context propagation
- Action classification
- Reversibility classification
- Trajectory engine
- Cross-session trajectory persistence
- Decision engine / security gate
- Tool registry and tool adapters
- Audit events
- Backend unit tests
- Backend integration tests
- Backend security invariants

Person B separately owns:

```text
agent/
frontend/
scripts/
```

Do not modify Person B's workstream unless explicitly requested.

Shared project documentation should be changed only when the contract itself needs an agreed update.

---

# 5. MVP Technology Direction

The agreed MVP technology direction is:

- Python
- FastAPI
- Pydantic
- SQLAlchemy
- SQLite for the MVP persistence layer
- REST API
- Small deterministic/demo agent owned by Person B
- Deterministic mock/protected tools
- Pytest

Do not add a new framework, database, queue, authentication provider, LLM provider, or infrastructure dependency unless it is actually required and approved by the project contract/team.

If the existing repository already uses compatible tooling, prefer the repository's established conventions.

---

# 6. Security Invariants

These are non-negotiable.

### Invariant 1 — Authorization

If the proposed action is unauthorized:

```text
decision = BLOCK
```

The protected tool must not execute.

### Invariant 2 — BLOCK means no execution

A `BLOCK` decision must terminate the execution path.

The tool handler must never be called after a `BLOCK`.

### Invariant 3 — Destructive actions require confirmation

A destructive action must **never** be automatically executed merely because authorization succeeds.

Depending on trajectory/risk:

```text
CONFIRM
```

or

```text
HARD_CONFIRM
```

must be returned.

Execution happens only after explicit human approval and successful re-validation.

### Invariant 4 — HIGH trajectory cannot auto-execute

If trajectory risk is HIGH:

```text
READ      → BLOCK
WRITE     → BLOCK
DESTRUCTIVE → BLOCK
```

Do not create an exception that automatically executes an action because it is authorized.

### Invariant 5 — Confirmation must re-validate

The confirmation endpoint must not blindly execute an action that was previously approved.

On confirmation:

1. Load the original action.
2. Verify the action is still valid.
3. Re-evaluate the relevant security controls.
4. Verify the human approval.
5. Execute only if the current decision permits execution.
6. Record the outcome in audit history.

### Invariant 6 — Cross-session state persists

Trajectory state is associated with the principal, not only an in-memory session.

Relevant state includes:

```text
principal_id
scope_footprint
max_destructiveness
trajectory_score
action_count_by_class
last_session_ended_at
```

A new session for the same principal can therefore inherit historical trajectory state.

### Invariant 7 — Agent cannot bypass Tripwire

Do not expose a backend path that lets an agent directly invoke a protected tool without the security gate.

### Invariant 8 — Backend is the authority

The frontend may display:

```text
ALLOW
CONFIRM
HARD_CONFIRM
BLOCK
```

but cannot override the backend decision.

---

# 7. Core Decisions

## 7.1 Decision Enum

Use exactly:

```text
ALLOW
CONFIRM
HARD_CONFIRM
BLOCK
```

Do not introduce alternate spellings such as:

```text
APPROVE
REQUIRE_CONFIRMATION
DENY
REJECT
```

unless the contract is explicitly changed.

---

# 8. Decision Matrix

Authorization and trajectory/reversibility jointly determine the security decision.

| Authorization | Risk | Action Class | Decision |
|---|---|---|---|
| Unauthorized | Any | Any | BLOCK |
| Authorized | LOW | READ | ALLOW |
| Authorized | LOW | WRITE | ALLOW |
| Authorized | LOW | DESTRUCTIVE | CONFIRM |
| Authorized | MEDIUM | READ | ALLOW |
| Authorized | MEDIUM | WRITE | CONFIRM |
| Authorized | MEDIUM | DESTRUCTIVE | HARD_CONFIRM |
| Authorized | HIGH | READ | BLOCK |
| Authorized | HIGH | WRITE | BLOCK |
| Authorized | HIGH | DESTRUCTIVE | BLOCK |

Important:

**Destructive does not mean ALLOW.**

Even when authorization and trajectory risk are otherwise safe, destructive operations require explicit confirmation.

---

# 9. Risk Bands

Risk score range:

```text
0.0 <= score <= 1.0
```

Risk bands:

```text
LOW     < 0.35
MEDIUM  0.35 <= score <= 0.65
HIGH    > 0.65
```

Boundary values must be implemented consistently:

```text
0.349999... → LOW
0.35        → MEDIUM
0.65        → MEDIUM
0.650001... → HIGH
```

Do not create different thresholds in different modules.

---

# 10. Action Classification

The agreed action classes are:

```text
READ
WRITE
DESTRUCTIVE
```

Suggested levels used by the trajectory engine:

```text
READ        = 0.0
WRITE       = 0.5
DESTRUCTIVE = 1.0
```

These numeric levels are used for destructiveness growth and are not themselves authorization decisions.

---

# 11. Trajectory Monitoring

Tripwire monitors behavior across a sequence of actions.

The trajectory engine uses four signals.

## 11.1 Scope Drift

```text
scope_drift ∈ {0, 1}
```

Set to `1` when the current exact resource is outside the persisted scope footprint.

Otherwise:

```text
scope_drift = 0
```

---

## 11.2 Destructiveness Growth

Use:

```text
destructiveness_growth =
    max(0, current_level - prior_max_level)
```

Action levels:

```text
READ        = 0.0
WRITE       = 0.5
DESTRUCTIVE = 1.0
```

**Important implementation detail:**

Take a snapshot of the previous maximum destructiveness level **before** updating the state with the current action.

---

## 11.3 Velocity

Velocity is:

```text
velocity = clamp(
    1 - seconds_since_last_action / 60,
    0,
    1
)
```

For the first action of a session:

```text
velocity = 0
```

Do not compute velocity across a session boundary.

---

## 11.4 Footprint Breadth

Count distinct resources touched by the session, including the current resource.

The agreed fixed catalog size is `6`.

```text
footprint_breadth =
    distinct_resources_touched / 6
```

The value must remain bounded to `[0, 1]`.

---

# 12. Trajectory Step Score

Calculate:

```text
step_score =
    0.30 * scope_drift
  + 0.35 * destructiveness_growth
  + 0.15 * velocity
  + 0.20 * footprint_breadth
```

Do not silently change these weights.

---

# 13. Asymmetric EMA

The trajectory score is updated using an asymmetric exponential moving average.

If the new step score is greater than or equal to the previous score:

```text
trajectory_score =
    previous_score
    + 0.6 * (step_score - previous_score)
```

If the new step score is lower:

```text
trajectory_score =
    previous_score
    + 0.2 * (step_score - previous_score)
```

This makes suspicious escalation rise faster than risk decays.

---

# 14. Cross-Session Initialization

At session start:

- New principal → previous trajectory score is `0`.
- Existing principal → seed the session trajectory from the persisted principal trajectory score.

The persisted principal state must not be lost merely because a new session starts.

Do not calculate velocity from the previous session's final action.

---

# 15. Reference Attack Trajectory

The agreed attack example is:

```text
logs:app_logs
    ↓
db_records:customer_table
    ↓
db_records:orders_table
    ↓
db_records:export_all
    ↓
db_schema:core
```

Approximate expected trajectory progression:

```text
0.200 → LOW    → ALLOW
0.372 → MEDIUM → ALLOW
0.570 → MEDIUM → HARD_CONFIRM
0.568 → MEDIUM → HARD_CONFIRM
0.695 → HIGH   → BLOCK
```

These values are a behavioral reference for testing/demo validation. Small floating-point implementation details should not be used to justify changing the defined algorithm.

The important security outcome is:

```text
suspicious escalation → risk rises → dangerous action is stopped
```

---

# 16. Legitimate Escalation

Tripwire must also demonstrate that legitimate behavior is not treated identically to an attack.

The legitimate scenario primarily stays around:

```text
migration_schema:core
```

with slower actions and a final cleanup around:

```text
migration_schema:temp_table
```

The expected trajectory can reach approximately:

```text
0.382 → MEDIUM
```

and a destructive action should require:

```text
HARD_CONFIRM
```

rather than being automatically blocked solely because it is destructive.

The implementation must preserve the distinction between:

```text
legitimate escalation → controlled confirmation
```

and

```text
suspicious escalation → block when HIGH
```

---

# 17. Tool Registry

The protected-tool registry should contain enough metadata for Tripwire to make a deterministic security decision.

At minimum, a tool definition contains:

```text
name
resource
reversibility
required_scope
handler
```

The agreed MVP mock tools are:

```text
read_logs
search_customers
read_customer
export_customers
update_customer
change_permissions
drop_table
```

The registry should map tools to their action/reversibility classification and required authorization scope.

Do not allow a tool to execute unless it has passed through the security decision path.

---

# 18. Action Proposal Contract

The action proposal should follow this structure:

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

Required conceptual fields:

- `principal_id`
- `session_id`
- `agent_id`
- `action`
- `resource`
- `parameters`

Do not add frontend-specific fields to the security contract unless required.

---

# 19. Action Decision Response

The proposal response should expose the security result, including:

```json
{
  "action_id": "action_001",
  "decision": "ALLOW",
  "trajectory_score": 0.2,
  "risk_band": "LOW",
  "reversibility": "READ",
  "reason": "Authorized read within current scope."
}
```

The exact `reason` wording may vary, but the security decision and relevant risk information must remain explicit.

---

# 20. Confirmation Contract

Confirmation request:

```json
{
  "approved_by": "admin_001"
}
```

A confirmation is not an unconditional execution command.

The backend must revalidate the action before execution.

Conceptually:

```text
CONFIRM/HARD_CONFIRM requested
        ↓
load original action
        ↓
verify approval
        ↓
re-run security validation
        ↓
if still permitted
        ↓
execute protected tool
        ↓
audit
```

If revalidation produces `BLOCK`, do not execute.

---

# 21. API Contract

Base URL:

```text
http://localhost:8000
```

API prefix:

```text
/api/v1
```

Agreed MVP endpoints:

```text
POST /api/v1/sessions

POST /api/v1/actions/propose

POST /api/v1/actions/{action_id}/confirm

GET /api/v1/sessions/{session_id}/trajectory

GET /api/v1/audit/{session_id}
```

Keep API routes thin.

Business/security logic should live in services/domain components rather than being duplicated inside route handlers.

---

# 22. Session Responsibilities

A session represents a bounded interaction sequence.

The backend should associate actions with:

```text
session_id
principal_id
agent_id
```

Session lifecycle must allow the trajectory engine to know:

- first action
- previous action timestamp
- resources touched
- current trajectory score
- session end

When a session ends, the relevant trajectory state must be persisted to the principal-level state.

---

# 23. Database Direction

The agreed MVP database direction is SQLAlchemy-backed persistence.

Core conceptual tables:

```text
principals
sessions
audit_events
```

Additional tables may be introduced if required by the final repository architecture, but do not add unnecessary persistence.

The database must support cross-session trajectory state.

Relevant persisted principal state:

```text
principal_id
scope_footprint
max_destructiveness
trajectory_score
action_count_by_class
last_session_ended_at
```

Use migrations for schema changes where the repository supports migrations.

---

# 24. Audit Requirements

Security-relevant actions should produce audit events.

Audit information should make it possible to understand:

```text
who
which session
which agent
what action
which resource
what classification
what trajectory/risk
what decision
whether confirmation occurred
whether execution occurred
when it happened
```

Audit history must distinguish between:

```text
proposed
evaluated
confirmed
blocked
executed
```

as applicable to the implementation.

Do not allow audit logging to become a mechanism for bypassing the decision gate.

---

# 25. Authorization Context Propagation

The security boundary must retain the identity and context associated with the request.

At minimum, the backend must be able to associate an action with:

```text
principal_id
session_id
agent_id
```

Authorization should evaluate whether the principal has the required scope for the requested tool/resource.

Do not trust a frontend-only authorization result.

Do not treat the agent's textual claim that it is authorized as proof of authorization.

---

# 26. LLM Usage Rule

An LLM may be used for **novel/free-text action classification** if required by the MVP.

However:

> **LLM output must not become the sole enforcement authority at the protected execution boundary.**

Critical security decisions must remain deterministic and testable.

The architecture should therefore follow:

```text
Agent proposes
    ↓
Tripwire normalizes/classifies
    ↓
Deterministic security policy
    ↓
Decision
    ↓
Tool execution
```

If an LLM is used for classification, validate its output against controlled enums/registries before it can influence enforcement.

---

# 27. Backend Testing Strategy

Security behavior must be tested, not only happy-path API responses.

At minimum, tests should cover:

### Authorization

- authorized action
- unauthorized action
- unauthorized action cannot execute

### Reversibility

- READ + LOW → ALLOW
- WRITE + LOW → ALLOW
- DESTRUCTIVE + LOW → CONFIRM
- WRITE + MEDIUM → CONFIRM
- DESTRUCTIVE + MEDIUM → HARD_CONFIRM

### HIGH risk

- HIGH + READ → BLOCK
- HIGH + WRITE → BLOCK
- HIGH + DESTRUCTIVE → BLOCK
- BLOCK never invokes the tool handler

### Confirmation

- valid approval can proceed after revalidation
- invalid/missing approval cannot execute
- action becoming unsafe before confirmation is blocked
- confirmation cannot bypass authorization

### Trajectory

- first action velocity = 0
- velocity is calculated only within a session
- scope drift detection
- destructiveness growth
- footprint breadth
- step score formula
- asymmetric EMA
- risk band boundaries
- persisted cross-session score
- legitimate trajectory
- suspicious escalation trajectory

### Audit

- proposed action is recorded
- blocked action is recorded
- confirmed action is recorded
- executed action is recorded where applicable

---

# 28. Testing the Core Security Invariant

Every implementation of the execution gate should make this test possible:

```text
if decision == BLOCK:
    protected_tool_handler.assert_not_called()
```

Similarly:

```text
if decision == CONFIRM or HARD_CONFIRM:
    protected_tool_handler.assert_not_called()
```

until valid human approval and successful re-validation occur.

This is one of the most important tests in the entire MVP.

---

# 29. Development Workflow for Claude Code

Claude must work **one phase at a time**.

For every task:

1. Read the relevant contract/documentation.
2. Inspect the existing repository.
3. Identify existing patterns that can be reused.
4. State the intended files to change.
5. Implement only the requested phase.
6. Add/update tests for the behavior.
7. Run the relevant tests.
8. Report results.
9. Do not continue automatically into the next phase.

Do not implement the entire project from one prompt.

---

# 30. Before Editing Code

Before modifying code, Claude should determine:

```text
- What already exists?
- Which files are authoritative?
- Which components own the behavior?
- Which existing conventions should be reused?
- What contract does the behavior expose?
- What security invariant could be affected?
- What tests prove the behavior?
```

If the answer is unclear, inspect the repository before coding.

---

# 31. Change Boundaries

For a requested phase:

- Modify only files necessary for that phase.
- Avoid unrelated refactoring.
- Avoid broad formatting changes.
- Avoid changing API contracts without approval.
- Avoid renaming public fields/enums casually.
- Avoid introducing duplicate implementations.
- Avoid adding dependencies without justification.
- Do not modify frontend/agent files owned by Person B.
- Do not change the master contract silently.

---

# 32. Dependency Rules

Before adding a dependency:

1. Check whether an existing dependency already provides the capability.
2. Check `pyproject.toml`.
3. Explain why the dependency is needed.
4. Prefer the smallest reasonable dependency.
5. Do not install random packages during an implementation task.

If the dependency changes project architecture or deployment, stop and report before proceeding.

---

# 33. API Implementation Rules

Routes should primarily:

```text
validate input
→ call application/service layer
→ map result to response
```

Avoid putting large security algorithms directly inside FastAPI route functions.

The security decision must be reusable and independently testable.

---

# 34. Error Handling

Errors must not accidentally turn into tool execution.

When a required security input cannot be validated:

```text
fail closed
```

Do not interpret:

```text
missing authorization
unknown tool
unknown scope
invalid classification
trajectory calculation failure
```

as permission to execute.

For security-sensitive failures, prefer a safe denial/block behavior rather than fail-open execution.

---

# 35. Logging

Logs must help developers understand security behavior without exposing unnecessary sensitive data.

Useful diagnostic information includes:

```text
action_id
session_id
principal_id
action
resource
risk_band
decision
```

Do not log secrets or credentials.

---

# 36. Repository Hygiene

Do not commit:

```text
.env
API keys
passwords
tokens
private credentials
local database files when excluded by project conventions
```

Use environment variables/configuration for secrets.

---

# 37. Git Discipline

Person A should work on the backend branch/workstream agreed by the team.

Use focused commits.

Preferred commit title format:

```text
<Verb> <ITEM_ID>: <summary>
```

Example:

```text
Implement USXXX: add trajectory decision gate
```

Do not mix unrelated work into the same commit.

Before committing:

```text
git status
git diff
tests
```

must be reviewed.

---

# 38. Phase Discipline

The backend should be implemented incrementally.

Claude should not jump directly to the final integrated system.

A reasonable implementation sequence is:

```text
A1 — Repository/backend foundation
A2 — Domain models and contracts
A3 — Authorization/context
A4 — Tool registry + action classification
A5 — Reversibility gate
A6 — Trajectory engine
A7 — Decision engine
A8 — Persistence/cross-session state
A9 — Audit
A10 — Runtime APIs
A11 — Confirmation/re-validation
A12 — Integration/security tests
A13 — Demo hardening
```

The exact phase boundaries must be reconciled with the actual repository after the initial read-only analysis.

Do not assume every phase requires a new module if the existing architecture already has an appropriate place.

---

# 39. Required Claude Code Reporting Format

After every implementation task, report:

## What was implemented
Short summary.

## Files changed
List every created/modified file.

## Contract alignment
Explain which contract requirements were implemented.

## Security impact
State which security invariant(s) are affected.

## Tests
List commands and results.

Example:

```text
poetry run pytest tests/unit/...
5 passed
```

## Assumptions
List any assumptions made.

## Conflicts
List any contract/repository conflicts.

## Remaining work
Only mention work belonging to the current implementation roadmap.

Do not silently proceed to the next phase.

---

# 40. First Claude Code Session Rule

The first backend Claude Code session must be **read-only analysis**.

It must:

- read `CLAUDE.md`
- read the master pre-implementation contract
- inspect the repository
- inspect backend source
- inspect tests
- inspect dependencies/configuration
- identify reusable architecture
- identify missing components
- identify conflicts

It must **not**:

- create implementation files
- modify implementation files
- install dependencies
- run destructive commands
- rewrite architecture
- start implementing Phase A1

Only after the analysis is reviewed should Claude receive the Phase A1 implementation prompt.

---

# 41. Required Initial Analysis Output

The first Claude response should contain:

1. Current repository structure
2. Existing backend architecture
3. Existing dependencies
4. Existing database/infrastructure
5. Existing testing setup
6. Reusable components
7. Missing components for Person A
8. Contract/repository conflicts
9. Proposed implementation phases mapped to actual files
10. Exact files expected for Phase A1
11. Questions/ambiguities requiring clarification

No code changes should be made during this analysis.

---

# 42. Final Security Boundary

The most important architecture rule in Tripwire is:

```text
                    ┌──────────────────────┐
AI Agent ─────────→ │      TRIPWIRE       │
                    │                      │
                    │ Authorization       │
                    │ Classification       │
                    │ Reversibility        │
                    │ Trajectory           │
                    │ Decision Gate        │
                    │ Audit               │
                    └──────────┬───────────┘
                               │
                     only if permitted
                               ↓
                         Protected Tool
```

Never implement:

```text
AI Agent ─────────────────────→ Protected Tool
```

outside the Tripwire security boundary.

The protected tool must never be allowed to execute merely because the agent requested it.

---

# 43. Compact Contract Reference

For quick lookup:

```text
Decision:
ALLOW | CONFIRM | HARD_CONFIRM | BLOCK

Risk:
LOW    < 0.35
MEDIUM  0.35–0.65
HIGH   > 0.65

Action levels:
READ        0.0
WRITE       0.5
DESTRUCTIVE 1.0

Trajectory:
step =
    0.30*scope_drift
  + 0.35*destructiveness_growth
  + 0.15*velocity
  + 0.20*footprint_breadth

EMA rising:
previous + 0.6*(step - previous)

EMA falling:
previous + 0.2*(step - previous)

API:
POST /api/v1/sessions
POST /api/v1/actions/propose
POST /api/v1/actions/{action_id}/confirm
GET  /api/v1/sessions/{session_id}/trajectory
GET  /api/v1/audit/{session_id}
```

---

# 44. Claude's Golden Rule

**Understand first. Implement second. Test third. Report fourth.**

Do not optimize for writing the most code.

Optimize for:

```text
correct contract
+ deterministic security boundary
+ testable behavior
+ minimal changes
+ clear auditability
```

Tripwire's purpose is runtime security. When in doubt between a convenient implementation and a safer fail-closed implementation, preserve the security boundary and report the trade-off.
