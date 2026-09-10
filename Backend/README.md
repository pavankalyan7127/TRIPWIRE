# Tripwire — Model-Agnostic Runtime Security Harness (Backend)

> **"The agent proposes. Tripwire decides. The protected tool executes only when Tripwire permits it."**

This is the backend implementation of Tripwire, a model-agnostic runtime security harness for AI agents. It sits directly on the execution boundary between an AI agent and protected tools, evaluating every proposed action against **Identity & Authorization Context**, **Action Classification & Reversibility**, and **Multi-Signal Behavioral Trajectory** before permitting tool execution.

---

## 1. Product Overview & Architecture

Modern AI agents generate tool calls autonomously. Traditional authorization (RBAC) only checks *if* an agent has permission for a single tool, ignoring behavioral drift and sequential escalation. 

Tripwire introduces a **Runtime Security Interception Boundary**:
- **No Direct Execution**: The agent never talks directly to protected tools.
- **Adaptive Autonomy**: Safe actions (`READ`) execute autonomously (`ALLOW`); impactful actions (`WRITE`/`DESTRUCTIVE`) trigger controlled human confirmation (`CONFIRM`/`HARD_CONFIRM`); suspicious behavioral escalation triggers an immediate universal `BLOCK`.
- **Dynamic Re-Validation**: Human approval is not an unconditional execution pass. Tripwire re-validates live security state at confirmation time prior to tool execution.

```text
       ┌────────────────┐
       │   User Context │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │    AI Agent    │
       └───────┬────────┘
               │ Action Proposal
       ┌───────▼─────────────────────────────────────────┐
       │                   TRIPWIRE                      │
       │                                                 │
       │  1. Authorization Service (Scope Validation)    │
       │  2. Action Classification (READ/WRITE/DESTRUCT) │
       │  3. Multi-Signal Trajectory Engine (4 Signals)  │
       │  4. Deterministic Decision Engine (4 Bands)     │
       │  5. Dynamic Re-Validation Gate                  │
       │  6. Authoritative ToolExecutionGate             │
       │  7. Immutable Audit Trail                       │
       └───────┬─────────────────────────────────────────┘
               │
        ALLOW / CONFIRM / HARD_CONFIRM / BLOCK
               │
       ┌───────▼────────┐
       │ Tool Execution │ ─── Only if permitted by Tripwire!
       │   Gate (Mock)  │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │ Protected Tool │
       └────────────────┘
```

---

## 2. Core Security Guarantees & Invariants

| Invariant | Rule | Guarantee |
|:---|:---|:---|
| **Invariant 1 (Authorization)** | `Unauthorized -> BLOCK` | Lacking required scope immediately terminates execution. |
| **Invariant 2 (Zero Tool Execution)** | `BLOCK -> 0 Calls` | Tool handler is **never invoked** when decision is `BLOCK`. |
| **Invariant 3 (Controlled Destructiveness)** | `DESTRUCTIVE -> CONFIRM` | High-impact actions require explicit human oversight. |
| **Invariant 4 (Universal High-Risk Block)** | `HIGH Risk (> 0.65) -> BLOCK` | When trajectory risk is HIGH, **all** action classes are blocked. |
| **Invariant 5 (Dynamic Re-Validation)** | `Confirm Re-Checks State` | Human approval cannot bypass a revoked scope or elevated risk. |
| **Invariant 6 (Cross-Session State)** | `State Persists to Principal` | Historical risk persists across sessions; velocity resets cleanly. |
| **Invariant 7 (No Execution Bypass)** | `No Direct Path` | Protected tools execute exclusively through `ToolExecutionGate`. |
| **Invariant 8 (Backend Authority)** | `Server Decides` | Client cannot forge decisions, scores, or risk bands. |

---

## 3. Decision Matrix & Risk Bands

### Decision Matrix

| Authorization | Risk Band | Action Class | Decision | Execution Outcome |
|:---|:---|:---|:---|:---|
| **Unauthorized** | Any | Any | `BLOCK` | **NOT EXECUTED** |
| **Authorized** | `LOW` (< 0.35) | `READ` | `ALLOW` | **EXECUTED** |
| **Authorized** | `LOW` (< 0.35) | `WRITE` | `ALLOW` | **EXECUTED** |
| **Authorized** | `LOW` (< 0.35) | `DESTRUCTIVE` | `CONFIRM` | **Held until Human Approval** |
| **Authorized** | `MEDIUM` (0.35–0.65) | `READ` | `ALLOW` | **EXECUTED** |
| **Authorized** | `MEDIUM` (0.35–0.65) | `WRITE` | `CONFIRM` | **Held until Human Approval** |
| **Authorized** | `MEDIUM` (0.35–0.65) | `DESTRUCTIVE` | `HARD_CONFIRM` | **Held until Strict Admin Approval** |
| **Authorized** | `HIGH` (> 0.65) | `READ` | `BLOCK` | **NOT EXECUTED** |
| **Authorized** | `HIGH` (> 0.65) | `WRITE` | `BLOCK` | **NOT EXECUTED** |
| **Authorized** | `HIGH` (> 0.65) | `DESTRUCTIVE` | `BLOCK` | **NOT EXECUTED** |

### Multi-Signal Trajectory Formula

$$\text{step\_score} = 0.30 \cdot \text{scope\_drift} + 0.35 \cdot \text{destructiveness\_growth} + 0.15 \cdot \text{velocity} + 0.20 \cdot \text{footprint\_breadth}$$

**Asymmetric Exponential Moving Average (EMA)**:
- Rising Risk ($\text{step} \ge \text{prev}$): $\alpha = 0.6$ (Suspicious risk escalates rapidly)
- Decaying Risk ($\text{step} < \text{prev}$): $\alpha = 0.2$ (Risk decays slowly)

---

## 4. Quickstart Guide

### Prerequisites
- Python 3.11+
- Poetry

### 1. Install Dependencies
```bash
# Assuming you are in the Backend/ directory
poetry install
```

### 2. Run All Tests
```bash
poetry run pytest
```
*Expected: 305 passed in ~3s.*

### 3. Start the Live Tripwire Backend
```bash
poetry run uvicorn app.main:app --reload --port 8000
```
Interactive API docs will be available at: `http://localhost:8000/docs`.

---

## 5. Jury Demonstration Scenarios

Tripwire includes a self-contained, turnkey demonstration runner (`demo.py`) that operates with **zero external dependencies** and deterministic mock protected tools:

```bash
# Run the interactive demo menu
poetry run python demo.py

# Or run all 4 canonical scenarios automatically
poetry run python demo.py --all --auto
```

### Scenario 1 — Canonical Legitimate Agent (Monthly Finance Report)
- **Workflow**: `read_logs` $\to$ `search_customers` $\to$ `update_customer` $\to$ `change_permissions`.
- **Key Visuals**:
  1. Safe `READ` actions receive `ALLOW` and execute autonomously.
  2. The destructive `change_permissions` action receives `HARD_CONFIRM` and is held in `NOT_EXECUTED`.
  3. Admin confirmation (`{"approved_by": "sec_admin_carol"}`) triggers **dynamic re-validation** and successfully executes the tool.
  4. Final trajectory remains safely in `LOW`/`MEDIUM`.

### Scenario 2 — Canonical Suspicious Agent (Database Escalation Attack)
- **Workflow**: `read_logs` $\to$ `read_customer` $\to$ `update_customer` $\to$ `export_customers` $\to$ `change_permissions` $\to$ `drop_table`.
- **Key Visuals**:
  1. As the agent drifts scope and touches multiple database tables, multi-signal trajectory score rises.
  2. Unauthorized attempts and high-risk proposals receive an immediate `BLOCK`.
  3. Tool execution is **strictly prevented** (`0` tool handler calls).
  4. Forged confirmation attempts are rejected (`400 Bad Request: Action was BLOCKED and cannot be confirmed`).

### Scenario 3 — Dynamic Re-Validation Security Invariant
- Demonstrates that human approval is **not an unconditional pass**.
- An action is proposed when authorized (`CONFIRM`), but administrator revokes the scope before confirmation arrives.
- When human approval is submitted, Tripwire re-validates the live security state, detects the revoked scope, issues `BLOCK`, and prohibits tool execution.

### Scenario 4 — Cross-Session Trajectory Persistence
- Session 1 escalates behavioral trajectory risk for a principal.
- Session 2 starts fresh for the same principal: historical risk score and footprint are inherited, while first-action velocity is strictly reset to `0.0`.

---

## 6. API Reference

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/v1/sessions` | Initialize a new session with inherited principal trajectory. |
| `POST` | `/api/v1/actions/propose` | Evaluate an action proposal (Auth + Trajectory + Decision). |
| `POST` | `/api/v1/actions/{action_id}/confirm` | Re-validate and execute a confirmed action. |
| `GET` | `/api/v1/sessions/{session_id}/trajectory` | Retrieve current trajectory score and step events. |
| `GET` | `/api/v1/audit/{session_id}` | Retrieve complete chronological audit trail. |
| `GET` | `/health` | Application health check. |

---

## 7. Deterministic Mock Protected Tools

Tripwire ships with a deterministic suite of mock protected tools in `app/security/mock_tools.py`:
- `read_logs` (`READ`, Scope: `logs:read`)
- `search_customers` (`READ`, Scope: `customer:read`)
- `read_customer` (`READ`, Scope: `customer:read`)
- `update_customer` (`WRITE`, Scope: `customer:write`)
- `export_customers` (`WRITE`, Scope: `export:read`)
- `change_permissions` (`DESTRUCTIVE`, Scope: `permissions:write`)
- `drop_table` (`DESTRUCTIVE`, Scope: `schema:admin`)

Every tool call is tracked in `MockToolExecutionRecorder` to verify zero execution on blocked decisions.
