# 🛡️ TRIPWIRE — Runtime Security Harness for AI Agents

> **PS1: Runtime Security Harness for AI Agents**  
> *"Build a runtime security harness, a model-agnostic middleware layer that wraps AI agents and enforces authorization boundaries, action reversibility gates, and cross-session behavioral trajectory monitoring, stopping the class of attacks that succeed precisely because the foundation model cannot stop them itself."*

---

## 🎯 Executive Summary & The Core Problem

When organizations deploy AI agents, security teams typically harden the model: tighter system prompts, output filters, and jailbreak red-teaming. **What they build is a well-defended front door on a house with no walls.**

The attacks that cause the most catastrophic damage do not look like attacks:
1. **The "Boiling Frog" Escalation**: A user makes normal, defensible requests. Over turns and sessions, the scope expands incrementally. Each step is individually justifiable; each is slightly beyond the last.
2. **Stateless Foundation Models**: The LLM evaluates each prompt in isolation with no cross-session memory, no real-world reversibility awareness, and no authorization chain visibility.
3. **The Disconnect**: By the time a destructive action (`DROP TABLE`, `DELETE S3_BUCKET`) is requested, the conversational norm has shifted so far that the model treats it as routine.

### The Tripwire Solution
**Tripwire** is an external, model-agnostic runtime security harness sitting between the AI agent and protected tools/databases.

```text
USER / ATTACKER
       ↓
AI AGENT (OpenAI / Claude / Gemini / Custom ReAct)
       ↓
ACTION PROPOSAL
       ↓
┌────────────────────────────────────────────────────────┐
│              TRIPWIRE SECURITY HARNESS                 │
│  ├── 1. Authorization Context Propagation (RBAC/ABAC)  │
│  ├── 2. Action Reversibility Gates (READ/WRITE/DESTR)  │
│  ├── 3. Cross-Session Behavioral Trajectory Monitor    │
│  ├── 4. Decision Gate (ALLOW / CONFIRM / BLOCK)        │
│  └── 5. Tamper-Evident Audit & Forensic Trail          │
└────────────────────────────────────────────────────────┘
       ↓
ALLOW / CONFIRM / BLOCK
       ↓
PROTECTED TOOL / DATABASE / CLOUD API
(Executed strictly if permitted; Execution = 0 on BLOCK)
```

---

## 🏛️ The 3 Core Pillars

### 1. Authorization Context Propagation
- Injects verified principal identity (`principal_id`, `role`, `scope`) into every action proposal.
- Intercepts tool calls at the middleware boundary; unauthorized actions are terminated immediately before reaching underlying APIs.

### 2. Action Reversibility Gates
Every action is classified by reversibility:
- `READ` (Level 0): Safe, idempotent inspection (`read_logs`, `search_customers`, `read_customer`).
- `WRITE` (Level 1): State modification (`update_customer`, `export_customers`).
- `DESTRUCTIVE` (Level 2): Irreversible or high-impact actions (`change_permissions`, `drop_table`). Mandates **Human-in-the-Loop (HITL)** confirmation.

### 3. Cross-Session Behavioral Trajectory Monitor
- **Asymmetric EMA Scoring**:
  $$\text{step\_score} = 0.30 \cdot \text{scope\_drift} + 0.35 \cdot \text{destructiveness\_growth} + 0.15 \cdot \text{velocity} + 0.20 \cdot \text{footprint\_breadth}$$
  - If risk increases: $\text{score}_{new} = \text{score}_{prev} + 0.6 \cdot (\text{step\_score} - \text{score}_{prev})$ (Rises fast)
  - If risk decreases: $\text{score}_{new} = \text{score}_{prev} + 0.2 \cdot (\text{step\_score} - \text{score}_{prev})$ (Decays slowly)
- **Threshold Bands**:
  - `LOW (< 0.35)`: Routine execution (`ALLOW`).
  - `MEDIUM (0.35 - 0.65)`: Elevated friction (`CONFIRM` / `HARD_CONFIRM`).
  - `HIGH (> 0.65)`: Autonomous block (`BLOCK`).
- **Cross-Session State**: Persisted at the **Principal** identity level across sessions, defeating multi-day distributed attacks.

---

## 📊 Frozen Decision Matrix

| Authorization | Risk Band | Reversibility | Decision | Tool Execution Outcome |
|:---|:---|:---|:---|:---|
| **DENIED** | Any | Any | **`BLOCK`** | Execution = 0 (Terminated) |
| **ALLOWED** | LOW ($< 0.35$) | `READ` | **`ALLOW`** | Immediate Execution |
| **ALLOWED** | LOW ($< 0.35$) | `WRITE` | **`ALLOW`** | Immediate Execution |
| **ALLOWED** | LOW ($< 0.35$) | `DESTRUCTIVE` | **`CONFIRM`** | Requires Human Approval |
| **ALLOWED** | MEDIUM ($0.35 - 0.65$) | `READ` | **`ALLOW`** | Immediate Execution |
| **ALLOWED** | MEDIUM ($0.35 - 0.65$) | `WRITE` | **`CONFIRM`** | Requires Human Approval |
| **ALLOWED** | MEDIUM ($0.35 - 0.65$) | `DESTRUCTIVE` | **`HARD_CONFIRM`** | Requires Dual Re-validation |
| **ALLOWED** | HIGH ($> 0.65$) | Any | **`BLOCK`** | **Autonomous Halt (Execution = 0)** |

---

## 🚀 Quickstart & Demo Walkthrough

### 1. Run Automated Test Suites
Tripwire includes a complete automated test suite verifying all invariants:
```bash
# Master End-to-End Test Suite (Authorization, Reversibility, Trajectory, Zero-Bypass)
python -m unittest scripts/test_phase8_e2e.py

# Tool Enforcement Test Suite
python -m unittest scripts/test_phase4_tool_enforcement.py

# Adversarial Bypass & Security Integrity Test Suite
python -m unittest scripts/test_phase10_security_integrity.py
```

### 2. Run CLI Scenario Demonstrators
```bash
# 1. Run Boiling Frog Attack Demo (Neutralized on Step 6 with 0 table invocations)
python scripts/run_attack_demo.py

# 2. Run Legitimate Monthly Finance Report Demo (Completes with 0 false blocks)
python scripts/run_legitimate_demo.py

# 3. Run Cross-Session Persistence Demo (Session 1 state carried into Session 2)
python scripts/run_cross_session_demo.py
```

### 3. Launch React SOC Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:3000** in your browser to view:
- **Real-time Trajectory Monitor** with live SVG curve & risk bands.
- **Interactive Scenario Demonstrator** (1-Click replay for judges).
- **Custom Action Sandbox** (Test arbitrary custom action proposals).
- **Human-in-the-Loop Confirmation Modal** (`[ APPROVE ]` / `[ DENY ]`).
- **Forensic Audit Explorer** with live search, filters, and JSON export.

---

## 📁 Repository Structure

```text
TRIPWIRE/
├── agent/
│   ├── demo_agent.py              # Zero-bypass Agent client wrapping Tripwire API
│   ├── tool_registry.py           # 7 contract-frozen mock tools with telemetry
│   ├── scenarios/
│   │   ├── attack.json            # 6-step Boiling Frog database attack
│   │   ├── legitimate.json        # In-scope monthly finance workflow
│   │   ├── cross_session_1.json   # Multi-session attack setup phase
│   │   └── cross_session_2.json   # Multi-session attack execution phase
│   └── tests/
│       └── test_agent_and_tools.py # Unit tests for tools and scenarios
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── TrajectoryChart.tsx     # Live SVG trajectory chart & thresholds
│   │   │   ├── DecisionCard.tsx        # Real-time intercept & decision badge
│   │   │   ├── ActionTimeline.tsx      # Step-by-step forensic trail
│   │   │   ├── ConfirmationModal.tsx   # HITL approval modal
│   │   │   ├── AuditTable.tsx          # Tamper-evident audit log & export
│   │   │   ├── ScenarioRunner.tsx      # 1-Click judge demo vector runner
│   │   │   ├── ToolRegistryView.tsx    # Live tool execution counter view
│   │   │   ├── CustomActionSandbox.tsx # Custom action proposal playground
│   │   │   └── ArchitectureView.tsx    # PS1 architecture & decision matrix
│   │   ├── api/
│   │   │   └── client.ts               # Tripwire REST client & simulator
│   │   ├── types/
│   │   │   └── tripwire.ts             # Shared contract TypeScript interfaces
│   │   └── App.tsx                     # SOC Command Center dashboard
│   └── package.json
├── scripts/
│   ├── run_demo.py                     # Generic CLI scenario runner
│   ├── run_attack_demo.py              # Phase 5 Boiling Frog Attack demo
│   ├── run_legitimate_demo.py          # Phase 6 Legitimate Workflow demo
│   ├── run_cross_session_demo.py       # Phase 7 Cross-Session Persistence demo
│   ├── test_integration_p1.py          # Integration Point 1 test suite
│   ├── test_phase4_tool_enforcement.py # Phase 4 tool enforcement test suite
│   ├── test_phase8_e2e.py              # Master End-to-End test suite
│   └── test_phase10_security_integrity.py # Security integrity bypass test suite
├── TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md # Single source of truth contract
├── TRIPWIRE_FINAL_IMPLEMENTATION_PLAN.md        # Phase-by-phase implementation plan
└── README.md
```

---

## 🏆 Final Summary for Judges

| Capability | Model-Only System | With Tripwire Harness |
|:---|:---|:---|
| **Multi-Session Memory** | ❌ None (Stateless resets) | ✅ **Persistent Principal Trajectory Graph** |
| **Reversibility Awareness** | ❌ Blind execution | ✅ **3-Tier Classification & HITL Gates** |
| **Slow Escalation Detection** | ❌ Evaluates steps in isolation | ✅ **Asymmetric EMA Behavioral Drift Scoring** |
| **Bypass Containment** | ❌ Broken by Prompt Injections | ✅ **Zero-Bypass Action Boundary Enforcement** |
| **False-Positive Handling** | ❌ Dumb keyword filters block valid work | ✅ **Intelligent Trajectory Posture Elevation** |

> **"The agent decides what it wants to do; Tripwire decides whether it is safe to let it happen."**
