# 🎙️ TRIPWIRE — Final Hackathon Judge Demo & Presentation Script

## ⏱️ Target Duration: 4 - 5 Minutes

---

## 🧭 Live Demo Checklist

1. **Terminal / CLI**:
   - Have terminal open at project root `TRIPWIRE/`.
2. **Web Dashboard**:
   - Run `npm run dev` in `frontend/` (accessible at `http://localhost:3000`).

---

## 🎬 Act 1: The Hook & The Problem (45 Seconds)

### 🗣️ Speaker Script:
> *"Judges, when organizations deploy AI agents today, their security teams harden the model: they write stricter system prompts, add regex filters, and run prompt red-teaming. But what they've built is a well-defended front door on a house with no walls.*
>
> *The most catastrophic agent intrusions documented in 2026—like the Claude Opus 5 production database deletion—did NOT use adversarial prompts or jailbreaks. An attacker made normal, individually defensible requests over time. Step 1: list files. Step 2: check schema. Step 3: export report. Step 4: drop table.
>
> *The model cannot stop this. It has no memory across sessions, no real-world reversibility awareness, and no way to see that a trajectory of reasonable requests constitutes an attack.*
>
> *Meet **TRIPWIRE**: a model-agnostic runtime security harness that wraps AI agents and enforces what foundation models structurally cannot."*

---

## 🎬 Act 2: Legitimate Work Flows Smoothly (60 Seconds)

### 🖥️ Action / UI Click:
- In the Dashboard, click **Interactive Scenario Runner** $\rightarrow$ Select **2. Legitimate Report** $\rightarrow$ Click **Auto-Run Scenario**.
- *(Or run in CLI)*: `python scripts/run_legitimate_demo.py`

### 🗣️ Speaker Script:
> *"A security harness that blocks everything is just a wall—it's useless. Let's first show a legitimate financial analyst querying accounts and updating invoice metadata.*
>
> *Notice as each action is evaluated:*
> 1. `read_logs` $\rightarrow$ Allowed (Low Risk, Score 0.033)
> 2. `search_customers` $\rightarrow$ Allowed (Score 0.079)
> 3. `read_customer` $\rightarrow$ Allowed (Score 0.107)
> 4. `update_customer` $\rightarrow$ Allowed (Score 0.179)
>
> *Because the agent operates within its scope boundaries, the trajectory score stays well beneath the 0.35 threshold. Legitimate work completes 100% with **zero false blocks**."*

---

## 🎬 Act 3: The "Boiling Frog" Multi-Step Attack Intercept (90 Seconds)

### 🖥️ Action / UI Click:
- In the Dashboard, select **1. Boiling Frog Attack** $\rightarrow$ Click **Step Next Action** to step through actions 1 to 6.
- *(Or run in CLI)*: `python scripts/run_attack_demo.py`

### 🗣️ Speaker Script:
> *"Now, watch what happens when an attacker executes the Boiling Frog escalation attack:*
>
> - **Step 1 & 2 (Reconnaissance)**: `read_logs` and `read_customer`. Allowed, but Tripwire records the footprint. Score rises to `0.132`.
> - **Step 3 & 4 (Staging & Export)**: `update_customer` and `export_customers`. Classified as `WRITE`. Score jumps to `0.484` (MEDIUM RISK), elevating friction.
> - **Step 5 (Privilege Escalation)**: `change_permissions`. Classified as `DESTRUCTIVE`. Trajectory score spikes to `0.779` (HIGH RISK).
> - **Step 6 (Catastrophe Attempt)**: The attacker prompts the agent to `drop_table`.
>
> *Look at the decision card:* **BLOCKED!**
>
> *The model itself believed this was a routine maintenance step. But Tripwire's behavioral trajectory engine detected the asymmetric velocity spike, breached the 0.65 threshold, and terminated execution.
>
> Look at the tool registry:* **Protected Table Execution Count is strictly 0.** The database was never touched."*

---

## 🎬 Act 4: Multi-Session Memory Persistence (60 Seconds)

### 🖥️ Action / UI Click:
- In Dashboard, switch to **3. Cross-Session Memory** $\rightarrow$ Run **Session 1 (Recon)** $\rightarrow$ Switch to **Session 2 (Infiltration)**.
- *(Or run in CLI)*: `python scripts/run_cross_session_demo.py`

### 🗣️ Speaker Script:
> *"Here is the critical differentiator: What if the attacker starts a brand-new session tomorrow with a new agent instance to clear their context window?*
>
> *In traditional agent systems, the slate resets to zero. In Tripwire, trajectory state is bound to the **verified Principal identity**.*
>
> *When Session 2 starts, it inherits the 0.373 risk score. The moment the attacker tries to export data and drop tables in the new session, Tripwire catches them on Step 1 and blocks them immediately on Step 2.*
>
> *Multi-day distributed attacks are completely dismantled."*

---

## 🎬 Act 5: Custom Action Sandbox & Closing Punchline (45 Seconds)

### 🖥️ Action / UI Click:
- Click **Custom Action Sandbox** tab $\rightarrow$ Click **Preset: Drop Table** $\rightarrow$ Click **Dispatch Action Proposal** $\rightarrow$ Show instant intercept and **Audit Forensics Table (with JSON Export)**.

### 🗣️ Speaker Script:
> *"Judges can also use our interactive sandbox to test custom arbitrary payloads in real time. Every decision is logged into a tamper-evident audit trail that security teams can export with one click.*
>
> *To summarize:*
> - **Traditional IAM**: Evaluates whether an isolated action is allowed.
> - **Tripwire**: Evaluates the **authorization, reversibility, and behavioral trajectory** surrounding that action across time.
>
> ***The agent decides what it wants to do; Tripwire decides whether it is safe to let it happen.***
>
> *Thank you! We're ready for your questions."*

---

## 🛡️ Judge Q&A Defense Sheet

### Q1: "How does Tripwire prevent latency bottlenecks?"
> **Answer**: *"Tripwire uses deterministic classification and asymmetric exponential moving averages ($O(1)$ constant time evaluation). Evaluation takes less than 2 milliseconds per action proposal."*

### Q2: "Why can't you just put this in the model's system prompt?"
> **Answer**: *"A system prompt has no persistent memory across sessions, cannot verify cryptographic principal identity tokens, and is vulnerable to indirect prompt injection. External middleware enforcement is the only mathematically sound guarantee."*

### Q3: "How do you handle false positives when an admin needs to do genuine maintenance?"
> **Answer**: *"Tripwire features a 3-tier Human-in-the-Loop (HITL) gate (`CONFIRM` / `HARD_CONFIRM`). Authorized administrators provide step-up credentials to approve high-impact operations without breaking the workflow."*
