# Tripwire — Project Instructions for Claude Code

## 1. Project Overview

Tripwire is a model-agnostic runtime security harness for AI agents.

The system sits between an AI agent and protected tools and evaluates every proposed tool action before the protected tool is allowed to execute.

The core principle is:

> The agent proposes. Tripwire decides. The protected tool executes only when Tripwire permits it.

Tripwire is being built for the hackathon PS1 and must demonstrate:

1. Authorization context propagation
2. Action reversibility gates
3. Cross-session behavioral trajectory monitoring

The MVP should clearly demonstrate both:

- suspicious escalation being detected and stopped
- legitimate escalation being handled through controlled confirmation rather than being treated as an automatic attack

---

## 2. Core Architecture

The intended architecture is:

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
  ├── Reversibility
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

There must never be an uncontrolled:

```text
AI Agent → Protected Tool
```

execution path.

Every protected tool action must pass through Tripwire.

---

## 3. Source of Truth

The project uses the following authority hierarchy:

```text
1. Hackathon Problem Statement / PS1
2. docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md
3. Focused contract documents under docs/ when created
4. Existing repository architecture and conventions
5. Claude's implementation choices
```

The master contract is:

```text
docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md
```

It contains the agreed MVP contracts, including:

- API contracts
- JSON request/response structures
- domain concepts
- decision matrix
- trajectory algorithm
- tool classifications
- attack scenario
- legitimate scenario
- database requirements
- ownership boundaries
- security invariants

Do not silently change these definitions.

If a conflict is discovered between the PS, contract, and repository:

1. Identify the conflict.
2. Explain the impact.
3. Do not silently invent a workaround.
4. Ask for clarification when the conflict affects architecture, security, or public contracts.

---

## 4. Project Ownership

### Person A — Backend / Security Core

Person A owns:

```text
Backend/
```

including:

- FastAPI
- API routes
- Pydantic schemas
- domain models
- SQLAlchemy
- database
- migrations
- authorization
- action classification
- reversibility
- trajectory engine
- decision engine
- cross-session persistence
- tool registry
- tool adapters
- audit
- backend tests
- security enforcement

Person A's detailed implementation instructions are in:

```text
Backend/CLAUDE.md
```

### Person B

Person B owns the separate agent/frontend workstream.

Do not modify Person B's work without explicit approval.

Shared project documentation should be changed only when the contract itself needs an agreed update.

---

## 5. Security Invariants

These rules are non-negotiable.

### Authorization

Unauthorized actions must result in:

```text
BLOCK
```

### Blocked actions never execute

If Tripwire returns:

```text
BLOCK
```

the protected tool must never execute.

### Destructive actions require confirmation

Destructive actions must never automatically execute.

They require:

```text
CONFIRM
```

or:

```text
HARD_CONFIRM
```

depending on risk.

### HIGH trajectory blocks

At HIGH trajectory risk:

```text
READ        → BLOCK
WRITE       → BLOCK
DESTRUCTIVE → BLOCK
```

### Confirmation requires re-validation

Human confirmation must not bypass security checks.

The action must be revalidated before execution.

### Cross-session state persists

Trajectory state must persist for the principal across sessions.

### Frontend is not the security authority

The frontend may display a decision but cannot override the backend.

### Agent cannot bypass Tripwire

The architecture must not provide a direct agent-to-tool execution path.

---

## 6. Backend Development Rule

When Claude Code is working inside:

```text
Backend/
```

it must also follow:

```text
Backend/CLAUDE.md
```

The backend CLAUDE file contains the detailed implementation rules, security contracts, trajectory formulas, API examples, testing requirements, and Person A workflow.

---

## 7. Implementation Philosophy

Tripwire should be implemented incrementally.

Do not attempt to build the entire system in one operation.

The preferred workflow is:

```text
Understand
    ↓
Analyze
    ↓
Implement one phase
    ↓
Test
    ↓
Review
    ↓
Next phase
```

Claude must not automatically continue into later phases after completing a requested phase.

---

## 8. Read Before Write

Before modifying code, Claude must:

1. Read the relevant contract.
2. Inspect the existing repository.
3. Understand the existing architecture.
4. Identify reusable components.
5. Identify affected files.
6. Identify security implications.
7. Implement only the requested change.
8. Add/update tests.
9. Run relevant tests.
10. Report the result.

Do not modify code merely because a structure appears different from the expected architecture.

Reuse existing repository conventions unless they conflict with the contract.

---

## 9. Minimal-Change Principle

Prefer:

```text
small
focused
testable
reviewable
```

changes.

Avoid:

- unrelated refactoring
- unnecessary dependency additions
- broad file rewrites
- changing public contracts without approval
- modifying another person's workstream
- duplicate implementations
- silently changing security semantics

---

## 10. Fail-Closed Security

Security-sensitive failures must never result in automatic tool execution.

For example:

```text
unknown tool
unknown authorization
invalid classification
missing required security context
trajectory calculation failure
invalid confirmation
```

must not be interpreted as permission to execute.

When security state cannot be safely determined:

```text
fail closed
```

and report the reason.

---

## 11. Testing Principle

Security behavior must be explicitly tested.

Especially:

```text
BLOCK → protected tool not executed

CONFIRM/HARD_CONFIRM
    → protected tool not executed until valid approval + revalidation

Unauthorized
    → BLOCK

HIGH trajectory
    → BLOCK for protected actions

Cross-session state
    → persists
```

Tests are part of the security implementation, not an optional final step.

---

## 12. Claude Code Working Rules

Claude must:

- inspect before implementing
- follow the source-of-truth hierarchy
- preserve security invariants
- work one phase at a time
- keep routes thin
- keep security logic deterministic and testable
- write tests for security behavior
- avoid unrelated changes
- report assumptions and conflicts
- stop when clarification is required

Claude must not:

- implement the whole project from one prompt
- silently alter contracts
- bypass Tripwire
- allow destructive actions automatically
- make the frontend the security authority
- allow an LLM to become the sole enforcement authority
- modify Person B's workstream without approval

---

## 13. Required Task Completion Report

After every implementation task, Claude should report:

### What was implemented

Short summary.

### Files changed

List every created/modified file.

### Contract alignment

Explain which contract requirements were implemented.

### Security impact

Explain which security invariants are affected.

### Tests

Show commands and results.

### Assumptions

List assumptions made.

### Conflicts

List any conflicts discovered.

### Remaining work

List only relevant remaining work.

---

## 14. First Claude Code Session

The first Claude Code session for the backend must be READ-ONLY.

Claude must first:

- read this file
- read `Backend/CLAUDE.md`
- read `docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md`
- inspect the complete repository
- inspect `Backend/`
- inspect existing tests
- inspect dependencies/configuration
- identify reusable components
- identify missing components
- identify contract conflicts

The first session must NOT:

- create implementation files
- modify source code
- install dependencies
- rewrite architecture
- implement Phase A1

The purpose of the first session is to establish a correct understanding of the repository and Tripwire contract before implementation begins.

---

## 15. Golden Rule

> Understand first. Implement second. Test third. Report fourth.

The goal is not to produce the most code.

The goal is to produce:

```text
correct contract
+ secure execution boundary
+ deterministic decisions
+ testable behavior
+ minimal changes
+ clear auditability
```
