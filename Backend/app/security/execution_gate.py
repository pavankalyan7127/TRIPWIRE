"""Tripwire Tool Execution Gate.

The execution gate is the strict security boundary through which protected tools execute.
No tool may execute directly from an agent proposal, API request, or frontend command.

Security Rules:
- ALLOW: Tool handler executed via authoritative ToolRegistry.
- CONFIRM: Execution denied (requires human approval and re-validation in A10).
- HARD_CONFIRM: Execution denied (requires human approval and re-validation in A10).
- BLOCK: Execution denied (permanently blocked).
- Unknown tools, mismatched metadata, or invalid parameters fail closed.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §28 (Security Invariants)
"""

from dataclasses import dataclass
from typing import Any, Optional

from app.models.enums import ActionClass, Decision, RiskBand
from app.security.mock_tools import MockToolExecutionRecorder
from app.security.tool_registry import ToolDefinition, ToolRegistry, default_tool_registry


@dataclass(frozen=True)
class ExecutionContext:
    """Trusted server-constructed execution context.

    Must be generated solely by server-side security evaluation (A7 Decision).
    Cannot be fabricated or altered by client/agent input.
    """
    action_id: str
    principal_id: str
    session_id: str
    agent_id: str
    action: str
    decision: Decision
    trajectory_score: float
    risk_band: RiskBand
    trusted_tool: ToolDefinition

    def __post_init__(self) -> None:
        if not self.action_id or not self.action_id.strip():
            raise ValueError("ExecutionContext must have a non-empty action_id.")
        if not self.principal_id or not self.principal_id.strip():
            raise ValueError("ExecutionContext must have a non-empty principal_id.")
        if not self.session_id or not self.session_id.strip():
            raise ValueError("ExecutionContext must have a non-empty session_id.")
        if not self.agent_id or not self.agent_id.strip():
            raise ValueError("ExecutionContext must have a non-empty agent_id.")
        if not self.action or not self.action.strip():
            raise ValueError("ExecutionContext must have a non-empty action name.")
        if not isinstance(self.decision, Decision):
            raise TypeError(f"ExecutionContext decision must be a Decision enum, got {type(self.decision).__name__}.")
        if not isinstance(self.risk_band, RiskBand):
            raise TypeError(f"ExecutionContext risk_band must be a RiskBand enum, got {type(self.risk_band).__name__}.")
        if not isinstance(self.trusted_tool, ToolDefinition):
            raise TypeError(f"ExecutionContext trusted_tool must be a ToolDefinition, got {type(self.trusted_tool).__name__}.")


@dataclass(frozen=True)
class ToolExecutionResult:
    """Explicit result of a tool execution attempt through the Execution Gate.

    Communicates execution status, output payload, and security rationale.
    """
    action_id: str
    action: str
    executed: bool
    decision: Decision
    result: Optional[Any] = None
    reason: str = ""
    error: Optional[str] = None


def create_execution_context(
    action_id: str,
    principal_id: str,
    session_id: str,
    agent_id: str,
    action: str,
    decision: Decision,
    trajectory_score: float,
    risk_band: RiskBand,
    tool_registry: Optional[ToolRegistry] = None,
) -> ExecutionContext:
    """Helper to construct a valid trusted ExecutionContext.

    Resolves the authoritative ToolDefinition from the trusted registry.

    Args:
        action_id: Unique action identifier.
        principal_id: Principal identifier.
        session_id: Session identifier.
        agent_id: Agent identifier.
        action: Tool name.
        decision: Evaluated security decision from DecisionEngine.
        trajectory_score: Evaluated trajectory score.
        risk_band: Evaluated risk band.
        tool_registry: Registry to resolve ToolDefinition from (defaults to default_tool_registry).

    Returns:
        Trusted ExecutionContext.

    Raises:
        KeyError: If the action is not in the trusted ToolRegistry.
    """
    registry = tool_registry or default_tool_registry
    trusted_tool = registry.get_or_raise(action)

    return ExecutionContext(
        action_id=action_id,
        principal_id=principal_id,
        session_id=session_id,
        agent_id=agent_id,
        action=action,
        decision=decision,
        trajectory_score=trajectory_score,
        risk_band=risk_band,
        trusted_tool=trusted_tool,
    )


class ToolExecutionGate:
    """Security gate controlling all protected tool execution in Tripwire.

    Enforces that:
    1. Only actions with Decision.ALLOW are permitted to execute.
    2. Decisions of CONFIRM, HARD_CONFIRM, and BLOCK are immediately rejected.
    3. Tool definitions and handlers are resolved exclusively from the trusted ToolRegistry.
    4. Execution is fail-closed on any validation error, missing handler, or exception.
    """

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        recorder: Optional[MockToolExecutionRecorder] = None,
    ):
        """Initialize the execution gate.

        Args:
            tool_registry: Authoritative tool registry. Defaults to default_tool_registry.
            recorder: Optional recorder to track tool executions for test isolation.
        """
        self.tool_registry = tool_registry or default_tool_registry
        self.recorder = recorder

    def execute(
        self,
        context: ExecutionContext,
        parameters: Optional[dict[str, Any]] = None,
    ) -> ToolExecutionResult:
        """Execute a tool if and only if permitted by the security decision.

        Args:
            context: Trusted server-generated ExecutionContext.
            parameters: Untrusted parameters dictionary to pass to the tool handler.

        Returns:
            ToolExecutionResult detailing whether the tool executed and the output.
        """
        # STEP 1: Validate context type
        if not isinstance(context, ExecutionContext):
            return ToolExecutionResult(
                action_id="unknown",
                action="unknown",
                executed=False,
                decision=Decision.BLOCK,
                reason="Execution denied: invalid execution context type.",
                error="Invalid ExecutionContext",
            )

        # STEP 2: Enforce Decision Gate
        # BLOCK -> never execute
        if context.decision == Decision.BLOCK:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=Decision.BLOCK,
                reason="Execution denied: action is BLOCKED by Tripwire security policy.",
            )

        # CONFIRM / HARD_CONFIRM -> never execute automatically in A9 (requires A10 human approval)
        if context.decision in (Decision.CONFIRM, Decision.HARD_CONFIRM):
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason=f"Execution denied: action requires human confirmation ({context.decision.value}).",
            )

        # Any decision other than ALLOW is rejected
        if context.decision != Decision.ALLOW:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason=f"Execution denied: unhandled decision '{context.decision}'.",
            )

        # STEP 3: Resolve tool from trusted ToolRegistry (fails closed on unknown tool)
        tool = self.tool_registry.get(context.action)
        if tool is None:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason=f"Execution denied: unknown tool '{context.action}' (fail-closed).",
                error=f"Tool '{context.action}' not registered",
            )

        # STEP 4: Verify context trusted_tool consistency with authoritative registry
        if context.trusted_tool.name != tool.name or context.trusted_tool.resource != tool.resource:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason="Execution denied: execution context metadata does not match trusted registry.",
                error="Mismatched tool metadata",
            )

        # STEP 5: Resolve authoritative handler from trusted ToolDefinition
        handler = tool.handler
        if handler is None:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason=f"Execution denied: no trusted handler registered for tool '{tool.name}'.",
                error=f"Missing handler for '{tool.name}'",
            )

        # STEP 6: Validate parameters type
        params = parameters if parameters is not None else {}
        if not isinstance(params, dict):
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason="Execution denied: parameters must be a dictionary.",
                error="Invalid parameters type",
            )

        # STEP 7: Execute trusted handler safely
        try:
            output = handler(**params)

            # Record call if recorder is attached
            if self.recorder is not None:
                self.recorder.record(
                    tool=context.action,
                    parameters=params,
                    result=output,
                )

            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=True,
                decision=Decision.ALLOW,
                result=output,
                reason="Tool executed successfully via Tripwire Execution Gate.",
            )
        except Exception as exc:
            return ToolExecutionResult(
                action_id=context.action_id,
                action=context.action,
                executed=False,
                decision=context.decision,
                reason=f"Tool execution failed: {str(exc)}",
                error=str(exc),
            )


# Authoritative default execution gate instance
default_tool_execution_gate = ToolExecutionGate(tool_registry=default_tool_registry)


def get_execution_gate() -> ToolExecutionGate:
    """FastAPI dependency for obtaining the authoritative ToolExecutionGate."""
    return default_tool_execution_gate

