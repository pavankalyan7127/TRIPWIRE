"""Action proposal and confirmation API routes.

Implements:
- POST /api/v1/actions/propose (Phase A8)
- POST /api/v1/actions/{action_id}/confirm (Phase A10)

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §3.2, §4
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.repositories.audit import AuditRepository
from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.db.session import get_db
from app.models.enums import Decision, RiskBand
from app.schemas.requests import ActionProposalRequest, ConfirmationRequest
from app.schemas.responses import ActionDecisionResponse, ConfirmationResponse
from app.security.authorization import AuthorizationContext, AuthorizationService
from app.security.decision_engine import DecisionEngine, classify_risk_band
from app.security.execution_gate import (
    ExecutionContext,
    ToolExecutionGate,
    get_execution_gate,
)
from app.security.tool_registry import default_tool_registry
from app.trajectory.engine import TrajectoryEngine

router = APIRouter()


@router.post("/actions/propose", response_model=ActionDecisionResponse)
def propose_action(
    request: ActionProposalRequest,
    db: Session = Depends(get_db),
) -> ActionDecisionResponse:
    """Evaluate an action proposal through the Tripwire security pipeline.

    Security Pipeline:
    1. Validate request
    2. Validate session exists and matches principal/agent
    3. Lookup trusted tool metadata from ToolRegistry
    4. Run AuthorizationService
    5. Run TrajectoryEngine (updates cross-session state)
    6. Run DecisionEngine
    7. Persist audit event
    8. Return security decision

    CRITICAL: This endpoint does NOT execute tools.
    Tool execution belongs to Phase A9/A10.

    Args:
        request: Action proposal containing principal_id, session_id, agent_id, action, resource, parameters.
        db: Database session (dependency-injected).

    Returns:
        ActionDecisionResponse with action_id, decision, trajectory_score, risk_band, reversibility, reason.

    Raises:
        HTTPException: If validation fails, session not found, or unknown tool.
    """
    session_repo = SessionRepository(db)
    audit_repo = AuditRepository(db)

    # Generate unique action_id
    action_id = f"action_{uuid.uuid4().hex[:12]}"

    # STEP 2: Validate session exists
    session_model = session_repo.get_by_id(request.session_id)
    if session_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{request.session_id}' not found",
        )

    # STEP 3: Validate session.principal_id matches request.principal_id
    if session_model.principal_id != request.principal_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Session '{request.session_id}' belongs to principal '{session_model.principal_id}', not '{request.principal_id}'",
        )

    # STEP 4: Validate session.agent_id matches request.agent_id
    if session_model.agent_id != request.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Session '{request.session_id}' belongs to agent '{session_model.agent_id}', not '{request.agent_id}'",
        )

    # STEP 5: Lookup action in ToolRegistry (fail-closed on unknown tool)
    try:
        tool = default_tool_registry.get_or_raise(request.action)
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown tool: {str(e)}",
        )

    # STEP 6: Resolve trusted metadata from registry
    trusted_action_class = tool.action_class
    trusted_resource = tool.resource
    trusted_reversibility = tool.reversibility

    # STEP 7: Run AuthorizationService
    auth_context = AuthorizationContext(
        principal_id=request.principal_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
    )

    auth_service = AuthorizationService(db)
    auth_result = auth_service.authorize(
        context=auth_context,
        action=request.action,
        resource=trusted_resource,
    )

    # STEP 8: Run TrajectoryEngine (updates principal trajectory state)
    trajectory_engine = TrajectoryEngine(db, tool_registry=default_tool_registry)
    trajectory_result = trajectory_engine.evaluate_action(
        principal_id=request.principal_id,
        session_id=request.session_id,
        action=request.action,
        timestamp=datetime.now(timezone.utc),
    )

    trajectory_score = trajectory_result.new_score
    risk_band = classify_risk_band(trajectory_score)

    # STEP 9: Run DecisionEngine
    decision_engine = DecisionEngine()
    decision_result = decision_engine.evaluate(
        authorized=auth_result.authorized,
        trajectory_score=trajectory_score,
        action_class=trusted_action_class,
    )

    # STEP 10: Persist audit event with parameters
    audit_repo.create(
        action_id=action_id,
        principal_id=request.principal_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=trusted_resource,
        reversibility=trusted_reversibility.value,
        trajectory_score=trajectory_score,
        risk_band=risk_band.value,
        decision=decision_result.decision.value,
        reason=decision_result.reason,
        parameters=request.parameters,
        timestamp=datetime.now(timezone.utc),
    )

    # Commit all state updates (trajectory, audit)
    db.commit()

    # STEP 11: Return security decision (NO TOOL EXECUTION)
    return ActionDecisionResponse(
        action_id=action_id,
        decision=decision_result.decision,
        trajectory_score=trajectory_score,
        risk_band=risk_band,
        reversibility=trusted_reversibility,
        reason=decision_result.reason,
    )


@router.post("/actions/{action_id}/confirm", response_model=ConfirmationResponse)
def confirm_action(
    action_id: str,
    request: ConfirmationRequest,
    db: Session = Depends(get_db),
    gate: ToolExecutionGate = Depends(get_execution_gate),
) -> ConfirmationResponse:
    """Confirm and re-validate an action requiring human approval (Phase A10).

    Security Pipeline:
    1. Validate action_id and approved_by are non-empty.
    2. Retrieve original action record from audit persistence.
    3. Validate action is eligible for confirmation (CONFIRM or HARD_CONFIRM).
       - ALLOW and BLOCK are rejected.
    4. Check for replay/double-execution: if already EXECUTED, return idempotent response without executing tool.
    5. Validate original session still exists and principal/agent identities match.
    6. Re-check authoritative ToolRegistry metadata (fails closed if unknown or inconsistent).
    7. Re-run AuthorizationService using current principal/session authorization context.
    8. Re-evaluate current trajectory score and risk band for the principal.
    9. Re-run DecisionEngine with current security inputs.
    10. Enforce Decision Gate:
        - If current decision is BLOCK: human approval CANNOT override; tool execution is rejected.
        - If current decision is still permitted (ALLOW, CONFIRM, HARD_CONFIRM):
          construct trusted ExecutionContext and execute strictly through ToolExecutionGate.
    11. Update audit event execution status and approver.
    12. Return ConfirmationResponse with execution outcome.

    Args:
        action_id: Unique action identifier.
        request: ConfirmationRequest containing approved_by.
        db: Database session (dependency-injected).
        gate: Authoritative ToolExecutionGate (dependency-injected).

    Returns:
        ConfirmationResponse with action_id, decision, approved_by, execution_status.

    Raises:
        HTTPException: If action_id/approved_by invalid, action not found, session mismatch, or action not confirmable.
    """
    clean_action_id = action_id.strip() if action_id else ""
    if not clean_action_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action ID cannot be empty",
        )

    approved_by = request.approved_by.strip()
    if not approved_by:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="approved_by must be a non-empty string",
        )

    # STEP 2: Retrieve original action from audit history
    audit_repo = AuditRepository(db)
    session_repo = SessionRepository(db)
    principal_repo = PrincipalRepository(db)

    audit_event = audit_repo.get_by_action_id(clean_action_id)
    if audit_event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action '{clean_action_id}' not found",
        )

    # STEP 3: Validate action is eligible for confirmation
    if audit_event.decision not in (Decision.CONFIRM.value, Decision.HARD_CONFIRM.value):
        if audit_event.decision == Decision.BLOCK.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action '{clean_action_id}' was BLOCKED and cannot be confirmed",
            )
        elif audit_event.decision == Decision.ALLOW.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action '{clean_action_id}' was already allowed and does not require confirmation",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action '{clean_action_id}' with decision '{audit_event.decision}' is not eligible for confirmation",
            )

    # STEP 4: Check replay / double execution protection
    if audit_event.execution_status == "EXECUTED":
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=Decision.ALLOW,
            approved_by=audit_event.approved_by or approved_by,
            execution_status="EXECUTED",
        )

    # STEP 5: Validate session exists and matches principal/agent identities
    session_model = session_repo.get_by_id(audit_event.session_id)
    if session_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{audit_event.session_id}' not found",
        )
    if session_model.principal_id != audit_event.principal_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Session '{audit_event.session_id}' belongs to principal '{session_model.principal_id}', not '{audit_event.principal_id}'",
        )
    if session_model.agent_id != audit_event.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Session '{audit_event.session_id}' belongs to agent '{session_model.agent_id}', not '{audit_event.agent_id}'",
        )

    # STEP 6: Re-check ToolRegistry metadata (fail-closed if unknown or inconsistent)
    tool = default_tool_registry.get(audit_event.action)
    if tool is None or tool.resource != audit_event.resource:
        audit_repo.update_execution(
            action_id=clean_action_id,
            execution_status="NOT_EXECUTED",
            approved_by=approved_by,
        )
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=Decision.BLOCK,
            approved_by=approved_by,
            execution_status="NOT_EXECUTED",
        )

    # STEP 7: Re-run AuthorizationService using current principal/session authorization context
    auth_context = AuthorizationContext(
        principal_id=audit_event.principal_id,
        session_id=audit_event.session_id,
        agent_id=audit_event.agent_id,
    )
    auth_service = AuthorizationService(db)
    auth_result = auth_service.authorize(
        context=auth_context,
        action=audit_event.action,
        resource=tool.resource,
    )
    if not auth_result.authorized:
        audit_repo.update_execution(
            action_id=clean_action_id,
            execution_status="NOT_EXECUTED",
            approved_by=approved_by,
        )
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=Decision.BLOCK,
            approved_by=approved_by,
            execution_status="NOT_EXECUTED",
        )

    # STEP 8: Re-evaluate current trajectory score and risk band
    principal = principal_repo.get_or_create(audit_event.principal_id)
    current_trajectory_score = principal.trajectory_score
    current_risk_band = classify_risk_band(current_trajectory_score)

    # STEP 9: Re-run DecisionEngine with current security inputs
    dec_engine = DecisionEngine()
    dec_result = dec_engine.evaluate(
        authorized=auth_result.authorized,
        trajectory_score=current_trajectory_score,
        action_class=tool.action_class,
    )

    # STEP 10: Enforce Decision Gate (BLOCK can never be overridden)
    if dec_result.decision == Decision.BLOCK:
        audit_repo.update_execution(
            action_id=clean_action_id,
            execution_status="NOT_EXECUTED",
            approved_by=approved_by,
        )
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=Decision.BLOCK,
            approved_by=approved_by,
            execution_status="NOT_EXECUTED",
        )

    # STEP 11: Execute through authoritative ToolExecutionGate (A9)
    exec_context = ExecutionContext(
        action_id=clean_action_id,
        principal_id=audit_event.principal_id,
        session_id=audit_event.session_id,
        agent_id=audit_event.agent_id,
        action=audit_event.action,
        decision=Decision.ALLOW,  # Permitted by human confirmation + re-validation
        trajectory_score=current_trajectory_score,
        risk_band=current_risk_band,
        trusted_tool=tool,
    )

    params = audit_event.parameters_dict
    exec_result = gate.execute(exec_context, parameters=params)

    if exec_result.executed:
        audit_repo.update_execution(
            action_id=clean_action_id,
            execution_status="EXECUTED",
            approved_by=approved_by,
            executed_at=datetime.now(timezone.utc),
        )
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=Decision.ALLOW,
            approved_by=approved_by,
            execution_status="EXECUTED",
        )
    else:
        audit_repo.update_execution(
            action_id=clean_action_id,
            execution_status="NOT_EXECUTED",
            approved_by=approved_by,
        )
        return ConfirmationResponse(
            action_id=clean_action_id,
            decision=dec_result.decision,
            approved_by=approved_by,
            execution_status="NOT_EXECUTED",
        )

