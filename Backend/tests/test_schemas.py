"""Unit tests for Tripwire Pydantic schemas and domain models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.domain import (
    ActionDecision,
    ActionProposal,
    AuditEvent,
    TrajectoryEvent,
)
from app.models.enums import ActionClass, Decision, RiskBand
from app.schemas.requests import (
    ActionProposalRequest,
    ConfirmationRequest,
    SessionCreateRequest,
)
from app.schemas.responses import (
    ActionDecisionResponse,
    AuditEventSchema,
    AuditResponse,
    ConfirmationResponse,
    SessionCreateResponse,
    TrajectoryEventSchema,
    TrajectoryResponse,
)


class TestSessionCreateSchemas:
    """Tests for SessionCreateRequest and SessionCreateResponse."""

    def test_session_create_request_valid(self):
        """Valid session create request parses correctly."""
        data = {"principal_id": "user_001", "agent_id": "agent_001"}
        req = SessionCreateRequest(**data)
        assert req.principal_id == "user_001"
        assert req.agent_id == "agent_001"

    def test_session_create_request_missing_required_fields(self):
        """Missing required fields in SessionCreateRequest must fail validation."""
        with pytest.raises(ValidationError):
            SessionCreateRequest(principal_id="user_001")
        with pytest.raises(ValidationError):
            SessionCreateRequest(agent_id="agent_001")

    def test_session_create_response_defaults(self):
        """SessionCreateResponse has correct contract defaults."""
        resp = SessionCreateResponse(
            session_id="session_001",
            principal_id="user_001",
            agent_id="agent_001",
        )
        assert resp.trajectory_score == 0.0
        assert resp.risk_band == RiskBand.LOW
        assert resp.model_dump() == {
            "session_id": "session_001",
            "principal_id": "user_001",
            "agent_id": "agent_001",
            "trajectory_score": 0.0,
            "risk_band": "LOW",
        }


class TestActionProposalSchemas:
    """Tests for ActionProposalRequest and ActionProposal domain model."""

    def test_action_proposal_request_valid(self):
        """Valid action proposal request matches contract §3.2."""
        data = {
            "principal_id": "user_001",
            "session_id": "session_001",
            "agent_id": "agent_001",
            "action": "read_customer",
            "resource": "db_records:customer_table",
            "parameters": {},
        }
        req = ActionProposalRequest(**data)
        assert req.principal_id == "user_001"
        assert req.session_id == "session_001"
        assert req.agent_id == "agent_001"
        assert req.action == "read_customer"
        assert req.resource == "db_records:customer_table"
        assert req.parameters == {}

    def test_action_proposal_request_parameters_defaults_to_empty_dict(self):
        """Parameters field defaults to empty dict when omitted."""
        data = {
            "principal_id": "user_001",
            "session_id": "session_001",
            "agent_id": "agent_001",
            "action": "read_logs",
            "resource": "logs",
        }
        req = ActionProposalRequest(**data)
        assert req.parameters == {}

    def test_action_proposal_request_missing_required_fields(self):
        """Missing any of the 5 required fields must fail validation."""
        valid_data = {
            "principal_id": "user_001",
            "session_id": "session_001",
            "agent_id": "agent_001",
            "action": "read_customer",
            "resource": "db_records:customer_table",
        }
        for field_to_drop in ["principal_id", "session_id", "agent_id", "action", "resource"]:
            data = {k: v for k, v in valid_data.items() if k != field_to_drop}
            with pytest.raises(ValidationError):
                ActionProposalRequest(**data)

    def test_action_proposal_has_no_decision_field(self):
        """ActionProposalRequest must not accept a decision field (security boundary)."""
        # Extra fields are ignored by default in Pydantic v2 unless forbidden,
        # but the model definition must NOT have a decision attribute
        req = ActionProposalRequest(
            principal_id="user_001",
            session_id="session_001",
            agent_id="agent_001",
            action="read_customer",
            resource="db_records:customer_table",
        )
        assert not hasattr(req, "decision")

    def test_action_proposal_domain_model(self):
        """ActionProposal domain model mirrors the request structure."""
        proposal = ActionProposal(
            principal_id="user_001",
            session_id="session_001",
            agent_id="agent_001",
            action="read_customer",
            resource="db_records:customer_table",
        )
        assert proposal.parameters == {}


class TestActionDecisionSchemas:
    """Tests for ActionDecisionResponse and ActionDecision domain model."""

    def test_action_decision_response_allow(self):
        """ActionDecisionResponse for ALLOW matches contract §3.2."""
        data = {
            "action_id": "action_001",
            "decision": "ALLOW",
            "trajectory_score": 0.22,
            "risk_band": "LOW",
            "reversibility": "READ",
            "reason": "Authorized read within permitted scope",
        }
        resp = ActionDecisionResponse(**data)
        assert resp.decision == Decision.ALLOW
        assert resp.risk_band == RiskBand.LOW
        assert resp.reversibility == ActionClass.READ
        assert resp.model_dump() == data

    def test_action_decision_response_confirm(self):
        """ActionDecisionResponse for CONFIRM matches contract §3.2."""
        data = {
            "action_id": "action_002",
            "decision": "CONFIRM",
            "trajectory_score": 0.42,
            "risk_band": "MEDIUM",
            "reversibility": "DESTRUCTIVE",
            "reason": "Destructive action requires human confirmation",
        }
        resp = ActionDecisionResponse(**data)
        assert resp.decision == Decision.CONFIRM
        assert resp.model_dump() == data

    def test_action_decision_response_hard_confirm(self):
        """ActionDecisionResponse for HARD_CONFIRM matches contract."""
        data = {
            "action_id": "action_002b",
            "decision": "HARD_CONFIRM",
            "trajectory_score": 0.57,
            "risk_band": "MEDIUM",
            "reversibility": "DESTRUCTIVE",
            "reason": "Medium risk destructive action requires hard confirmation",
        }
        resp = ActionDecisionResponse(**data)
        assert resp.decision == Decision.HARD_CONFIRM
        assert resp.model_dump() == data

    def test_action_decision_response_block(self):
        """ActionDecisionResponse for BLOCK matches contract §3.2."""
        data = {
            "action_id": "action_003",
            "decision": "BLOCK",
            "trajectory_score": 0.71,
            "risk_band": "HIGH",
            "reversibility": "DESTRUCTIVE",
            "reason": "Behavioral trajectory exceeds the high-risk threshold",
        }
        resp = ActionDecisionResponse(**data)
        assert resp.decision == Decision.BLOCK
        assert resp.model_dump() == data

    def test_action_decision_invalid_decision_rejected(self):
        """Invalid decision string must fail Pydantic validation."""
        with pytest.raises(ValidationError):
            ActionDecisionResponse(
                action_id="action_001",
                decision="APPROVE",  # invalid
                trajectory_score=0.22,
                risk_band=RiskBand.LOW,
                reversibility=ActionClass.READ,
                reason="test",
            )

    def test_action_decision_invalid_risk_band_rejected(self):
        """Invalid risk band string must fail Pydantic validation."""
        with pytest.raises(ValidationError):
            ActionDecisionResponse(
                action_id="action_001",
                decision=Decision.ALLOW,
                trajectory_score=0.22,
                risk_band="CRITICAL",  # invalid
                reversibility=ActionClass.READ,
                reason="test",
            )

    def test_action_decision_invalid_reversibility_rejected(self):
        """Invalid reversibility string must fail Pydantic validation."""
        with pytest.raises(ValidationError):
            ActionDecisionResponse(
                action_id="action_001",
                decision=Decision.ALLOW,
                trajectory_score=0.22,
                risk_band=RiskBand.LOW,
                reversibility="EXECUTE",  # invalid
                reason="test",
            )


class TestConfirmationSchemas:
    """Tests for ConfirmationRequest and ConfirmationResponse."""

    def test_confirmation_request_valid(self):
        """ConfirmationRequest matches contract §4."""
        req = ConfirmationRequest(approved_by="admin_001")
        assert req.approved_by == "admin_001"
        assert req.model_dump() == {"approved_by": "admin_001"}

    def test_confirmation_request_missing_approved_by(self):
        """ConfirmationRequest without approved_by must fail validation."""
        with pytest.raises(ValidationError):
            ConfirmationRequest()

    def test_confirmation_response_approved(self):
        """ConfirmationResponse for approved action matches contract §4."""
        data = {
            "action_id": "action_002",
            "decision": "ALLOW",
            "approved_by": "admin_001",
            "execution_status": "EXECUTED",
        }
        resp = ConfirmationResponse(**data)
        assert resp.decision == Decision.ALLOW
        assert resp.execution_status == "EXECUTED"
        assert resp.model_dump() == data

    def test_confirmation_response_denied(self):
        """ConfirmationResponse for denied action matches contract §4."""
        data = {
            "action_id": "action_002",
            "decision": "BLOCK",
            "approved_by": "admin_001",
            "execution_status": "NOT_EXECUTED",
        }
        resp = ConfirmationResponse(**data)
        assert resp.decision == Decision.BLOCK
        assert resp.execution_status == "NOT_EXECUTED"
        assert resp.model_dump() == data


class TestTrajectorySchemas:
    """Tests for TrajectoryResponse and TrajectoryEventSchema."""

    def test_trajectory_response_matches_contract(self):
        """TrajectoryResponse matches contract §5."""
        data = {
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
                    "decision": "ALLOW",
                },
                {
                    "step": 2,
                    "action": "read_customer",
                    "resource": "db_records:customer_table",
                    "reversibility": "READ",
                    "trajectory_score": 0.37,
                    "risk_band": "MEDIUM",
                    "decision": "ALLOW",
                },
            ],
        }
        resp = TrajectoryResponse(**data)
        assert resp.session_id == "session_001"
        assert len(resp.events) == 2
        assert resp.events[0].step == 1
        assert resp.events[0].decision == Decision.ALLOW
        assert resp.events[1].step == 2
        assert resp.events[1].risk_band == RiskBand.MEDIUM
        assert resp.model_dump() == data

    def test_trajectory_response_empty_events(self):
        """TrajectoryResponse defaults to empty events list."""
        resp = TrajectoryResponse(
            session_id="session_001",
            principal_id="user_001",
            trajectory_score=0.0,
            risk_band=RiskBand.LOW,
        )
        assert resp.events == []


class TestAuditSchemas:
    """Tests for AuditResponse and AuditEventSchema."""

    def test_audit_event_schema_matches_contract(self):
        """AuditEventSchema matches contract §6, §7."""
        now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
        event = AuditEventSchema(
            action_id="action_001",
            principal_id="user_001",
            session_id="session_001",
            agent_id="agent_001",
            action="read_customer",
            resource="db_records:customer_table",
            reversibility=ActionClass.READ,
            trajectory_score=0.22,
            risk_band=RiskBand.LOW,
            decision=Decision.ALLOW,
            reason="Authorized read within permitted scope",
            timestamp=now,
        )
        assert event.action_id == "action_001"
        assert event.decision == Decision.ALLOW
        assert event.timestamp == now

    def test_audit_response_matches_contract(self):
        """AuditResponse matches contract §6."""
        now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
        data = {
            "session_id": "session_001",
            "events": [
                {
                    "action_id": "action_001",
                    "principal_id": "user_001",
                    "session_id": "session_001",
                    "agent_id": "agent_001",
                    "action": "read_customer",
                    "resource": "db_records:customer_table",
                    "reversibility": "READ",
                    "trajectory_score": 0.22,
                    "risk_band": "LOW",
                    "decision": "ALLOW",
                    "reason": "Authorized read within permitted scope",
                    "timestamp": now.isoformat(),
                }
            ],
        }
        resp = AuditResponse(**data)
        assert resp.session_id == "session_001"
        assert len(resp.events) == 1
        assert resp.events[0].action == "read_customer"
