"""Tests for the Tripwire Authorization Service.

Tests cover:
- Authorized cases (single, multiple scopes, contract §12 examples)
- Scope parsing (JSON, comma-separated, single token, empty)
- Unauthorized cases (scope mismatch, unknown principal, empty scope)
- Context validation (missing fields, session mismatch)
- Security / Fail-Closed behavior (database errors, exceptions)
- Invariant: Agent cannot modify its own scope
"""

import json
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository
from app.security.authorization import (
    AuthorizationContext,
    AuthorizationResult,
    AuthorizationService,
)


@pytest.fixture
def auth_service(db_session):
    """Create AuthorizationService instance with test database session."""
    return AuthorizationService(db_session)


@pytest.fixture
def standard_principal(db_session):
    """Create standard principal matching contract §12 example:
    scope: ["customer:read", "customer:write"]
    """
    repo = PrincipalRepository(db_session)
    return repo.create(
        principal_id="user_001",
        role="analyst",
        scope=json.dumps(["customer:read", "customer:write"]),
    )


@pytest.fixture
def active_session(db_session, standard_principal):
    """Create an active session for the standard principal."""
    repo = SessionRepository(db_session)
    return repo.create(
        session_id="session_001",
        principal_id=standard_principal.id,
        agent_id="agent_001",
    )


class TestScopeParsing:
    """Tests for scope parsing and normalization."""

    def test_parse_json_array(self, auth_service):
        """JSON array format parses correctly."""
        raw = '["customer:read", "customer:write", "logs"]'
        parsed = auth_service.parse_scope(raw)
        assert parsed == ["customer:read", "customer:write", "logs"]

    def test_parse_comma_separated(self, auth_service):
        """Comma-separated string parses correctly."""
        raw = "customer:read, customer:write, logs"
        parsed = auth_service.parse_scope(raw)
        assert parsed == ["customer:read", "customer:write", "logs"]

    def test_parse_single_token(self, auth_service):
        """Single scope token parses correctly."""
        raw = "customer:read"
        parsed = auth_service.parse_scope(raw)
        assert parsed == ["customer:read"]

    def test_parse_empty_or_none(self, auth_service):
        """Empty string or None returns empty list."""
        assert auth_service.parse_scope("") == []
        assert auth_service.parse_scope(None) == []
        assert auth_service.parse_scope("   ") == []

    def test_parse_malformed_json_falls_back_to_comma_split(self, auth_service):
        """Malformed JSON array falls back gracefully without crashing."""
        raw = '["broken_json, customer:read'
        parsed = auth_service.parse_scope(raw)
        assert len(parsed) > 0


class TestAuthorizedCases:
    """Tests for authorized action proposals (Contract §12)."""

    def test_contract_example_read_customer_allowed(self, auth_service, standard_principal, active_session):
        """Contract §12: user_001 with customer:read -> read_customer is authorized."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="read_customer",
            resource="db_records:customer_table",
        )
        assert result.authorized is True
        assert "authorized" in result.reason.lower()

    def test_contract_example_update_customer_allowed(self, auth_service, standard_principal, active_session):
        """Contract §12: user_001 with customer:write -> update_customer is authorized."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="update_customer",
            resource="db_records:customer_table",
        )
        assert result.authorized is True

    def test_search_customers_allowed_with_customer_read(self, auth_service, standard_principal, active_session):
        """search_customers authorized under customer:read."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="search_customers",
            resource="db_records:customer_table",
        )
        assert result.authorized is True

    def test_export_customers_allowed_with_customer_write(self, auth_service, standard_principal, active_session):
        """export_customers authorized under customer:write."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="export_customers",
            resource="db_records:customer_table",
        )
        assert result.authorized is True

    def test_exact_resource_match_authorizes(self, auth_service, db_session):
        """Principal with exact resource string in scope is authorized."""
        repo = PrincipalRepository(db_session)
        p = repo.create("user_exact", scope="db_records:orders_table")
        context = AuthorizationContext("user_exact", "session_any", "agent_001")

        result = auth_service.authorize(
            context=context,
            action="read_orders",
            resource="db_records:orders_table",
        )
        assert result.authorized is True


class TestUnauthorizedCases:
    """Tests for unauthorized action proposals (Contract §12)."""

    def test_contract_example_drop_table_denied(self, auth_service, standard_principal, active_session):
        """Contract §12: user_001 with customer:* -> drop_table is denied."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="drop_table",
            resource="db_schema:core",
        )
        assert result.authorized is False
        assert "not permitted" in result.reason.lower()

    def test_change_permissions_denied_without_permissions_scope(self, auth_service, standard_principal, active_session):
        """change_permissions denied when principal lacks permissions scope."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="change_permissions",
            resource="system:permissions",
        )
        assert result.authorized is False

    def test_unknown_principal_unauthorized(self, auth_service):
        """Unknown principal must fail closed (authorized=False)."""
        context = AuthorizationContext(
            principal_id="nonexistent_user",
            session_id="session_001",
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="read_customer",
            resource="db_records:customer_table",
        )
        assert result.authorized is False
        assert "not found" in result.reason.lower()

    def test_empty_scope_unauthorized(self, auth_service, db_session):
        """Principal with empty or None scope is unauthorized for everything."""
        repo = PrincipalRepository(db_session)
        p = repo.create("user_no_scope", scope=None)
        context = AuthorizationContext("user_no_scope", "session_any", "agent_001")

        result = auth_service.authorize(
            context=context,
            action="read_logs",
            resource="logs",
        )
        assert result.authorized is False
        assert "no authorized scope" in result.reason.lower()

    def test_resource_outside_scope_unauthorized(self, auth_service, standard_principal, active_session):
        """Targeting a resource completely unrelated to scope is unauthorized."""
        context = AuthorizationContext(
            principal_id=standard_principal.id,
            session_id=active_session.id,
            agent_id="agent_001",
        )
        result = auth_service.authorize(
            context=context,
            action="read_finance",
            resource="finance:quarterly_ledger",
        )
        assert result.authorized is False


class TestContextValidationAndFailClosed:
    """Tests for fail-closed behavior on missing or invalid context."""

    def test_missing_principal_id_fails_closed(self, auth_service):
        """Empty principal_id fails closed."""
        context = AuthorizationContext("", "session_001", "agent_001")
        result = auth_service.authorize(context, "read_logs", "logs")
        assert result.authorized is False

    def test_missing_action_fails_closed(self, auth_service, standard_principal):
        """Empty action fails closed."""
        context = AuthorizationContext(standard_principal.id, "session_001", "agent_001")
        result = auth_service.authorize(context, "", "db_records:customer_table")
        assert result.authorized is False

    def test_missing_resource_fails_closed(self, auth_service, standard_principal):
        """Empty resource fails closed."""
        context = AuthorizationContext(standard_principal.id, "session_001", "agent_001")
        result = auth_service.authorize(context, "read_customer", "")
        assert result.authorized is False

    def test_session_principal_mismatch_fails_closed(self, auth_service, db_session):
        """Session belonging to another principal must fail closed."""
        p_repo = PrincipalRepository(db_session)
        s_repo = SessionRepository(db_session)

        # Principal A owns Session A
        p_a = p_repo.create("user_A", scope="customer:read")
        s_a = s_repo.create("session_A", "user_A", "agent_001")

        # Principal B tries to use Session A
        p_b = p_repo.create("user_B", scope="customer:read")
        context = AuthorizationContext(
            principal_id="user_B",
            session_id="session_A",  # belongs to user_A!
            agent_id="agent_001",
        )

        result = auth_service.authorize(context, "read_customer", "db_records:customer_table")
        assert result.authorized is False
        assert "does not belong" in result.reason.lower()


class TestDatabaseFailureFailClosed:
    """Tests verifying database failures ALWAYS result in authorized=False."""

    def test_repository_exception_fails_closed(self):
        """If the database throws an exception, authorization MUST return authorized=False."""
        mock_db = MagicMock(spec=Session)
        # Configure mock to raise an operational error
        mock_db.query.side_effect = Exception("Database connection lost")

        service = AuthorizationService(mock_db)
        context = AuthorizationContext("user_001", "session_001", "agent_001")

        result = service.authorize(context, "read_customer", "db_records:customer_table")

        assert result.authorized is False, "Database failure MUST fail closed"
        assert "fail-closed" in result.reason.lower()

    def test_never_returns_none(self, auth_service):
        """Authorization result is always a valid AuthorizationResult instance."""
        context = AuthorizationContext("invalid", "invalid", "invalid")
        result = auth_service.authorize(context, "invalid", "invalid")
        assert isinstance(result, AuthorizationResult)
        assert isinstance(result.authorized, bool)
        assert isinstance(result.reason, str)


class TestNoPrivilegeEscalation:
    """Security tests: agent cannot modify scope or bypass authorization."""

    def test_cannot_access_other_principal_resources(self, auth_service, db_session):
        """User A cannot access User B's permitted resources."""
        repo = PrincipalRepository(db_session)
        p_a = repo.create("user_restricted", scope="logs:read")
        p_b = repo.create("user_privileged", scope="customer:read, customer:write")

        context_a = AuthorizationContext("user_restricted", "session_a", "agent_001")

        # user_restricted tries to access customer_table
        result = auth_service.authorize(context_a, "read_customer", "db_records:customer_table")
        assert result.authorized is False

    def test_role_does_not_grant_implicit_access(self, auth_service, db_session):
        """Role named 'admin' without explicit scope does NOT bypass authorization."""
        repo = PrincipalRepository(db_session)
        # Create an 'admin' with empty scope — should still fail closed
        admin = repo.create("admin_no_scope", role="admin", scope=None)
        context = AuthorizationContext("admin_no_scope", "session_admin", "agent_001")

        result = auth_service.authorize(context, "drop_table", "db_schema:core")
        assert result.authorized is False, "Role 'admin' must not bypass scope check"
