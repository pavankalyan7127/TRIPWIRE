"""Tripwire Authorization Service.

Evaluates whether a principal has the required scope to propose an action.
Does NOT compute decisions (ALLOW/CONFIRM/BLOCK) or trajectory risk.
Fails closed on any ambiguity, missing context, or repository error.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §12
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.orm import Session

from app.db.repositories.principal import PrincipalRepository
from app.db.repositories.session import SessionRepository


@dataclass(frozen=True)
class AuthorizationContext:
    """Trusted identity and request context for authorization.

    Contract: §25 Authorization Context Propagation
    """
    principal_id: str
    session_id: str
    agent_id: str


@dataclass(frozen=True)
class AuthorizationResult:
    """Explicit result of an authorization evaluation.

    Contains only authorization determination, NOT final decision enums.
    """
    authorized: bool
    reason: str


class AuthorizationService:
    """Evaluates whether an action proposal is authorized for a principal.

    Authorization is based on:
        principal + scope + action + resource

    Rules:
    1. The principal must exist in the database.
    2. If a session_id is provided, the session must exist and belong to the principal.
    3. The principal must have a defined scope.
    4. The requested action/resource must be covered by the principal's scope.
    5. Any failure, missing context, or DB error results in authorized=False (fail-closed).
    """

    def __init__(self, db: Session):
        """Initialize with a database session.

        Args:
            db: SQLAlchemy session for repository access.
        """
        self.db = db
        self.principal_repo = PrincipalRepository(db)
        self.session_repo = SessionRepository(db)

    def parse_scope(self, scope_str: Optional[str]) -> list[str]:
        """Parse and normalize the principal's scope string into a list of scope tokens.

        Supports:
        - JSON array: '["customer:read", "customer:write"]' -> ["customer:read", "customer:write"]
        - Comma-separated: "customer:read, customer:write" -> ["customer:read", "customer:write"]
        - Single token / exact resource: "customer:read" -> ["customer:read"]
        - None / empty string -> []

        Args:
            scope_str: Raw scope string from database.

        Returns:
            List of normalized (trimmed) scope strings.
        """
        if not scope_str or not scope_str.strip():
            return []

        cleaned = scope_str.strip()

        # Try JSON array first
        if cleaned.startswith("[") and cleaned.endswith("]"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except (json.JSONDecodeError, TypeError):
                pass

        # Fallback to comma-separated
        return [part.strip() for part in cleaned.split(",") if part.strip()]

    def is_action_in_scope(
        self,
        action: str,
        resource: str,
        scope_tokens: list[str],
    ) -> bool:
        """Check if the requested action and resource are authorized by the scope tokens.

        Matching rules:
        1. Exact resource match: token == resource (e.g. "db_records:customer_table")
        2. Exact action match: token == action (e.g. "read_customer")
        3. Action:resource or permission token matching:
           - "customer:read" matches read_customer on customer resources
           - "customer:write" matches update_customer / export_customers on customer resources
           - "logs:read" matches read_logs on logs
           - "permissions:write" matches change_permissions
           - "schema:admin" / "schema:write" matches drop_table

        Exact token matches always take precedence.

        Args:
            action: Proposed tool/action name (e.g. "read_customer").
            resource: Target resource (e.g. "db_records:customer_table").
            scope_tokens: Normalized scope list from principal.

        Returns:
            True if authorized, False otherwise.
        """
        if not scope_tokens:
            return False

        # Direct exact match on resource or action name
        if resource in scope_tokens or action in scope_tokens:
            return True

        # Semantic scope matching for standard contract scopes
        for token in scope_tokens:
            if self._matches_semantic_scope(action, resource, token):
                return True

        return False

    def _matches_semantic_scope(self, action: str, resource: str, token: str) -> bool:
        """Evaluate semantic scope token against action and resource.

        Contract §12 example:
            scope: ["customer:read", "customer:write"]
            read_customer -> allowed
            update_customer -> allowed
            drop_table -> denied

        Args:
            action: Action name.
            resource: Resource name.
            token: Scope token.

        Returns:
            True if token authorizes the action/resource pair.
        """
        token = token.lower()
        action = action.lower()
        resource = resource.lower()

        # Exact match
        if token == action or token == resource:
            return True

        # Customer domain scopes
        if token == "customer:read":
            if "customer" in action and ("read" in action or "search" in action or "get" in action):
                return True
            if "customer" in resource and ("read" in action or "search" in action):
                return True

        elif token == "customer:write":
            if "customer" in action and ("write" in action or "update" in action or "export" in action or "create" in action):
                return True
            if "customer" in resource and ("update" in action or "export" in action or "write" in action):
                return True

        # Logs domain scopes
        elif token == "logs:read" or token == "logs":
            if "log" in action or "log" in resource:
                return True

        # Schema domain scopes
        elif token == "schema:read":
            if "schema" in resource and "read" in action:
                return True
        elif token == "schema:admin" or token == "schema:write":
            if "schema" in resource or "table" in action or "drop" in action:
                return True

        # Permissions domain scopes
        elif token == "permissions:write" or token == "permissions:admin":
            if "permission" in action or "permission" in resource:
                return True

        return False

    def authorize(
        self,
        context: AuthorizationContext,
        action: str,
        resource: str,
    ) -> AuthorizationResult:
        """Authorize an action proposal against the principal's persisted scope.

        Fails closed on any error, missing data, or scope mismatch.

        Args:
            context: Trusted identity context (principal_id, session_id, agent_id).
            action: Proposed tool/action name.
            resource: Target resource.

        Returns:
            AuthorizationResult with authorized=True/False and reason.
        """
        # Validate required inputs
        if not context.principal_id or not context.principal_id.strip():
            return AuthorizationResult(
                authorized=False,
                reason="Missing or empty principal_id in authorization context.",
            )

        if not action or not action.strip():
            return AuthorizationResult(
                authorized=False,
                reason="Missing or empty action name.",
            )

        if not resource or not resource.strip():
            return AuthorizationResult(
                authorized=False,
                reason="Missing or empty resource target.",
            )

        try:
            # 1. Lookup principal
            principal = self.principal_repo.get_by_id(context.principal_id)
            if principal is None:
                return AuthorizationResult(
                    authorized=False,
                    reason=f"Principal '{context.principal_id}' not found.",
                )

            # 2. Validate session association if session_id is provided
            if context.session_id and context.session_id.strip():
                session = self.session_repo.get_by_id(context.session_id)
                if session is not None and session.principal_id != context.principal_id:
                    return AuthorizationResult(
                        authorized=False,
                        reason=f"Session '{context.session_id}' does not belong to principal '{context.principal_id}'.",
                    )

            # 3. Parse principal scope
            scope_tokens = self.parse_scope(principal.scope)
            if not scope_tokens:
                return AuthorizationResult(
                    authorized=False,
                    reason=f"Principal '{context.principal_id}' has no authorized scope.",
                )

            # 4. Evaluate scope
            if self.is_action_in_scope(action, resource, scope_tokens):
                return AuthorizationResult(
                    authorized=True,
                    reason=f"Action '{action}' on '{resource}' is authorized by principal scope.",
                )
            else:
                return AuthorizationResult(
                    authorized=False,
                    reason=f"Action '{action}' on '{resource}' is not permitted by principal scope.",
                )

        except Exception as e:
            # Critical fail-closed rule: ANY database or system error must NOT authorize
            return AuthorizationResult(
                authorized=False,
                reason=f"Authorization system error (fail-closed): {str(e)}",
            )
