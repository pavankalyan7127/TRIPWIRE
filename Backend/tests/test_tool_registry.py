"""Tests for the Tripwire Tool Registry and Action Classification Layer.

Tests verify:
- Registry completeness (all 7 contract-defined tools)
- Deterministic lookup and fail-closed behavior on unknown tools
- Correct action classifications and destructiveness weights (Contract §8, §10, §11)
- Correct reversibility, resource, and required scope metadata
- Security invariants: immutability, agent tamper-resistance, fail-closed unknown tools
- Validation: static validation catches invalid/duplicate configuration
- Consistency with A4 authorization requirements
"""

from dataclasses import FrozenInstanceError

import pytest

from app.models.enums import ActionClass
from app.models.domain import ActionProposal
from app.schemas.requests import ActionProposalRequest
from app.security.tool_registry import (
    CONTRACT_TOOLS,
    DESTRUCTIVENESS_LEVELS,
    ToolDefinition,
    ToolRegistry,
    default_tool_registry,
)


class TestRegistryCompleteness:
    """Tests verifying all contract-defined tools are present and correct."""

    def test_all_contract_tools_registered(self):
        """All 7 contract-defined tools must be present in default registry (Contract §11)."""
        expected_tools = {
            "read_logs",
            "search_customers",
            "read_customer",
            "export_customers",
            "update_customer",
            "change_permissions",
            "drop_table",
        }
        registered_names = set(default_tool_registry.list_tool_names())
        assert registered_names == expected_tools
        assert len(default_tool_registry) == 7

    def test_no_duplicate_tools_in_contract_list(self):
        """CONTRACT_TOOLS must not contain duplicate tool names."""
        names = [tool.name for tool in CONTRACT_TOOLS]
        assert len(names) == len(set(names)), "Tool names must be unique"


class TestToolLookup:
    """Tests for deterministic tool lookup and fail-closed behavior."""

    @pytest.mark.parametrize(
        "tool_name",
        [
            "read_logs",
            "search_customers",
            "read_customer",
            "export_customers",
            "update_customer",
            "change_permissions",
            "drop_table",
        ],
    )
    def test_known_tool_lookup_succeeds(self, tool_name):
        """Known tools can be retrieved via get() and get_or_raise()."""
        tool = default_tool_registry.get(tool_name)
        assert tool is not None
        assert tool.name == tool_name

        tool_raised = default_tool_registry.get_or_raise(tool_name)
        assert tool_raised == tool
        assert tool_name in default_tool_registry

    def test_unknown_tool_returns_none(self):
        """Unknown tools return None via get() (fail-closed)."""
        assert default_tool_registry.get("nonexistent_tool") is None
        assert default_tool_registry.get("execute_shell") is None
        assert default_tool_registry.get("") is None
        assert default_tool_registry.get(None) is None  # type: ignore[arg-type]

    def test_unknown_tool_raises_key_error(self):
        """get_or_raise() on an unknown tool raises KeyError."""
        with pytest.raises(KeyError, match="not registered"):
            default_tool_registry.get_or_raise("unauthorized_cmd")

    def test_lookup_is_deterministic(self):
        """Repeated lookups for the same tool return identical definition."""
        tool1 = default_tool_registry.get("drop_table")
        tool2 = default_tool_registry.get("drop_table")
        assert tool1 is tool2  # Same instance in memory


class TestActionClassification:
    """Tests for action classification mapping (Contract §10, §11)."""

    def test_read_logs_classification(self):
        """read_logs is classified as READ with 0.0 destructiveness."""
        tool = default_tool_registry.get_or_raise("read_logs")
        assert tool.action_class == ActionClass.READ
        assert tool.reversibility == ActionClass.READ
        assert tool.destructiveness_level == 0.0

    def test_search_customers_classification(self):
        """search_customers is classified as READ with 0.0 destructiveness."""
        tool = default_tool_registry.get_or_raise("search_customers")
        assert tool.action_class == ActionClass.READ
        assert tool.reversibility == ActionClass.READ
        assert tool.destructiveness_level == 0.0

    def test_read_customer_classification(self):
        """read_customer is classified as READ with 0.0 destructiveness."""
        tool = default_tool_registry.get_or_raise("read_customer")
        assert tool.action_class == ActionClass.READ
        assert tool.reversibility == ActionClass.READ
        assert tool.destructiveness_level == 0.0

    def test_export_customers_classification(self):
        """export_customers is classified as WRITE with 0.5 destructiveness."""
        tool = default_tool_registry.get_or_raise("export_customers")
        assert tool.action_class == ActionClass.WRITE
        assert tool.reversibility == ActionClass.WRITE
        assert tool.destructiveness_level == 0.5

    def test_update_customer_classification(self):
        """update_customer is classified as WRITE with 0.5 destructiveness."""
        tool = default_tool_registry.get_or_raise("update_customer")
        assert tool.action_class == ActionClass.WRITE
        assert tool.reversibility == ActionClass.WRITE
        assert tool.destructiveness_level == 0.5

    def test_change_permissions_classification(self):
        """change_permissions is classified as DESTRUCTIVE with 1.0 destructiveness."""
        tool = default_tool_registry.get_or_raise("change_permissions")
        assert tool.action_class == ActionClass.DESTRUCTIVE
        assert tool.reversibility == ActionClass.DESTRUCTIVE
        assert tool.destructiveness_level == 1.0

    def test_drop_table_classification(self):
        """drop_table is classified as DESTRUCTIVE with 1.0 destructiveness."""
        tool = default_tool_registry.get_or_raise("drop_table")
        assert tool.action_class == ActionClass.DESTRUCTIVE
        assert tool.reversibility == ActionClass.DESTRUCTIVE
        assert tool.destructiveness_level == 1.0

    def test_destructiveness_level_weights(self):
        """Destructiveness level values match the agreed weights (CLAUDE.md §10)."""
        assert DESTRUCTIVENESS_LEVELS[ActionClass.READ] == 0.0
        assert DESTRUCTIVENESS_LEVELS[ActionClass.WRITE] == 0.5
        assert DESTRUCTIVENESS_LEVELS[ActionClass.DESTRUCTIVE] == 1.0


class TestMetadataAndResourceConsistency:
    """Tests verifying resources and required scopes match the contract specifications."""

    @pytest.mark.parametrize(
        "tool_name,expected_resource,expected_scope",
        [
            ("read_logs", "logs", "logs:read"),
            ("search_customers", "db_records:customer_table", "customer:read"),
            ("read_customer", "db_records:customer_table", "customer:read"),
            ("export_customers", "db_records:customer_table", "customer:write"),
            ("update_customer", "db_records:customer_table", "customer:write"),
            ("change_permissions", "system:permissions", "permissions:write"),
            ("drop_table", "db_schema:core", "schema:admin"),
        ],
    )
    def test_tool_resource_and_scope_metadata(self, tool_name, expected_resource, expected_scope):
        """Every tool has the exact resource and required_scope defined in Contract §11."""
        tool = default_tool_registry.get_or_raise(tool_name)
        assert tool.resource == expected_resource
        assert tool.required_scope == expected_scope

    def test_helper_lookup_methods(self):
        """Helper classification methods return correct values."""
        assert default_tool_registry.classify_action("drop_table") == ActionClass.DESTRUCTIVE
        assert default_tool_registry.get_reversibility("update_customer") == ActionClass.WRITE
        assert default_tool_registry.get_required_scope("read_customer") == "customer:read"
        assert default_tool_registry.get_resource("read_logs") == "logs"

        # Unknown tool helpers fail closed (return None)
        assert default_tool_registry.classify_action("unknown") is None
        assert default_tool_registry.get_reversibility("unknown") is None
        assert default_tool_registry.get_required_scope("unknown") is None
        assert default_tool_registry.get_resource("unknown") is None


class TestSecurityInvariants:
    """Security tests verifying immutability, tamper-resistance, and fail-closed guarantees."""

    def test_tool_definition_is_immutable(self):
        """ToolDefinition is a frozen dataclass and cannot be modified at runtime."""
        tool = default_tool_registry.get_or_raise("drop_table")
        with pytest.raises(FrozenInstanceError):
            tool.action_class = ActionClass.READ  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            tool.reversibility = ActionClass.READ  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            tool.required_scope = ""  # type: ignore[misc]

    def test_agent_proposal_cannot_override_registry_metadata(self):
        """Agent proposal payload attempting to inject fake classification does not affect registry.

        Contract Invariant: The agent proposes. Tripwire decides.
        Security classification is determined exclusively by the registry.
        """
        # An agent sends a malicious proposal attempting to downgrade drop_table to READ
        proposal_req = ActionProposalRequest(
            principal_id="attacker",
            session_id="session_001",
            agent_id="agent_001",
            action="drop_table",
            resource="db_schema:core",
            parameters={"fake_classification": "READ", "fake_reversibility": "READ"},
        )

        # The security harness looks up metadata strictly from the registry
        authoritative_tool = default_tool_registry.get_or_raise(proposal_req.action)

        # Verify registry metadata remains untouched and authoritative
        assert authoritative_tool.action_class == ActionClass.DESTRUCTIVE
        assert authoritative_tool.reversibility == ActionClass.DESTRUCTIVE
        assert authoritative_tool.required_scope == "schema:admin"
        assert authoritative_tool.destructiveness_level == 1.0

    def test_unknown_tool_does_not_receive_default_permissions(self):
        """Unknown tools fail closed and are never assigned READ or default scope."""
        unknown_name = "malicious_backdoor_tool"
        assert default_tool_registry.get(unknown_name) is None
        assert default_tool_registry.classify_action(unknown_name) is None
        assert default_tool_registry.get_reversibility(unknown_name) is None
        assert default_tool_registry.get_required_scope(unknown_name) is None
        assert default_tool_registry.get_resource(unknown_name) is None


class TestRegistryValidation:
    """Tests verifying static validation catches invalid configuration fast."""

    def test_duplicate_registration_fails(self):
        """Registering two tools with the same name raises ValueError."""
        tool1 = ToolDefinition("tool1", "res1", ActionClass.READ, "scope1")
        tool2 = ToolDefinition("tool1", "res2", ActionClass.WRITE, "scope2")

        with pytest.raises(ValueError, match="Duplicate tool registration"):
            ToolRegistry([tool1, tool2])

    def test_empty_tool_name_fails(self):
        """ToolDefinition with empty name raises ValueError."""
        with pytest.raises(ValueError, match="Tool name must be a non-empty string"):
            ToolDefinition("", "resource", ActionClass.READ, "scope")

    def test_empty_resource_fails(self):
        """ToolDefinition with empty resource raises ValueError."""
        with pytest.raises(ValueError, match="must have a non-empty resource"):
            ToolDefinition("tool_name", "", ActionClass.READ, "scope")

    def test_invalid_action_class_fails(self):
        """ToolDefinition with non-ActionClass action_class raises ValueError."""
        with pytest.raises(ValueError, match="invalid action_class"):
            ToolDefinition("tool_name", "res", "INVALID_CLASS", "scope")  # type: ignore[arg-type]

    def test_invalid_reversibility_fails(self):
        """ToolDefinition with non-ActionClass reversibility raises ValueError."""
        with pytest.raises(ValueError, match="invalid reversibility"):
            ToolDefinition("tool_name", "res", ActionClass.READ, "scope", reversibility="INVALID")  # type: ignore[arg-type]

    def test_empty_required_scope_fails(self):
        """ToolDefinition with empty required_scope raises ValueError."""
        with pytest.raises(ValueError, match="must have a non-empty required_scope"):
            ToolDefinition("tool_name", "resource", ActionClass.READ, "")
