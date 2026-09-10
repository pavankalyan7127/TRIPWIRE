"""Tripwire Tool Registry and Action Classification Layer.

Provides authoritative, server-side metadata for protected tools and actions.
Security classifications (action class, reversibility, required scope, resource)
are determined solely by this trusted registry and cannot be influenced by agent proposals.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §10, §11
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.enums import ActionClass
from app.security.mock_tools import (
    mock_change_permissions,
    mock_drop_table,
    mock_export_customers,
    mock_read_customer,
    mock_read_logs,
    mock_search_customers,
    mock_update_customer,
)

# Destructiveness numeric weights used for trajectory calculations
DESTRUCTIVENESS_LEVELS: dict[ActionClass, float] = {
    ActionClass.READ: 0.0,
    ActionClass.WRITE: 0.5,
    ActionClass.DESTRUCTIVE: 1.0,
}


@dataclass(frozen=True)
class ToolDefinition:
    """Authoritative metadata for a protected tool.

    Immutable domain object representing trusted tool metadata.

    Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §11
    """
    name: str
    resource: str
    action_class: ActionClass
    required_scope: str
    reversibility: ActionClass = field(default=None)  # type: ignore[assignment]
    description: Optional[str] = None
    handler: Optional[Callable[..., Any]] = None

    def __post_init__(self) -> None:
        # Validate non-empty tool name
        if not self.name or not self.name.strip():
            raise ValueError("Tool name must be a non-empty string.")

        # Validate non-empty resource
        if not self.resource or not self.resource.strip():
            raise ValueError(f"Tool '{self.name}' must have a non-empty resource.")

        # Validate action_class is a valid ActionClass enum
        if not isinstance(self.action_class, ActionClass):
            raise ValueError(
                f"Tool '{self.name}' has invalid action_class '{self.action_class}'. "
                f"Must be an instance of ActionClass."
            )

        # Default reversibility to action_class if not explicitly provided
        if self.reversibility is None:
            object.__setattr__(self, "reversibility", self.action_class)
        elif not isinstance(self.reversibility, ActionClass):
            raise ValueError(
                f"Tool '{self.name}' has invalid reversibility '{self.reversibility}'. "
                f"Must be an instance of ActionClass."
            )

        # Validate non-empty required_scope
        if not self.required_scope or not self.required_scope.strip():
            raise ValueError(f"Tool '{self.name}' must have a non-empty required_scope.")

    @property
    def destructiveness_level(self) -> float:
        """Destructiveness level used for trajectory growth calculations."""
        return DESTRUCTIVENESS_LEVELS.get(self.action_class, 0.0)


# Authoritative contract-defined protected tools (Contract §11) with trusted mock handlers bound
CONTRACT_TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="read_logs",
        resource="logs",
        action_class=ActionClass.READ,
        reversibility=ActionClass.READ,
        required_scope="logs:read",
        description="Read system application logs",
        handler=mock_read_logs,
    ),
    ToolDefinition(
        name="search_customers",
        resource="db_records:customer_table",
        action_class=ActionClass.READ,
        reversibility=ActionClass.READ,
        required_scope="customer:read",
        description="Search customer database records",
        handler=mock_search_customers,
    ),
    ToolDefinition(
        name="read_customer",
        resource="db_records:customer_table",
        action_class=ActionClass.READ,
        reversibility=ActionClass.READ,
        required_scope="customer:read",
        description="Read specific customer database record",
        handler=mock_read_customer,
    ),
    ToolDefinition(
        name="export_customers",
        resource="db_records:customer_table",
        action_class=ActionClass.WRITE,
        reversibility=ActionClass.WRITE,
        required_scope="customer:write",
        description="Export customer database records to external file",
        handler=mock_export_customers,
    ),
    ToolDefinition(
        name="update_customer",
        resource="db_records:customer_table",
        action_class=ActionClass.WRITE,
        reversibility=ActionClass.WRITE,
        required_scope="customer:write",
        description="Update customer database record",
        handler=mock_update_customer,
    ),
    ToolDefinition(
        name="change_permissions",
        resource="system:permissions",
        action_class=ActionClass.DESTRUCTIVE,
        reversibility=ActionClass.DESTRUCTIVE,
        required_scope="permissions:write",
        description="Modify system access control permissions",
        handler=mock_change_permissions,
    ),
    ToolDefinition(
        name="drop_table",
        resource="db_schema:core",
        action_class=ActionClass.DESTRUCTIVE,
        reversibility=ActionClass.DESTRUCTIVE,
        required_scope="schema:admin",
        description="Drop database core schema tables",
        handler=mock_drop_table,
    ),
)


class ToolRegistry:
    """Authoritative registry for protected tools and action classifications.

    Tripwire consults this registry to determine the classification,
    reversibility, required scope, resource, and handler of proposed actions.

    The registry is deterministic, immutable after initialization,
    and fails closed on unknown tools.
    """

    def __init__(self, tools: Optional[list[ToolDefinition] | tuple[ToolDefinition, ...]] = None):
        """Initialize the tool registry.

        Args:
            tools: Optional custom list of tool definitions.
                   Defaults to the authoritative CONTRACT_TOOLS.
        """
        self._tools: dict[str, ToolDefinition] = {}

        tool_list = tools if tools is not None else CONTRACT_TOOLS
        for tool in tool_list:
            self._register(tool)

    def _register(self, tool: ToolDefinition) -> None:
        """Register a tool definition into the registry.

        Validates that tool names are unique and not duplicated.
        """
        if tool.name in self._tools:
            raise ValueError(f"Duplicate tool registration: '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Look up a tool definition by name.

        Returns None if tool is unknown (fail-closed).
        """
        if not name or not isinstance(name, str):
            return None
        return self._tools.get(name.strip())

    def get_or_raise(self, name: str) -> ToolDefinition:
        """Look up a tool definition by name, raising KeyError if not found.

        Args:
            name: Tool name to look up.

        Returns:
            Authoritative ToolDefinition.

        Raises:
            KeyError: If the tool is not registered.
        """
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' is not registered in Tripwire tool registry.")
        return tool

    def is_registered(self, name: str) -> bool:
        """Check if a tool is registered."""
        return self.get(name) is not None

    def classify_action(self, name: str) -> Optional[ActionClass]:
        """Get the authoritative ActionClass for a tool name.

        Returns None for unknown tools (fail-closed).
        """
        tool = self.get(name)
        return tool.action_class if tool else None

    def get_reversibility(self, name: str) -> Optional[ActionClass]:
        """Get the authoritative reversibility classification for a tool name.

        Returns None for unknown tools (fail-closed).
        """
        tool = self.get(name)
        return tool.reversibility if tool else None

    def get_required_scope(self, name: str) -> Optional[str]:
        """Get the authoritative required authorization scope for a tool name.

        Returns None for unknown tools (fail-closed).
        """
        tool = self.get(name)
        return tool.required_scope if tool else None

    def get_resource(self, name: str) -> Optional[str]:
        """Get the authoritative resource target for a tool name.

        Returns None for unknown tools (fail-closed).
        """
        tool = self.get(name)
        return tool.resource if tool else None

    def get_handler(self, name: str) -> Optional[Callable[..., Any]]:
        """Get the authoritative executable handler for a tool name.

        Returns None if tool is unknown or handler is unset.
        """
        tool = self.get(name)
        return tool.handler if tool else None

    def list_tools(self) -> list[ToolDefinition]:
        """List all registered tool definitions."""
        return list(self._tools.values())

    def list_tool_names(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def __len__(self) -> int:
        """Number of registered tools."""
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        """Check if a tool name is registered using `in` operator."""
        return self.is_registered(name)


# Authoritative default registry instance
default_tool_registry = ToolRegistry()
