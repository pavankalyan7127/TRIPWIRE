"""Deterministic mock protected tools for Tripwire runtime security harness.

These mock tools represent protected operations in demonstration and testing environments.
They accept parameters and return deterministic structured results without performing
any real-world destructive actions, shell executions, OS permission modifications, or SQL DROP TABLEs.

Contract: docs/TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md §10, §11
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def mock_read_logs(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for read_logs (READ, logs).

    Returns deterministic mock application log records.
    """
    limit = kwargs.get("limit", 10)
    service = kwargs.get("service", "core-api")
    return {
        "tool": "read_logs",
        "status": "success",
        "service": service,
        "logs": [
            {
                "timestamp": "2026-09-10T10:00:00Z",
                "level": "INFO",
                "service": service,
                "message": "Tripwire security engine initialized successfully.",
            },
            {
                "timestamp": "2026-09-10T10:01:23Z",
                "level": "INFO",
                "service": service,
                "message": "Agent session started for principal user_001.",
            },
            {
                "timestamp": "2026-09-10T10:05:00Z",
                "level": "WARN",
                "service": service,
                "message": "Rate limit threshold reached for worker pool 2.",
            },
        ][:limit] if isinstance(limit, int) else [],
        "count": min(3, limit) if isinstance(limit, int) else 3,
    }


def mock_search_customers(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for search_customers (READ, db_records:customer_table).

    Returns deterministic mock customer query results.
    """
    query = kwargs.get("query", "")
    return {
        "tool": "search_customers",
        "status": "success",
        "query": str(query),
        "customers": [
            {"id": "cust_101", "name": "Acme Industrial", "tier": "Enterprise", "status": "active"},
            {"id": "cust_102", "name": "Beta Technologies", "tier": "Standard", "status": "active"},
            {"id": "cust_103", "name": "Cyberdyne Systems", "tier": "Enterprise", "status": "pending"},
        ],
        "total": 3,
    }


def mock_read_customer(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for read_customer (READ, db_records:customer_table).

    Returns deterministic mock customer detail record.
    """
    customer_id = kwargs.get("customer_id", "cust_101")
    return {
        "tool": "read_customer",
        "status": "success",
        "customer": {
            "id": str(customer_id),
            "name": "Acme Industrial",
            "email": "security@acme.example.com",
            "tier": "Enterprise",
            "credit_limit": 50000.0,
            "created_at": "2025-01-15T08:30:00Z",
        },
    }


def mock_export_customers(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for export_customers (WRITE, db_records:customer_table).

    Simulates customer export without creating real external files or network calls.
    """
    export_format = kwargs.get("format", "csv")
    destination = kwargs.get("destination", "s3://mock-bucket/exports/")
    return {
        "tool": "export_customers",
        "status": "success",
        "format": str(export_format),
        "destination": str(destination),
        "record_count": 150,
        "export_id": "export_mock_20260910_001",
        "message": "Export completed successfully to mock buffer.",
    }


def mock_update_customer(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for update_customer (WRITE, db_records:customer_table).

    Performs safe in-memory simulated record update.
    """
    customer_id = kwargs.get("customer_id", "cust_101")
    updates = kwargs.get("updates", {})
    return {
        "tool": "update_customer",
        "status": "success",
        "customer_id": str(customer_id),
        "updated_fields": list(updates.keys()) if isinstance(updates, dict) else [],
        "message": f"Customer '{customer_id}' updated in mock state.",
    }


def mock_change_permissions(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for change_permissions (DESTRUCTIVE, system:permissions).

    Simulates permission modification in mock memory.
    NEVER modifies real OS permissions, files, or user accounts.
    """
    user = kwargs.get("user", "user_target")
    role = kwargs.get("role", "admin")
    return {
        "tool": "change_permissions",
        "status": "success",
        "user": str(user),
        "role": str(role),
        "message": f"MOCK: Permission change applied to '{user}' -> role '{role}'. No real OS permissions were modified.",
    }


def mock_drop_table(**kwargs: Any) -> dict[str, Any]:
    """Mock handler for drop_table (DESTRUCTIVE, db_schema:core).

    Simulates schema table drop in mock memory.
    ABSOLUTELY NEVER executes real SQL DROP TABLE against any database.
    """
    table_name = kwargs.get("table_name", "core")
    return {
        "tool": "drop_table",
        "status": "mock_executed",
        "table": str(table_name),
        "message": f"MOCK: Table '{table_name}' simulated drop. Real database was NOT modified.",
    }


# Mapping of contract tool names to their mock handlers
MOCK_TOOL_HANDLERS: dict[str, Callable[..., Any]] = {
    "read_logs": mock_read_logs,
    "search_customers": mock_search_customers,
    "read_customer": mock_read_customer,
    "export_customers": mock_export_customers,
    "update_customer": mock_update_customer,
    "change_permissions": mock_change_permissions,
    "drop_table": mock_drop_table,
}


@dataclass
class ToolCallRecord:
    """Record of a tool execution invocation."""
    tool: str
    parameters: dict[str, Any]
    result: Any
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MockToolExecutionRecorder:
    """Thread-safe, test-isolated recorder for verifying tool handler executions.

    Used by unit and integration tests to assert whether a handler was invoked or not.
    """

    def __init__(self) -> None:
        self._records: list[ToolCallRecord] = []

    def record(self, tool: str, parameters: dict[str, Any], result: Any) -> None:
        """Record a tool invocation."""
        self._records.append(
            ToolCallRecord(
                tool=tool,
                parameters=parameters,
                result=result,
            )
        )

    @property
    def call_count(self) -> int:
        """Total number of tool invocations recorded."""
        return len(self._records)

    @property
    def records(self) -> list[ToolCallRecord]:
        """List of all recorded tool invocations."""
        return list(self._records)

    def tool_call_count(self, tool: str) -> int:
        """Number of times a specific tool was invoked."""
        return sum(1 for r in self._records if r.tool == tool)

    def was_called(self, tool: Optional[str] = None) -> bool:
        """Check if any tool or a specific tool was called."""
        if tool is None:
            return len(self._records) > 0
        return self.tool_call_count(tool) > 0

    def clear(self) -> None:
        """Clear all recorded calls."""
        self._records.clear()
