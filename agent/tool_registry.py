"""
TRIPWIRE — Mock Tool Registry
Person B: Agent / Tools / Frontend Foundation

Deterministic mock tools for evaluating Tripwire runtime security harness.
Enforces that tool execution happens ONLY when authorized and permitted by Tripwire.
"""

from typing import Dict, Any, Callable, Optional
from dataclasses import dataclass


@dataclass
class ToolDefinition:
    name: str
    resource: str
    reversibility: str  # "READ" | "WRITE" | "DESTRUCTIVE"
    required_scope: str
    description: str
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    execution_count: int = 0


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def register(
        self,
        name: str,
        resource: str,
        reversibility: str,
        required_scope: str,
        description: str,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ):
        self._tools[name] = ToolDefinition(
            name=name,
            resource=resource,
            reversibility=reversibility,
            required_scope=required_scope,
            description=description,
            handler=handler,
            execution_count=0,
        )

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: {
                "name": t.name,
                "resource": t.resource,
                "reversibility": t.reversibility,
                "required_scope": t.required_scope,
                "description": t.description,
                "execution_count": t.execution_count,
            }
            for name, t in self._tools.items()
        }

    def execute_tool(self, name: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes the protected tool.
        NOTE: Must ONLY be called if Tripwire harness returns ALLOW or CONFIRM approval.
        """
        if name not in self._tools:
            raise ValueError(f"Unknown tool: {name}")
        
        tool = self._tools[name]
        params = parameters or {}
        
        # Increment execution counter for telemetry / test assertion
        tool.execution_count += 1
        
        # Run handler
        result = tool.handler(params)
        return {
            "status": "SUCCESS",
            "tool": name,
            "resource": tool.resource,
            "reversibility": tool.reversibility,
            "execution_count": tool.execution_count,
            "result": result,
        }

    def reset_execution_counts(self):
        for tool in self._tools.values():
            tool.execution_count = 0

    def _register_default_tools(self):
        # 1. read_logs (READ)
        self.register(
            name="read_logs",
            resource="logs",
            reversibility="READ",
            required_scope="logs:read",
            description="Read system application audit logs",
            handler=lambda params: {
                "logs": [
                    {"timestamp": "2026-09-10T10:00:00Z", "level": "INFO", "msg": "System health nominal"},
                    {"timestamp": "2026-09-10T10:05:00Z", "level": "INFO", "msg": "Database sync completed"},
                ]
            },
        )

        # 2. search_customers (READ)
        self.register(
            name="search_customers",
            resource="db_records:customer_table",
            reversibility="READ",
            required_scope="customer:read",
            description="Search records in customer database",
            handler=lambda params: {
                "matches": [
                    {"id": "cust_101", "name": "Acme Corp", "tier": "Enterprise"},
                    {"id": "cust_102", "name": "GlobalTech", "tier": "Pro"},
                ]
            },
        )

        # 3. read_customer (READ)
        self.register(
            name="read_customer",
            resource="db_records:customer_table",
            reversibility="READ",
            required_scope="customer:read",
            description="Read specific customer details",
            handler=lambda params: {
                "customer": {
                    "id": params.get("id", "cust_101"),
                    "name": "Acme Corp",
                    "balance": 154000.50,
                    "status": "ACTIVE",
                }
            },
        )

        # 4. export_customers (WRITE)
        self.register(
            name="export_customers",
            resource="db_records:customer_table",
            reversibility="WRITE",
            required_scope="customer:write",
            description="Export customer dataset to external dump",
            handler=lambda params: {
                "export_id": "exp_9812",
                "record_count": 24500,
                "destination": params.get("destination", "s3://exports/customers_dump.csv"),
            },
        )

        # 5. update_customer (WRITE)
        self.register(
            name="update_customer",
            resource="db_records:customer_table",
            reversibility="WRITE",
            required_scope="customer:write",
            description="Update customer record attributes",
            handler=lambda params: {
                "updated_id": params.get("id", "cust_101"),
                "status": "UPDATED",
                "fields_modified": list(params.keys()),
            },
        )

        # 6. change_permissions (DESTRUCTIVE)
        self.register(
            name="change_permissions",
            resource="system:permissions",
            reversibility="DESTRUCTIVE",
            required_scope="system:admin",
            description="Modify global role-based access controls and privileges",
            handler=lambda params: {
                "status": "PERMISSIONS_OVERRIDDEN",
                "target_role": params.get("role", "admin"),
                "applied_rules": params.get("rules", ["*"]),
            },
        )

        # 7. drop_table (DESTRUCTIVE)
        self.register(
            name="drop_table",
            resource="db_schema:core",
            reversibility="DESTRUCTIVE",
            required_scope="db:admin",
            description="Drop core relational database table (IRREVERSIBLE)",
            handler=lambda params: {
                "status": "TABLE_DROPPED",
                "table": params.get("table", "customer_table"),
                "affected_rows": 24500,
            },
        )


# Global default instance
default_tool_registry = ToolRegistry()
