"""Concrete MySQL database adapter for the business-analysis path.

Enforces least-privileged read-only access for business data querying and schema inspection.
Secrets and credentials are never exposed, logged, or returned.
"""

from __future__ import annotations

from typing import Any

from config import Settings, get_settings
from database.adapter import DatabaseAdapter
from database.connection import DatabaseConnectionError, get_business_connection
from database.database_context import ActiveDatabaseContext


class MySQLAdapter(DatabaseAdapter):
    """Concrete MySQL implementation of DatabaseAdapter.

    Uses bi_reader credentials for strictly read-only execution and schema inspection.
    """

    dialect: str = "mysql"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def test_connection(self, context: ActiveDatabaseContext) -> bool:
        """Test read connectivity to the active database context.

        Returns True if connection succeeds and a ping/test query executes, False otherwise.
        """
        try:
            with get_business_connection(
                custom_settings=self.settings,
                database_name=context.database_name,
            ) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1;")
                    cursor.fetchall()
            return True
        except (DatabaseConnectionError, Exception):
            return False

    def inspect_schema(self, context: ActiveDatabaseContext) -> dict[str, Any]:
        """Inspect schema metadata for the given active database context.

        Delegates to tools.schema_tool.get_schema_snapshot.
        """
        from tools.schema_tool import get_schema_snapshot
        return get_schema_snapshot(
            custom_settings=self.settings,
            database_context=context,
        )

    def execute_read_query(
        self,
        sql: str,
        context: ActiveDatabaseContext,
    ) -> Any:
        """Execute a validated read-only SQL query against the active database context.

        Delegates to tools.sql_tool.execute_safe_query.
        """
        from tools.sql_tool import execute_safe_query
        return execute_safe_query(
            sql=sql,
            custom_settings=self.settings,
            database_context=context,
        )
