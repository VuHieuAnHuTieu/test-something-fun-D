"""Database adapter interface abstraction for multi-database adaptation.

Defines the DatabaseAdapter base class. Decouples runtime tooling from engine-specific
implementation details while enforcing read-only guarantees for business analytics.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from database.database_context import ActiveDatabaseContext


class DatabaseAdapter(ABC):
    """Abstract interface for database engine adapters.

    All business database adapters must be strictly read-only during analytics.
    """

    dialect: str = "mysql"

    @abstractmethod
    def test_connection(self, context: ActiveDatabaseContext) -> bool:
        """Verify connectivity and read access to the context's target database."""
        pass

    @abstractmethod
    def inspect_schema(self, context: ActiveDatabaseContext) -> dict[str, Any]:
        """Inspect visible schema objects, columns, and constraints for the target database."""
        pass

    @abstractmethod
    def execute_read_query(
        self,
        sql: str,
        context: ActiveDatabaseContext,
    ) -> Any:
        """Execute a validated read-only SQL query against the target database."""
        pass
