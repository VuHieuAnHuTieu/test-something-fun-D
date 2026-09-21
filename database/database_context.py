"""Active Database Context and schema fingerprinting for dynamic multi-database adaptation.

Defines immutable ActiveDatabaseContext, SourceType, DatabaseStatus, strict
database identifier validation, and deterministic SHA-256 schema fingerprinting.

Security Guarantees:
- ActiveDatabaseContext is an immutable frozen dataclass.
- ZERO passwords, API keys, or raw credential strings are stored, exposed, or serialized.
- MySQL system schemas (mysql, information_schema, performance_schema, sys) and agent_system
  are strictly prohibited from becoming a business database context.
- Database identifiers are strictly validated against injection characters.
- Schema fingerprinting is deterministic, canonical, and computed only from schema metadata
  (zero row data, zero passwords, zero timestamps).
- ActiveDatabaseContext does not perform live database operations itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ==============================================================================
# PROHIBITED SCHEMAS & IDENTIFIER REGEX
# ==============================================================================

PROHIBITED_BUSINESS_SCHEMAS: frozenset[str] = frozenset({
    "mysql",
    "information_schema",
    "performance_schema",
    "sys",
    "agent_system",
})

_IDENTIFIER_REGEX: re.Pattern = re.compile(r"^[a-zA-Z0-9_]+$")


# ==============================================================================
# ENUMS
# ==============================================================================

class SourceType(str, Enum):
    """Supported database source types."""
    EXISTING_MYSQL = "existing_mysql"
    MYSQL_DUMP = "mysql_dump"
    CSV_IMPORT = "csv_import"


class DatabaseStatus(str, Enum):
    """Lifecycle status of a database context."""
    READY = "READY"
    IMPORT_VALIDATING = "IMPORT_VALIDATING"
    IMPORTING = "IMPORTING"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    DATABASE_NOT_FOUND = "DATABASE_NOT_FOUND"
    DATABASE_NOT_ACCESSIBLE = "DATABASE_NOT_ACCESSIBLE"
    IMPORT_PRIVILEGE_REQUIRED = "IMPORT_PRIVILEGE_REQUIRED"


# ==============================================================================
# IDENTIFIER VALIDATION
# ==============================================================================

def validate_database_identifier(database_name: str | None) -> str:
    """Validate that database_name is a clean MySQL identifier and not a prohibited schema.

    Args:
        database_name: Candidate database/schema name.

    Returns:
        The validated database identifier in cleaned format.

    Raises:
        ValueError: If database_name is empty, contains invalid characters, or is prohibited.
    """
    if database_name is None or not str(database_name).strip():
        raise ValueError("Database name cannot be empty or blank.")

    cleaned = str(database_name).strip()

    if not _IDENTIFIER_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid database identifier '{database_name}'. "
            "Must be a plain identifier containing only letters, numbers, and underscores, "
            "with no dots, semicolons, quotes, spaces, or comment characters."
        )

    if cleaned.lower() in PROHIBITED_BUSINESS_SCHEMAS:
        raise ValueError(
            f"Schema '{cleaned}' is a protected system or internal schema "
            "and cannot be used as an active business database context."
        )

    return cleaned


# ==============================================================================
# SCHEMA FINGERPRINTING
# ==============================================================================

def compute_schema_fingerprint(snapshot_or_metadata: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 fingerprint from canonical schema metadata.

    The fingerprint covers:
    - sorted table/view names and their types
    - sorted columns with ordinal position, data type, nullability
    - sorted primary keys
    - sorted foreign key relationships

    Guarantees:
    - Repeated fingerprinting of an unchanged schema produces the exact same hash.
    - Zero row data, zero passwords, zero connection credentials, zero timestamps are included.

    Args:
        snapshot_or_metadata: Dictionary matching the structure of get_schema_snapshot().

    Returns:
        Hexadecimal SHA-256 digest string.
    """
    db_name = str(snapshot_or_metadata.get("database", "")).strip().lower()

    # 1. Canonical objects: list of (object_name, object_type) sorted by name
    raw_objects = snapshot_or_metadata.get("objects", [])
    canonical_objects = sorted([
        (
            str(obj.get("object_name", "")).strip().lower(),
            str(obj.get("object_type", "")).strip().upper(),
        )
        for obj in raw_objects
        if obj.get("object_name")
    ])

    # 2. Canonical columns: list of (table_name, column_name, data_type, is_nullable, column_key) sorted
    raw_columns = snapshot_or_metadata.get("columns", [])
    canonical_columns = sorted([
        (
            str(col.get("table_name", "")).strip().lower(),
            str(col.get("column_name", "")).strip().lower(),
            str(col.get("data_type", "")).strip().lower(),
            str(col.get("is_nullable", "")).strip().upper(),
            str(col.get("column_key", "")).strip().upper(),
        )
        for col in raw_columns
        if col.get("table_name") and col.get("column_name")
    ])

    # 3. Canonical primary keys: list of (table_name, column_name, ordinal_position) sorted
    raw_pks = snapshot_or_metadata.get("primary_keys", [])
    canonical_pks = sorted([
        (
            str(pk.get("table_name", "")).strip().lower(),
            str(pk.get("column_name", "")).strip().lower(),
            int(pk.get("ordinal_position", 0)),
        )
        for pk in raw_pks
        if pk.get("table_name") and pk.get("column_name")
    ])

    # 4. Canonical foreign keys: list of (table, column, ref_table, ref_col) sorted
    raw_fks = snapshot_or_metadata.get("foreign_keys", [])
    canonical_fks = sorted([
        (
            str(fk.get("table_name", "")).strip().lower(),
            str(fk.get("column_name", "")).strip().lower(),
            str(fk.get("referenced_table_name", "")).strip().lower(),
            str(fk.get("referenced_column_name", "")).strip().lower(),
        )
        for fk in raw_fks
        if fk.get("table_name") and fk.get("column_name")
    ])

    canonical_payload: dict[str, Any] = {
        "database": db_name,
        "objects": canonical_objects,
        "columns": canonical_columns,
        "primary_keys": canonical_pks,
        "foreign_keys": canonical_fks,
    }

    raw_approved = snapshot_or_metadata.get("approved_objects")
    if raw_approved:
        canonical_payload["approved_objects"] = sorted([
            str(obj).strip().lower() for obj in raw_approved if str(obj).strip()
        ])

    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ==============================================================================
# ACTIVE DATABASE CONTEXT
# ==============================================================================

@dataclass(frozen=True)
class ActiveDatabaseContext:
    """Immutable representation of an active MySQL database context.

    Contains only SAFE metadata. Never contains passwords, credentials,
    connection secrets, or raw connection strings.
    """

    context_id: str
    display_name: str
    database_name: str
    dialect: str = "mysql"
    source_type: str = SourceType.EXISTING_MYSQL.value
    host: str = "127.0.0.1"
    port: int = 3306
    schema_fingerprint: str = ""
    status: str = DatabaseStatus.READY.value
    metadata: dict[str, Any] = field(default_factory=dict)
    approved_objects: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        # 1. Enforce strict database name validation and prohibited schema exclusion
        validated_db = validate_database_identifier(self.database_name)
        object.__setattr__(self, "database_name", validated_db)

        # 2. Enforce dialect restriction (MySQL only for Step 20)
        if self.dialect.lower() != "mysql":
            raise ValueError(f"Unsupported dialect '{self.dialect}'. Step 20 supports 'mysql' only.")

        # 3. Canonicalize approved_objects if provided
        if self.approved_objects is not None:
            clean_approved = tuple(sorted({
                str(obj).strip().lower()
                for obj in self.approved_objects
                if str(obj).strip()
            }))
            object.__setattr__(self, "approved_objects", clean_approved)

        # 4. Ensure context_id is populated deterministically if empty
        if not self.context_id or not self.context_id.strip():
            suffix = ""
            if self.approved_objects:
                suffix = f"_{hashlib.sha256(','.join(self.approved_objects).encode()).hexdigest()[:8]}"
            auto_id = f"ctx_{self.host}_{self.port}_{self.database_name}{suffix}"
            object.__setattr__(self, "context_id", auto_id)

    def is_object_approved(self, object_name: str) -> bool:
        """Check whether an object name is permitted under this database context."""
        if not object_name:
            return False
        clean = str(object_name).strip().lower()
        if self.approved_objects is None:
            return True
        return clean in self.approved_objects

    def __repr__(self) -> str:
        """Safe string representation guaranteeing zero secret exposure."""
        approved_repr = f", approved_objects={self.approved_objects!r}" if self.approved_objects is not None else ""
        return (
            f"ActiveDatabaseContext("
            f"context_id='{self.context_id}', "
            f"display_name='{self.display_name}', "
            f"database_name='{self.database_name}', "
            f"dialect='{self.dialect}', "
            f"source_type='{self.source_type}', "
            f"host='{self.host}', "
            f"port={self.port}, "
            f"schema_fingerprint='{self.schema_fingerprint[:12]}...', "
            f"status='{self.status}'"
            f"{approved_repr})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return safe dictionary representation without any sensitive fields."""
        return {
            "context_id": self.context_id,
            "display_name": self.display_name,
            "database_name": self.database_name,
            "dialect": self.dialect,
            "source_type": self.source_type,
            "host": self.host,
            "port": self.port,
            "schema_fingerprint": self.schema_fingerprint,
            "status": self.status,
            "metadata": dict(self.metadata),
            "approved_objects": list(self.approved_objects) if self.approved_objects is not None else None,
        }

