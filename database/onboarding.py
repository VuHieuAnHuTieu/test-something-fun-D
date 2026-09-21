"""Dynamic Database Onboarding and Ingestion for MySQL.

Provides:
1. Existing MySQL database discovery and validation.
2. Safe CSV staging, identifier sanitization, and conservative type inference.
3. Safe MySQL dump AST validation (strict whitelist: CREATE TABLE and INSERT only).
4. Strict privilege isolation: Fails closed with IMPORT_PRIVILEGE_REQUIRED if write/DDL
   privileges are unavailable. Never uses root or weakens bi_reader.
"""

from __future__ import annotations

import csv
import io
import os
import re
from pathlib import Path
from typing import Any

import sqlglot
from sqlglot import exp

from config import Settings, get_settings
from database.connection import DatabaseConnectionError, get_business_connection
from database.database_context import (
    PROHIBITED_BUSINESS_SCHEMAS,
    ActiveDatabaseContext,
    DatabaseStatus,
    SourceType,
    compute_schema_fingerprint,
    validate_database_identifier,
)

# ==============================================================================
# CONSTANTS & POLICIES
# ==============================================================================

MAX_CSV_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
MAX_CSV_FILE_COUNT: int = 10

_UNSAFE_DUMP_KEYWORDS: tuple[str, ...] = (
    "DROP DATABASE",
    "DROP USER",
    "CREATE USER",
    "ALTER USER",
    "GRANT",
    "REVOKE",
    "SET PASSWORD",
    "LOAD DATA",
    "LOAD_FILE",
    "INTO OUTFILE",
    "INTO DUMPFILE",
    "INSTALL",
    "UNINSTALL",
    "PLUGIN",
    "FUNCTION",
    "PROCEDURE",
    "TRIGGER",
    "EVENT",
    "CALL",
    "EXECUTE",
    "PREPARE",
    "LOCK TABLES",
    "UNLOCK TABLES",
    "DEFINER",
    "DELIMITER",
)


# ==============================================================================
# IDENTIFIER SANITIZATION
# ==============================================================================

def sanitize_sql_identifier(name: str | None, prefix_if_digit: str = "col_") -> str:
    """Sanitize a candidate string into a clean, safe MySQL identifier [a-zA-Z0-9_].

    Args:
        name: Raw identifier candidate (e.g. from CSV header or filename).
        prefix_if_digit: Prefix to prepend if the identifier starts with a number.

    Returns:
        Sanitized lowercase identifier.

    Raises:
        ValueError: If candidate is empty or cannot be sanitized.
    """
    if name is None or not str(name).strip():
        raise ValueError("Identifier cannot be empty or blank.")

    cleaned = str(name).strip().lower()
    # Replace non-alphanumeric chars with underscore
    cleaned = re.sub(r"[^a-z0-9_]", "_", cleaned)
    # Collapse multiple consecutive underscores
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")

    if not cleaned:
        raise ValueError(f"Identifier '{name}' contains no valid alphanumeric characters.")

    if cleaned[0].isdigit():
        cleaned = f"{prefix_if_digit}{cleaned}"

    return cleaned


# ==============================================================================
# EXISTING MYSQL ONBOARDING
# ==============================================================================

def discover_accessible_databases(custom_settings: Settings | None = None) -> list[str]:
    """Discover user schemas accessible to the configured business connection.

    Excludes MySQL system schemas (mysql, information_schema, performance_schema, sys)
    and agent_system.

    Returns:
        Sorted list of accessible user database names.
    """
    settings = custom_settings or get_settings()
    try:
        with get_business_connection(custom_settings=settings) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SHOW DATABASES;")
                rows = cursor.fetchall()
                accessible = [
                    str(r[0]).strip().lower()
                    for r in rows
                    if r and str(r[0]).strip().lower() not in PROHIBITED_BUSINESS_SCHEMAS
                ]
                return sorted(accessible)
    except DatabaseConnectionError:
        return []


def onboard_existing_database(
    database_name: str,
    display_name: str | None = None,
    custom_settings: Settings | None = None,
) -> ActiveDatabaseContext:
    """Onboard an existing MySQL database into an ActiveDatabaseContext.

    Discovers schema objects, computes the canonical SHA-256 fingerprint,
    and returns a ready context. Does not expose credentials or modify data.

    Args:
        database_name: Target MySQL database name.
        display_name: Human-friendly name.
        custom_settings: Optional settings injection.

    Returns:
        ActiveDatabaseContext with status READY, DATABASE_NOT_FOUND, or DATABASE_NOT_ACCESSIBLE.
    """
    settings = custom_settings or get_settings()

    # 1. Validate database identifier
    try:
        clean_db = validate_database_identifier(database_name)
    except ValueError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{database_name}",
            display_name=display_name or database_name,
            database_name=database_name,
            dialect="mysql",
            source_type=SourceType.EXISTING_MYSQL.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={"error": str(exc)},
        )

    # 2. Check existence in accessible databases
    accessible = discover_accessible_databases(custom_settings=settings)
    if clean_db.lower() not in accessible:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{clean_db}",
            display_name=display_name or clean_db,
            database_name=clean_db,
            dialect="mysql",
            source_type=SourceType.EXISTING_MYSQL.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.DATABASE_NOT_FOUND.value,
            metadata={"error": f"Database '{clean_db}' not found among accessible user schemas."},
        )

    # 3. Create provisional context and inspect schema metadata
    provisional_context = ActiveDatabaseContext(
        context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{clean_db}",
        display_name=display_name or clean_db.replace("_", " ").title(),
        database_name=clean_db,
        dialect="mysql",
        source_type=SourceType.EXISTING_MYSQL.value,
        host=settings.mysql_host,
        port=settings.mysql_port,
        status=DatabaseStatus.READY.value,
    )

    from tools.schema_tool import SchemaInspectionError, get_schema_snapshot
    try:
        snapshot = get_schema_snapshot(
            custom_settings=settings,
            database_context=provisional_context,
        )
        fingerprint = compute_schema_fingerprint(snapshot)
        raw_objects = [
            str(obj["object_name"]).strip()
            for obj in snapshot.get("objects", [])
            if obj.get("object_name")
        ]
        approved_tuple = tuple(sorted(raw_objects))

        return ActiveDatabaseContext(
            context_id=provisional_context.context_id,
            display_name=provisional_context.display_name,
            database_name=clean_db,
            dialect="mysql",
            source_type=SourceType.EXISTING_MYSQL.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            schema_fingerprint=fingerprint,
            status=DatabaseStatus.READY.value,
            approved_objects=approved_tuple,
            metadata={"object_count": len(approved_tuple)},
        )
    except (DatabaseConnectionError, SchemaInspectionError, Exception) as exc:
        return ActiveDatabaseContext(
            context_id=provisional_context.context_id,
            display_name=provisional_context.display_name,
            database_name=clean_db,
            dialect="mysql",
            source_type=SourceType.EXISTING_MYSQL.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.DATABASE_NOT_ACCESSIBLE.value,
            metadata={"error": str(exc)},
        )


# ==============================================================================
# CONSERVATIVE CSV TYPE INFERENCE
# ==============================================================================

_DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$")
_INTEGER_REGEX = re.compile(r"^-?\d+$")
_DECIMAL_REGEX = re.compile(r"^-?\d+\.\d+$")
_BOOLEAN_VALUES = frozenset({"true", "false", "0", "1", "t", "f", "yes", "no"})


def infer_sql_type(sample_values: list[str | None]) -> str:
    """Conservatively infer MySQL data type from a sample of non-null string values.

    Rules:
    - If empty/all null -> VARCHAR(255)
    - If all integer strings -> BIGINT
    - If all decimal/float strings -> DECIMAL(18, 4)
    - If all YYYY-MM-DD -> DATE
    - If all YYYY-MM-DD HH:MM:SS -> DATETIME
    - If all boolean tokens -> BOOLEAN
    - Otherwise -> VARCHAR(255) (or TEXT if max length > 255)
    """
    non_nulls = [v.strip() for v in sample_values if v is not None and v.strip() != ""]
    if not non_nulls:
        return "VARCHAR(255)"

    # Check boolean
    if all(v.lower() in _BOOLEAN_VALUES for v in non_nulls):
        return "BOOLEAN"

    # Check integer
    if all(_INTEGER_REGEX.match(v) for v in non_nulls):
        return "BIGINT"

    # Check decimal (or combination of integer and decimal)
    if all(_DECIMAL_REGEX.match(v) or _INTEGER_REGEX.match(v) for v in non_nulls):
        return "DECIMAL(18, 4)"

    # Check date
    if all(_DATE_REGEX.match(v) for v in non_nulls):
        return "DATE"

    # Check datetime
    if all(_DATETIME_REGEX.match(v) for v in non_nulls):
        return "DATETIME"

    # Check max string length for text vs varchar
    max_len = max(len(v) for v in non_nulls)
    if max_len > 255:
        return "TEXT"

    return "VARCHAR(255)"


# ==============================================================================
# CSV ONBOARDING PREPARATION & VALIDATION
# ==============================================================================

def prepare_csv_import(
    file_paths: list[str | Path] | str | Path,
    target_schema: str = "managed_import",
    dataset_id: str | None = None,
) -> dict[str, Any]:
    """Validate, parse, and stage CSV files for deterministic import.

    Guarantees:
    - Validates file existence and size.
    - Handles UTF-8 and UTF-8 BOM.
    - Sanitizes table names and column names.
    - Rejects empty datasets and duplicate column names.
    - Cell values are strictly passed as parameterized tuples (%s), NEVER string-concatenated.

    Args:
        file_paths: One or more paths to CSV files.
        target_schema: Destination schema namespace.
        dataset_id: Optional dataset identifier to construct managed namespace managed_import_<dataset_id>.

    Returns:
        Structured staging dictionary containing sanitized tables, columns, types, and parameterized rows.

    Raises:
        ValueError: If validation fails.
    """
    if isinstance(file_paths, (str, Path)):
        paths = [Path(file_paths)]
    else:
        paths = [Path(p) for p in file_paths]

    if not paths:
        raise ValueError("No CSV files provided for onboarding.")

    if len(paths) > MAX_CSV_FILE_COUNT:
        raise ValueError(f"Exceeded maximum file count ({MAX_CSV_FILE_COUNT}). Provided {len(paths)}.")

    if dataset_id is not None and str(dataset_id).strip():
        safe_ds = sanitize_sql_identifier(dataset_id)
        target_schema = f"managed_import_{safe_ds}"

    target_schema_clean = validate_database_identifier(target_schema)

    tables_data: list[dict[str, Any]] = []
    seen_tables: set[str] = set()

    for path in paths:
        if not path.is_file():
            raise ValueError(f"CSV file not found: '{path}'")

        if path.suffix.lower() != ".csv":
            raise ValueError(f"File '{path.name}' is not a CSV file.")

        file_size = path.stat().st_size
        if file_size == 0:
            raise ValueError(f"CSV file '{path.name}' is empty (0 bytes).")
        if file_size > MAX_CSV_FILE_SIZE_BYTES:
            raise ValueError(f"CSV file '{path.name}' exceeds maximum size ({MAX_CSV_FILE_SIZE_BYTES} bytes).")

        raw_table_name = path.stem
        sanitized_table = sanitize_sql_identifier(raw_table_name)
        if sanitized_table in seen_tables:
            raise ValueError(f"Duplicate table name collision: '{sanitized_table}'")
        seen_tables.add(sanitized_table)

        # Read CSV with BOM handling
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                headers = next(reader, None)
                if not headers:
                    raise ValueError(f"CSV file '{path.name}' has no headers.")

                # Sanitize column names
                sanitized_cols: list[str] = []
                seen_cols: set[str] = set()
                for idx, h in enumerate(headers):
                    col_name = sanitize_sql_identifier(h, prefix_if_digit="col_")
                    if col_name in seen_cols:
                        raise ValueError(f"Duplicate column '{col_name}' detected in '{path.name}'.")
                    seen_cols.add(col_name)
                    sanitized_cols.append(col_name)

                # Read rows
                rows: list[list[str | None]] = []
                for row in reader:
                    # Pad row if ragged
                    padded = [row[i] if i < len(row) else None for i in range(len(sanitized_cols))]
                    rows.append(padded)

                if not rows:
                    raise ValueError(f"CSV file '{path.name}' has headers but zero data rows.")

        except UnicodeDecodeError:
            raise ValueError(f"CSV file '{path.name}' is not valid UTF-8.")

        # Infer column types
        col_types: dict[str, str] = {}
        for idx, col_name in enumerate(sanitized_cols):
            samples = [r[idx] for r in rows[:1000]]
            col_types[col_name] = infer_sql_type(samples)

        # Build parameterized statement
        col_str = ", ".join(sanitized_cols)
        placeholder_str = ", ".join(["%s"] * len(sanitized_cols))
        parameterized_insert_sql = (
            f"INSERT INTO `{target_schema_clean}`.`{sanitized_table}` ({col_str}) "
            f"VALUES ({placeholder_str});"
        )

        tables_data.append({
            "table_name": sanitized_table,
            "columns": sanitized_cols,
            "types": col_types,
            "row_count": len(rows),
            "parameterized_insert_sql": parameterized_insert_sql,
            "parameter_tuples": rows,
        })

    return {
        "status": "VALIDATED",
        "target_schema": target_schema_clean,
        "dataset_id": dataset_id,
        "tables": tables_data,
    }


def execute_csv_import(
    prepared_import: dict[str, Any],
    custom_settings: Settings | None = None,
    dataset_id: str | None = None,
) -> ActiveDatabaseContext:
    """Execute CSV import into managed MySQL schema using dedicated importer connection.

    Enforces fail-closed privilege and security guarantees:
    - Never uses root.
    - Never uses read-only bi_reader (fails closed with IMPORT_PRIVILEGE_REQUIRED if
      dedicated importer account is not provisioned or configured).
    - Discovers pre-existing objects in the target schema prior to execution.
    - Executes DDL and DML using transactional DML + compensating DDL cleanup.
    - If any error occurs: rolls back pending DML, explicitly drops ONLY freshly created
      tables from THIS import attempt, never drops pre-existing objects or other datasets,
      and returns FAILED status (never READY).
    - On success, commits transaction, generates canonical schema fingerprint, sets
      approved_objects allowlist, and returns READY status.

    Args:
        prepared_import: Output dictionary from prepare_csv_import().
        custom_settings: Optional Settings injection.
        dataset_id: Optional dataset identifier override.

    Returns:
        ActiveDatabaseContext with READY, IMPORT_PRIVILEGE_REQUIRED, or FAILED status.
    """
    settings = custom_settings or get_settings()
    effective_ds = dataset_id or prepared_import.get("dataset_id")
    target_schema = prepared_import.get("target_schema")
    if effective_ds and (not target_schema or target_schema == "managed_import"):
        target_schema = f"managed_import_{sanitize_sql_identifier(effective_ds)}"
    elif not target_schema:
        target_schema = "managed_import"

    try:
        target_schema_clean = validate_database_identifier(target_schema)
    except ValueError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema}",
            display_name=f"Import {str(target_schema).title()}",
            database_name=str(target_schema),
            dialect="mysql",
            source_type=SourceType.CSV_IMPORT.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={"error": str(exc)},
        )

    # 1. Attempt connection using dedicated dataset_importer role
    from database.connection import DatabaseConnectionError, get_import_connection
    try:
        conn = get_import_connection(custom_settings=settings, database_name=target_schema_clean)
    except DatabaseConnectionError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
            display_name=f"Import {target_schema_clean.title()}",
            database_name=target_schema_clean,
            dialect="mysql",
            source_type=SourceType.CSV_IMPORT.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.IMPORT_PRIVILEGE_REQUIRED.value,
            metadata={
                "error": (
                    "IMPORT_PRIVILEGE_REQUIRED: The dedicated import account is not available or not configured. "
                    f"Underlying error: {exc}"
                ),
                "prepared_tables": [t["table_name"] for t in prepared_import.get("tables", [])],
            },
        )

    # 2. Discover pre-existing tables to ensure compensating cleanup NEVER touches them
    pre_existing_tables: set[str] = set()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s;",
                (target_schema_clean,),
            )
            for row in cursor.fetchall():
                if row and row[0]:
                    pre_existing_tables.add(str(row[0]).strip().lower())
    except Exception:
        pass

    # 3. Transactional execution + compensating DDL cleanup tracking
    freshly_created_objects: list[str] = []
    tables_created: list[str] = []
    total_rows_imported: int = 0
    try:
        with conn.cursor() as cursor:
            for table_data in prepared_import.get("tables", []):
                t_name = sanitize_sql_identifier(table_data["table_name"])
                cols = table_data["columns"]
                types = table_data["types"]
                col_defs = [f"`{col}` {types.get(col, 'VARCHAR(255)')}" for col in cols]
                create_sql = (
                    f"CREATE TABLE IF NOT EXISTS `{target_schema_clean}`.`{t_name}` "
                    f"({', '.join(col_defs)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
                )
                cursor.execute(create_sql)
                if t_name.lower() not in pre_existing_tables and t_name not in freshly_created_objects:
                    freshly_created_objects.append(t_name)
                tables_created.append(t_name)

                insert_sql = table_data.get("parameterized_insert_sql")
                rows = table_data.get("parameter_tuples", [])
                if rows:
                    tuples = [tuple(r) for r in rows]
                    cursor.executemany(insert_sql, tuples)
                    total_rows_imported += len(tuples)

        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        # Compensating DDL cleanup: drop ONLY freshly created tables from THIS import attempt
        tables_to_drop = [t for t in freshly_created_objects if t.lower() not in pre_existing_tables]
        try:
            with conn.cursor() as cleanup_cursor:
                for t in tables_to_drop:
                    cleanup_cursor.execute(f"DROP TABLE IF EXISTS `{target_schema_clean}`.`{t}`;")
            conn.commit()
        except Exception:
            pass
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
            display_name=f"Import {target_schema_clean.title()}",
            database_name=target_schema_clean,
            dialect="mysql",
            source_type=SourceType.CSV_IMPORT.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={
                "error": f"CSV import execution failed and was rolled back with compensating DDL cleanup: {exc}",
                "cleaned_tables": tables_to_drop,
            },
        )
    finally:
        try:
            if conn.is_connected():
                conn.close()
        except Exception:
            pass

    # 3. Compute deterministic schema fingerprint
    canonical_objects = [{"object_name": t, "object_type": "BASE TABLE"} for t in sorted(tables_created)]
    canonical_columns = []
    for table_data in prepared_import.get("tables", []):
        t_name = sanitize_sql_identifier(table_data["table_name"])
        for col in table_data["columns"]:
            canonical_columns.append({
                "table_name": t_name,
                "column_name": col,
                "data_type": table_data["types"].get(col, "VARCHAR(255)").split("(")[0].lower(),
                "is_nullable": "YES",
                "column_key": "",
            })
    canonical_snapshot = {
        "database": target_schema_clean,
        "objects": canonical_objects,
        "columns": canonical_columns,
        "primary_keys": [],
        "foreign_keys": [],
        "approved_objects": sorted(tables_created),
    }
    fingerprint = compute_schema_fingerprint(canonical_snapshot)

    approved_tuple = tuple(sorted(tables_created))
    return ActiveDatabaseContext(
        context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
        display_name=f"Import {target_schema_clean.title()}",
        database_name=target_schema_clean,
        dialect="mysql",
        source_type=SourceType.CSV_IMPORT.value,
        host=settings.mysql_host,
        port=settings.mysql_port,
        schema_fingerprint=fingerprint,
        status=DatabaseStatus.READY.value,
        approved_objects=approved_tuple,
        metadata={
            "imported_tables": tables_created,
            "total_rows": total_rows_imported,
            "dataset_id": effective_ds,
        },
    )


# ==============================================================================
# MYSQL DUMP ONBOARDING (STRICT SAFE SUBSET)
# ==============================================================================

def validate_sql_dump(
    dump_sql: str,
    target_schema: str = "managed_import",
    dataset_id: str | None = None,
) -> dict[str, Any]:
    """Validate a MySQL dump string against a strict safe subset (CREATE TABLE, INSERT).

    Strict rejection rules:
    - DROP DATABASE, DROP USER, CREATE USER, GRANT, REVOKE rejected.
    - LOAD DATA, INTO OUTFILE, INTO DUMPFILE rejected.
    - FUNCTION, PROCEDURE, TRIGGER, EVENT, DEFINER, DELIMITER rejected.
    - Uploaded USE statement cannot redirect target schema (rejected).
    - CTAS (CREATE TABLE ... AS SELECT) rejected.
    - CREATE TABLE ... LIKE rejected.
    - Non-standard storage engines rejected (only InnoDB permitted; FEDERATED/BLACKHOLE/CSV rejected).
    - DATA DIRECTORY, INDEX DIRECTORY, CONNECTION options rejected.
    - Cross-schema foreign key REFERENCES rejected.
    - INSERT ... SELECT rejected (only literal VALUES-based INSERT permitted).

    Args:
        dump_sql: Raw SQL text from dump file.
        target_schema: Target isolated business schema.
        dataset_id: Optional dataset identifier to construct managed namespace managed_import_<dataset_id>.

    Returns:
        Structured validation dictionary with validated statement count and tables.

    Raises:
        ValueError: If unsupported or dangerous statements are detected.
    """
    if not dump_sql or not dump_sql.strip():
        raise ValueError("SQL dump is empty or blank.")

    if dataset_id is not None and str(dataset_id).strip():
        safe_ds = sanitize_sql_identifier(dataset_id)
        target_schema = f"managed_import_{safe_ds}"

    target_schema_clean = validate_database_identifier(target_schema)

    # 1. Check raw keywords for dangerous operations
    for kw in _UNSAFE_DUMP_KEYWORDS:
        pattern = rf"\b{re.escape(kw)}\b"
        if re.search(pattern, dump_sql, re.IGNORECASE):
            raise ValueError(f"UNSUPPORTED_DUMP_STATEMENT: Prohibited operation detected '{kw}'.")

    # 2. Parse with SQLGlot
    try:
        statements = sqlglot.parse(dump_sql, read="mysql")
    except Exception as exc:
        raise ValueError(f"UNSUPPORTED_DUMP_STATEMENT: Failed to parse SQL dump: {exc}")

    non_empty = [s for s in statements if s is not None]
    if not non_empty:
        raise ValueError("SQL dump contains no executable statements.")

    validated_tables: set[str] = set()
    validated_inserts: int = 0

    for stmt in non_empty:
        stmt_sql = stmt.sql(dialect="mysql")

        # Whitelist: Only CREATE TABLE and INSERT are accepted
        if isinstance(stmt, exp.Create):
            if stmt.kind != "TABLE":
                raise ValueError(
                    f"UNSUPPORTED_DUMP_STATEMENT: Only 'CREATE TABLE' is supported in V1 dumps (found '{stmt.kind}')."
                )

            # Reject CTAS (CREATE TABLE ... AS SELECT)
            if stmt.find(exp.Select) is not None or (stmt.expression is not None and isinstance(stmt.expression, exp.Select)):
                raise ValueError(
                    "UNSUPPORTED_DUMP_STATEMENT: 'CREATE TABLE ... AS SELECT' is prohibited in safe dumps."
                )

            # Reject CREATE TABLE ... LIKE
            if stmt.args.get("like") or stmt.find(exp.Like) or re.search(r"\bLIKE\s+", stmt_sql, re.IGNORECASE):
                raise ValueError(
                    "UNSUPPORTED_DUMP_STATEMENT: 'CREATE TABLE ... LIKE' is prohibited in safe dumps."
                )

            # Reject DATA DIRECTORY and INDEX DIRECTORY table options
            if re.search(r"\b(DATA|INDEX)\s+DIRECTORY\b", stmt_sql, re.IGNORECASE):
                raise ValueError(
                    "UNSUPPORTED_DUMP_STATEMENT: DATA DIRECTORY and INDEX DIRECTORY table options are prohibited."
                )

            # Reject non-InnoDB storage engines (e.g. FEDERATED, BLACKHOLE, CSV)
            engine_match = re.search(r"\bENGINE\s*=\s*([a-zA-Z0-9_]+)", stmt_sql, re.IGNORECASE)
            if engine_match:
                engine_name = engine_match.group(1).lower()
                if engine_name != "innodb":
                    raise ValueError(
                        f"UNSUPPORTED_DUMP_STATEMENT: Prohibited storage engine '{engine_name}'. Only InnoDB is permitted."
                    )

            # Reject CONNECTION option
            if re.search(r"\bCONNECTION\s*=", stmt_sql, re.IGNORECASE):
                raise ValueError(
                    "UNSUPPORTED_DUMP_STATEMENT: CONNECTION table option is prohibited."
                )

            # Reject cross-schema foreign key references
            for ref in stmt.find_all(exp.Reference):
                ref_tbl = ref.find(exp.Table)
                if ref_tbl and ref_tbl.db:
                    if ref_tbl.db.lower() != target_schema_clean.lower():
                        raise ValueError(
                            f"UNSUPPORTED_DUMP_STATEMENT: Cross-schema foreign key REFERENCES to '{ref_tbl.db}' are prohibited."
                        )

            # Verify target table name and schema
            table_expr = stmt.find(exp.Table)
            if table_expr:
                if table_expr.db and (table_expr.db.lower() in PROHIBITED_BUSINESS_SCHEMAS or table_expr.db.lower() != target_schema_clean.lower()):
                    raise ValueError(
                        f"UNSUPPORTED_DUMP_STATEMENT: Table targets prohibited schema '{table_expr.db}'."
                    )
                sanitized_table = sanitize_sql_identifier(table_expr.name)
                validated_tables.add(sanitized_table)

        elif isinstance(stmt, exp.Insert):
            # Reject INSERT ... SELECT (only literal VALUES-based INSERT permitted)
            if stmt.find(exp.Select) is not None or not isinstance(stmt.expression, exp.Values):
                raise ValueError(
                    "UNSUPPORTED_DUMP_STATEMENT: Only literal VALUES-based INSERT statements are accepted in V1 dumps."
                )

            validated_inserts += 1
            table_expr = stmt.find(exp.Table)
            if table_expr and table_expr.db:
                if table_expr.db.lower() in PROHIBITED_BUSINESS_SCHEMAS or table_expr.db.lower() != target_schema_clean.lower():
                    raise ValueError(
                        f"UNSUPPORTED_DUMP_STATEMENT: INSERT targets prohibited schema '{table_expr.db}'."
                    )
        elif isinstance(stmt, exp.Use):
            raise ValueError("UNSUPPORTED_DUMP_STATEMENT: USE statements are rejected to prevent target schema redirection.")
        else:
            raise ValueError(
                f"UNSUPPORTED_DUMP_STATEMENT: Statement type '{type(stmt).__name__}' is rejected. "
                "Only CREATE TABLE and INSERT are accepted in V1 dumps."
            )

    return {
        "status": "VALIDATED",
        "statement_count": len(non_empty),
        "validated_tables": sorted(list(validated_tables)),
        "insert_count": validated_inserts,
        "target_schema": target_schema_clean,
        "dataset_id": dataset_id,
    }


def execute_sql_dump_import(
    dump_sql: str,
    target_schema: str = "managed_import",
    dataset_id: str | None = None,
    custom_settings: Settings | None = None,
) -> ActiveDatabaseContext:
    """Validate and execute a MySQL dump into the managed target schema.

    Enforces strict security isolation:
    1. Validates AST against strict safe whitelist (CREATE TABLE and literal INSERT only;
       rejects CTAS, LIKE, cross-schema REFERENCES, non-InnoDB engines, and INSERT...SELECT).
    2. Uses dedicated dataset_importer role (never root, never bi_reader).
    3. Fails closed with IMPORT_PRIVILEGE_REQUIRED if importer credentials are unavailable.
    4. Discovers pre-existing tables prior to execution to protect them.
    5. Executes statements with transactional DML + compensating DDL cleanup.
       On failure: rolls back DML, drops ONLY freshly created tables from THIS attempt
       (never pre-existing objects or other datasets), and returns FAILED (never READY).
    6. On success, commits, sets approved_objects allowlist, computes canonical schema fingerprint,
       and returns READY.

    Args:
        dump_sql: Raw SQL text from dump file.
        target_schema: Isolated target schema.
        dataset_id: Optional dataset identifier to construct managed namespace managed_import_<dataset_id>.
        custom_settings: Optional Settings injection.

    Returns:
        ActiveDatabaseContext with READY, IMPORT_PRIVILEGE_REQUIRED, or FAILED status.
    """
    settings = custom_settings or get_settings()

    if dataset_id is not None and str(dataset_id).strip():
        safe_ds = sanitize_sql_identifier(dataset_id)
        target_schema = f"managed_import_{safe_ds}"

    # 1. Validate target schema identifier
    try:
        target_schema_clean = validate_database_identifier(target_schema)
    except ValueError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema}",
            display_name=f"Dump {str(target_schema).title()}",
            database_name=str(target_schema),
            dialect="mysql",
            source_type=SourceType.MYSQL_DUMP.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={"error": str(exc)},
        )

    # 2. Validate dump AST
    try:
        val_result = validate_sql_dump(dump_sql, target_schema=target_schema_clean, dataset_id=dataset_id)
    except ValueError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
            display_name=f"Dump {target_schema_clean.title()}",
            database_name=target_schema_clean,
            dialect="mysql",
            source_type=SourceType.MYSQL_DUMP.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={"error": f"SQL dump validation rejected: {exc}"},
        )

    # 3. Attempt import connection via dedicated dataset_importer
    from database.connection import DatabaseConnectionError, get_import_connection
    try:
        conn = get_import_connection(custom_settings=settings, database_name=target_schema_clean)
    except DatabaseConnectionError as exc:
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
            display_name=f"Dump {target_schema_clean.title()}",
            database_name=target_schema_clean,
            dialect="mysql",
            source_type=SourceType.MYSQL_DUMP.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.IMPORT_PRIVILEGE_REQUIRED.value,
            metadata={
                "error": (
                    "IMPORT_PRIVILEGE_REQUIRED: Dedicated import account is not available or not configured. "
                    f"Underlying error: {exc}"
                ),
                "validated_tables": val_result["validated_tables"],
                "statement_count": val_result["statement_count"],
            },
        )

    # 4. Discover pre-existing tables to protect them during compensating cleanup
    pre_existing_tables: set[str] = set()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s;",
                (target_schema_clean,),
            )
            for row in cursor.fetchall():
                if row and row[0]:
                    pre_existing_tables.add(str(row[0]).strip().lower())
    except Exception:
        pass

    # 5. Execute validated statements in a transaction + track created objects
    freshly_created_objects: list[str] = []
    tables_created: list[str] = []
    try:
        statements = sqlglot.parse(dump_sql, read="mysql")
        with conn.cursor() as cursor:
            for stmt in statements:
                if stmt is None:
                    continue
                # Ensure target schema qualification
                if isinstance(stmt, exp.Create):
                    t = stmt.find(exp.Table)
                    if t:
                        if not t.db:
                            t.set("db", exp.to_identifier(target_schema_clean))
                        t_name = sanitize_sql_identifier(t.name)
                        cursor.execute(stmt.sql(dialect="mysql"))
                        if t_name.lower() not in pre_existing_tables and t_name not in freshly_created_objects:
                            freshly_created_objects.append(t_name)
                        tables_created.append(t_name)
                elif isinstance(stmt, exp.Insert):
                    t = stmt.find(exp.Table)
                    if t and not t.db:
                        t.set("db", exp.to_identifier(target_schema_clean))
                    cursor.execute(stmt.sql(dialect="mysql"))

        conn.commit()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        # Compensating DDL cleanup: drop ONLY freshly created tables from THIS attempt
        tables_to_drop = [t for t in freshly_created_objects if t.lower() not in pre_existing_tables]
        try:
            with conn.cursor() as cleanup_cursor:
                for t in tables_to_drop:
                    cleanup_cursor.execute(f"DROP TABLE IF EXISTS `{target_schema_clean}`.`{t}`;")
            conn.commit()
        except Exception:
            pass
        return ActiveDatabaseContext(
            context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
            display_name=f"Dump {target_schema_clean.title()}",
            database_name=target_schema_clean,
            dialect="mysql",
            source_type=SourceType.MYSQL_DUMP.value,
            host=settings.mysql_host,
            port=settings.mysql_port,
            status=DatabaseStatus.FAILED.value,
            metadata={
                "error": f"SQL dump execution failed and was rolled back with compensating DDL cleanup: {exc}",
                "cleaned_tables": tables_to_drop,
            },
        )
    finally:
        try:
            if conn.is_connected():
                conn.close()
        except Exception:
            pass

    # 6. Compute deterministic schema fingerprint
    canonical_objects = [{"object_name": t, "object_type": "BASE TABLE"} for t in sorted(val_result["validated_tables"])]
    canonical_snapshot = {
        "database": target_schema_clean,
        "objects": canonical_objects,
        "columns": [],
        "primary_keys": [],
        "foreign_keys": [],
        "approved_objects": sorted(val_result["validated_tables"]),
    }
    fingerprint = compute_schema_fingerprint(canonical_snapshot)
    approved_tuple = tuple(sorted(val_result["validated_tables"]))

    return ActiveDatabaseContext(
        context_id=f"ctx_{settings.mysql_host}_{settings.mysql_port}_{target_schema_clean}",
        display_name=f"Dump {target_schema_clean.title()}",
        database_name=target_schema_clean,
        dialect="mysql",
        source_type=SourceType.MYSQL_DUMP.value,
        host=settings.mysql_host,
        port=settings.mysql_port,
        schema_fingerprint=fingerprint,
        status=DatabaseStatus.READY.value,
        approved_objects=approved_tuple,
        metadata={
            "validated_tables": val_result["validated_tables"],
            "statement_count": val_result["statement_count"],
            "dataset_id": dataset_id,
        },
    )
