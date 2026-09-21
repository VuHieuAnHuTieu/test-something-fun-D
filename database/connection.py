"""Database connection layer enforcing least-privilege security separation.

This module provides two distinct, mutually isolated connection functions:
1. get_business_connection(): Read-only access to approved business database for bi_reader.
2. get_agent_connection(): State persistence access to agent_system for agent_app.

Security Guarantees:
- Uses validated credentials from config.py only.
- Passwords and secrets are never printed, logged, or leaked in exception strings.
- Connections are short-lived, fresh instances with connection timeouts.
- No generic, unrestricted, or raw SQL execution helpers are exposed here.
"""

from __future__ import annotations

import mysql.connector
from mysql.connector.connection import MySQLConnection

from config import Settings, get_settings


class DatabaseConnectionError(RuntimeError):
    """Raised when establishing a database connection fails without leaking secrets."""
    pass


def _redact_secrets(message: str, secrets: tuple[str, ...]) -> str:
    """Ensure no plaintext secret appears in an error message."""
    redacted = message
    for secret in secrets:
        if secret and secret in redacted:
            redacted = redacted.replace(secret, "********")
    return redacted


def get_business_connection(
    custom_settings: Settings | None = None,
    database_name: str | None = None,
) -> MySQLConnection:
    """Establish a fresh, read-only connection to the business database for bi_reader.

    Args:
        custom_settings: Optional Settings instance (used for dependency injection in tests).
        database_name: Optional database name override. If omitted, uses settings.mysql_business_db.

    Returns:
        MySQLConnection: Connected MySQL connection object for the business database.

    Raises:
        DatabaseConnectionError: If connection fails, with secrets sanitized.
    """
    settings = custom_settings or get_settings()
    target_db = database_name or settings.mysql_business_db
    try:
        conn = mysql.connector.connect(
            host=settings.mysql_host,
            port=settings.mysql_port,
            database=target_db,
            user=settings.mysql_read_user,
            password=settings.mysql_read_password,
            connection_timeout=int(settings.query_timeout_seconds),
            autocommit=True,
        )
        return conn
    except Exception as exc:
        safe_msg = _redact_secrets(
            str(exc),
            (settings.mysql_read_password, settings.mysql_app_password),
        )
        raise DatabaseConnectionError(
            f"Failed to connect to business database '{target_db}' "
            f"at {settings.mysql_host}:{settings.mysql_port} as '{settings.mysql_read_user}': {safe_msg}"
        ) from None


def get_agent_connection(custom_settings: Settings | None = None) -> MySQLConnection:
    """Establish a fresh state-persistence connection to agent_system for agent_app.

    Args:
        custom_settings: Optional Settings instance (used for dependency injection in tests).

    Returns:
        MySQLConnection: Connected MySQL connection object for the agent state database.

    Raises:
        DatabaseConnectionError: If connection fails, with secrets sanitized.
    """
    settings = custom_settings or get_settings()
    try:
        conn = mysql.connector.connect(
            host=settings.mysql_host,
            port=settings.mysql_port,
            database=settings.mysql_agent_db,
            user=settings.mysql_app_user,
            password=settings.mysql_app_password,
            connection_timeout=int(settings.query_timeout_seconds),
            autocommit=False,  # Explicit transaction handling for state persistence
        )
        return conn
    except Exception as exc:
        safe_msg = _redact_secrets(
            str(exc),
            (settings.mysql_read_password, settings.mysql_app_password),
        )
        raise DatabaseConnectionError(
            f"Failed to connect to agent database '{settings.mysql_agent_db}' "
            f"at {settings.mysql_host}:{settings.mysql_port} as '{settings.mysql_app_user}': {safe_msg}"
        ) from None


def get_import_connection(
    custom_settings: Settings | None = None,
    database_name: str | None = None,
) -> MySQLConnection:
    """Establish a restricted connection to the managed import schema using dataset_importer.

    Security Guarantees:
    - Strictly dedicated to the user-triggered onboarding import path into managed_import.
    - NEVER used by schema_tool or sql_tool business querying or by Qwen runtime agents.
    - Scoped only to the managed import schema namespace.
    - Passwords and secrets are never leaked in logs, strings, or exception messages.

    Args:
        custom_settings: Optional Settings instance.
        database_name: Optional database name override (defaults to settings.mysql_import_db).

    Returns:
        MySQLConnection: Connected MySQL connection object for managed imports.

    Raises:
        DatabaseConnectionError: If connection fails, with secrets sanitized.
    """
    settings = custom_settings or get_settings()
    target_db = database_name or settings.mysql_import_db

    if not settings.mysql_import_password:
        raise DatabaseConnectionError(
            f"Failed to connect to import database '{target_db}' as '{settings.mysql_import_user}': "
            "IMPORT_PRIVILEGE_REQUIRED: Importer credentials not configured. "
            "Provision the user with database/create_import_user.sql and configure environment credentials."
        )

    try:
        conn = mysql.connector.connect(
            host=settings.mysql_host,
            port=settings.mysql_port,
            database=target_db,
            user=settings.mysql_import_user,
            password=settings.mysql_import_password,
            connection_timeout=int(settings.query_timeout_seconds),
            autocommit=False,  # Transactional integrity required for imports
        )
        return conn
    except Exception as exc:
        safe_msg = _redact_secrets(
            str(exc),
            (settings.mysql_read_password, settings.mysql_app_password, settings.mysql_import_password),
        )
        raise DatabaseConnectionError(
            f"Failed to connect to import database '{target_db}' "
            f"at {settings.mysql_host}:{settings.mysql_port} as '{settings.mysql_import_user}': {safe_msg}"
        ) from None

