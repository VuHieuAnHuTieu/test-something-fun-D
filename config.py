"""Configuration management and local-only security policy validation.

Runtime Security Rules:
- When LOCAL_ONLY=true, only loopback Ollama endpoints (http://127.0.0.1, http://localhost) are allowed.
- Remote, external, and LAN LLM endpoints are strictly blocked.
- Cloud API keys (OpenAI, Gemini, OpenRouter, Anthropic, DashScope) are forbidden.
- Database passwords and secrets are never printed in logs, repr, str, or exceptions.
- Empty or whitespace database usernames/passwords are rejected.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

# Explicitly load project-root .env; existing OS environment variables take precedence
load_dotenv(dotenv_path=ENV_PATH, override=False)


class ConfigurationError(ValueError):
    """Raised when runtime configuration is invalid or violates local-only policy."""
    pass


PROHIBITED_CLOUD_KEYS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "DASHSCOPE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "XAI_API_KEY",
)

ALLOWED_LOCAL_HOSTNAMES = {"127.0.0.1", "localhost"}

REQUIRED_VARS = (
    "LOCAL_ONLY",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    "MYSQL_HOST",
    "MYSQL_PORT",
    "MYSQL_BUSINESS_DB",
    "MYSQL_AGENT_DB",
    "MYSQL_READ_USER",
    "MYSQL_READ_PASSWORD",
    "MYSQL_APP_USER",
    "MYSQL_APP_PASSWORD",
)


class Settings(BaseModel):
    """Immutable runtime configuration container with secret redaction."""
    model_config = ConfigDict(frozen=True)

    local_only: bool
    ollama_host: str
    ollama_model: str

    mysql_host: str
    mysql_port: int
    mysql_business_db: str
    mysql_agent_db: str
    mysql_read_user: str
    mysql_read_password: str
    mysql_app_user: str
    mysql_app_password: str

    mysql_import_user: str = "dataset_importer"
    mysql_import_password: str = ""
    mysql_import_db: str = "managed_import"

    max_query_rows: int = 1000
    query_timeout_seconds: float = 5.0
    audit_log_path: str = "logs/audit.jsonl"
    app_env: str = "development"

    ollama_timeout_seconds: float = 30.0
    ollama_temperature: float = 0.1
    ollama_num_predict: int = 2048
    max_messages: int = 50
    max_message_chars: int = 32000
    max_total_prompt_chars: int = 128000

    # Step 27: Verified-Result Cache Configuration
    cache_enabled: bool = True
    cache_ttl_seconds: int = 30
    cache_max_entries: int = 128
    cache_max_entry_bytes: int = 1_000_000

    # Step 28: Deterministic Chart Configuration
    chart_enabled: bool = True
    chart_max_points: int = 500
    chart_max_categories: int = 30
    chart_dpi: int = 120
    chart_output_dir: str = "reports/charts"

    # Step 29: Deterministic Professional Report Configuration
    report_enabled: bool = True
    report_output_dir: str = "reports/pdfs"
    report_max_evidence_refs: int = 8
    report_max_charts: int = 5
    report_max_table_rows: int = 50
    report_max_table_columns: int = 12
    report_max_total_table_rows: int = 100
    report_max_pages: int = 20
    report_max_file_bytes: int = 10_000_000
    report_max_summary_chars: int = 2000
    report_max_cell_chars: int = 300

    # Step 35B: Generalized Question Understanding & Dynamic Schema Intelligence
    resolution_confidence_threshold: float = 0.70
    ambiguity_delta_threshold: float = 0.15
    max_schema_retrieval_rounds: int = 2
    max_schema_objects_per_round: int = 8
    max_graph_expansion_depth: int = 3
    max_schema_context_chars: int = 8000
    max_planning_calls: int = 2
    max_replans: int = 1

    def __repr__(self) -> str:
        return (
            f"Settings(local_only={self.local_only!r}, "
            f"ollama_host={self.ollama_host!r}, "
            f"ollama_model={self.ollama_model!r}, "
            f"mysql_host={self.mysql_host!r}, "
            f"mysql_port={self.mysql_port}, "
            f"mysql_business_db={self.mysql_business_db!r}, "
            f"mysql_agent_db={self.mysql_agent_db!r}, "
            f"mysql_read_user={self.mysql_read_user!r}, "
            f"mysql_read_password='***', "
            f"mysql_app_user={self.mysql_app_user!r}, "
            f"mysql_app_password='***', "
            f"mysql_import_user={self.mysql_import_user!r}, "
            f"mysql_import_password='***', "
            f"mysql_import_db={self.mysql_import_db!r}, "
            f"max_query_rows={self.max_query_rows}, "
            f"query_timeout_seconds={self.query_timeout_seconds}, "
            f"audit_log_path={self.audit_log_path!r}, "
            f"app_env={self.app_env!r}, "
            f"ollama_timeout_seconds={self.ollama_timeout_seconds}, "
            f"ollama_temperature={self.ollama_temperature}, "
            f"ollama_num_predict={self.ollama_num_predict}, "
            f"max_messages={self.max_messages}, "
            f"max_message_chars={self.max_message_chars}, "
            f"max_total_prompt_chars={self.max_total_prompt_chars}, "
            f"cache_enabled={self.cache_enabled}, "
            f"cache_ttl_seconds={self.cache_ttl_seconds}, "
            f"cache_max_entries={self.cache_max_entries}, "
            f"cache_max_entry_bytes={self.cache_max_entry_bytes}, "
            f"chart_enabled={self.chart_enabled}, "
            f"chart_max_points={self.chart_max_points}, "
            f"chart_max_categories={self.chart_max_categories}, "
            f"chart_dpi={self.chart_dpi}, "
            f"chart_output_dir={self.chart_output_dir!r}, "
            f"report_enabled={self.report_enabled}, "
            f"report_output_dir={self.report_output_dir!r}, "
            f"report_max_evidence_refs={self.report_max_evidence_refs}, "
            f"report_max_charts={self.report_max_charts}, "
            f"report_max_table_rows={self.report_max_table_rows}, "
            f"report_max_table_columns={self.report_max_table_columns}, "
            f"report_max_total_table_rows={self.report_max_total_table_rows}, "
            f"report_max_pages={self.report_max_pages}, "
            f"report_max_file_bytes={self.report_max_file_bytes}, "
            f"report_max_summary_chars={self.report_max_summary_chars}, "
            f"report_max_cell_chars={self.report_max_cell_chars})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def parse_bool(val: Any) -> bool:
    """Parse a boolean value from boolean or string representation."""
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in {"true", "1", "yes", "t"}:
        return True
    if s in {"false", "0", "no", "f"}:
        return False
    raise ConfigurationError(
        f"Configuration error: LOCAL_ONLY must be a boolean ('true' or 'false'). Received: '{val}'"
    )


def parse_port(val: Any) -> int:
    """Parse and validate an integer network port."""
    try:
        port_int = int(str(val).strip())
    except (ValueError, TypeError):
        raise ConfigurationError(
            f"Configuration error: MYSQL_PORT must be a valid integer. Received: '{val}'"
        )
    if not (1 <= port_int <= 65535):
        raise ConfigurationError(
            f"Configuration error: MYSQL_PORT must be between 1 and 65535. Received: {port_int}"
        )
    return port_int


def parse_bounded_float(
    val: Any,
    var_name: str,
    min_val: float,
    max_val: float,
) -> float:
    """Parse and validate a bounded float value."""
    try:
        f = float(str(val).strip())
    except (ValueError, TypeError):
        raise ConfigurationError(
            f"Configuration error: {var_name} must be a valid float. Received: '{val}'"
        )
    if not (min_val <= f <= max_val):
        raise ConfigurationError(
            f"Configuration error: {var_name} must be between {min_val} and {max_val}. Received: {f}"
        )
    return f


def parse_bounded_int(
    val: Any,
    var_name: str,
    min_val: int,
    max_val: int,
) -> int:
    """Parse and validate a bounded integer value."""
    try:
        i = int(str(val).strip())
    except (ValueError, TypeError):
        raise ConfigurationError(
            f"Configuration error: {var_name} must be a valid integer. Received: '{val}'"
        )
    if not (min_val <= i <= max_val):
        raise ConfigurationError(
            f"Configuration error: {var_name} must be between {min_val} and {max_val}. Received: {i}"
        )
    return i


def validate_chart_output_dir(raw_dir: str | Path, base_dir: Path = BASE_DIR) -> str:
    """Validate that CHART_OUTPUT_DIR is strictly project-relative and contained in project root."""
    raw_str = str(raw_dir).strip()
    if not raw_str:
        raise ConfigurationError("CHART_OUTPUT_DIR cannot be empty.")
    lower = raw_str.lower()
    if lower.startswith(("http://", "https://", "file://", "\\\\")):
        raise ConfigurationError(
            f"SECURITY VIOLATION: Remote or UNC path not allowed for CHART_OUTPUT_DIR: '{raw_str}'"
        )
    # Check for path traversal components
    normalized_parts = raw_str.replace("\\", "/").split("/")
    if ".." in normalized_parts:
        raise ConfigurationError(
            f"SECURITY VIOLATION: Path traversal '..' not allowed in CHART_OUTPUT_DIR: '{raw_str}'"
        )
    candidate = Path(raw_str)
    if candidate.is_absolute() or raw_str.startswith(("/", "\\")):
        raise ConfigurationError(
            f"SECURITY VIOLATION: Absolute paths not allowed for CHART_OUTPUT_DIR: '{raw_str}'"
        )
    resolved_base = base_dir.resolve()
    resolved_target = (resolved_base / candidate).resolve()
    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise ConfigurationError(
            f"SECURITY VIOLATION: CHART_OUTPUT_DIR must reside within project root: '{raw_str}'"
        )
    return raw_str


def validate_report_output_dir(raw_dir: str | Path, base_dir: Path = BASE_DIR) -> str:
    """Validate that REPORT_OUTPUT_DIR is strictly project-relative and contained in project root."""
    raw_str = str(raw_dir).strip()
    if not raw_str:
        raise ConfigurationError("REPORT_OUTPUT_DIR cannot be empty.")
    lower = raw_str.lower()
    if lower.startswith(("http://", "https://", "file://", "\\\\")):
        raise ConfigurationError(
            f"SECURITY VIOLATION: Remote or UNC path not allowed for REPORT_OUTPUT_DIR: '{raw_str}'"
        )
    # Check for path traversal components
    normalized_parts = raw_str.replace("\\", "/").split("/")
    if ".." in normalized_parts:
        raise ConfigurationError(
            f"SECURITY VIOLATION: Path traversal '..' not allowed in REPORT_OUTPUT_DIR: '{raw_str}'"
        )
    candidate = Path(raw_str)
    if candidate.is_absolute() or raw_str.startswith(("/", "\\")):
        raise ConfigurationError(
            f"SECURITY VIOLATION: Absolute paths not allowed for REPORT_OUTPUT_DIR: '{raw_str}'"
        )
    resolved_base = base_dir.resolve()
    resolved_target = (resolved_base / candidate).resolve()
    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise ConfigurationError(
            f"SECURITY VIOLATION: REPORT_OUTPUT_DIR must reside within project root: '{raw_str}'"
        )
    return raw_str


def validate_ollama_host(host_url: str, local_only: bool) -> str:
    """Validate Ollama host against local-only cybersecurity policy."""
    raw = host_url.strip()
    parsed = urlparse(raw)

    if local_only:
        # Scheme must be http (remote APIs typically use https)
        if parsed.scheme.lower() != "http":
            raise ConfigurationError(
                f"SECURITY VIOLATION: When LOCAL_ONLY=true, OLLAMA_HOST must use http scheme "
                f"(e.g. http://127.0.0.1 or http://localhost). Received: '{raw}'"
            )

        hostname = (parsed.hostname or "").lower()
        if hostname not in ALLOWED_LOCAL_HOSTNAMES:
            raise ConfigurationError(
                f"SECURITY VIOLATION: LOCAL_ONLY policy violation. "
                f"External or LAN endpoint '{raw}' is strictly blocked. "
                f"OLLAMA_HOST may only use loopback addresses (http://127.0.0.1 or http://localhost)."
            )

    return raw


def load_settings(
    env: Mapping[str, Any] | None = None,
    dotenv_path: Path | str | None = None,
) -> Settings:
    """Load, validate, and return application runtime settings.

    Args:
        env: Optional mapping of environment variables. If None, loads from .env
             and os.environ.
        dotenv_path: Optional path to a specific .env file to load.

    Returns:
        Settings: Validated, immutable settings object.

    Raises:
        ConfigurationError: If any required variable is missing, empty, or violates policy.
    """
    if env is None:
        target_path = Path(dotenv_path) if dotenv_path else ENV_PATH
        if target_path.exists():
            load_dotenv(dotenv_path=target_path, override=True if dotenv_path else False)
        source_env = dict(os.environ)
    else:
        source_env = dict(env)

    # 1. Prohibited cloud API keys detection
    for key in PROHIBITED_CLOUD_KEYS:
        val = source_env.get(key)
        if val is not None and str(val).strip():
            raise ConfigurationError(
                f"SECURITY VIOLATION: Prohibited cloud API key '{key}' detected in environment. "
                f"When LOCAL_ONLY=true, external metered LLM APIs are strictly forbidden."
            )

    # 2. Check existence of all required variables
    for var in REQUIRED_VARS:
        if var not in source_env or source_env[var] is None:
            raise ConfigurationError(
                f"Configuration error: Missing required environment variable '{var}'."
            )

    # 3. Parse boolean LOCAL_ONLY
    local_only = parse_bool(source_env["LOCAL_ONLY"])

    # 4. Check for empty or whitespace-only variables (never reveal secrets in errors)
    for var in REQUIRED_VARS:
        val_str = str(source_env[var]).strip()
        if not val_str:
            raise ConfigurationError(
                f"Configuration error: Environment variable '{var}' cannot be empty or whitespace."
            )

    # 5. Parse MYSQL_PORT as integer
    mysql_port = parse_port(source_env["MYSQL_PORT"])

    # 6. Validate OLLAMA_HOST against local-only policy
    ollama_host = validate_ollama_host(str(source_env["OLLAMA_HOST"]), local_only)

    # 7. Optional parameters with defaults
    max_query_rows = int(source_env.get("MAX_QUERY_ROWS", 1000))
    query_timeout_seconds = float(source_env.get("QUERY_TIMEOUT_SECONDS", 5.0))
    audit_log_path = str(source_env.get("AUDIT_LOG_PATH", "logs/audit.jsonl"))
    app_env = str(source_env.get("APP_ENV", "development"))

    mysql_import_user = str(source_env.get("MYSQL_IMPORT_USER", "dataset_importer")).strip()
    mysql_import_password = str(source_env.get("MYSQL_IMPORT_PASSWORD", ""))
    mysql_import_db = str(source_env.get("MYSQL_IMPORT_DB", "managed_import")).strip()

    # 8. Ollama operational configuration with bounds validation
    ollama_timeout_seconds = parse_bounded_float(
        source_env.get("OLLAMA_TIMEOUT_SECONDS", 30.0),
        "OLLAMA_TIMEOUT_SECONDS",
        0.001,
        600.0,
    )
    ollama_temperature = parse_bounded_float(
        source_env.get("OLLAMA_TEMPERATURE", 0.1),
        "OLLAMA_TEMPERATURE",
        0.0,
        1.0,
    )
    ollama_num_predict = parse_bounded_int(
        source_env.get("OLLAMA_NUM_PREDICT", 2048),
        "OLLAMA_NUM_PREDICT",
        1,
        8192,
    )
    max_messages = parse_bounded_int(
        source_env.get("MAX_MESSAGES", 50),
        "MAX_MESSAGES",
        1,
        200,
    )
    max_message_chars = parse_bounded_int(
        source_env.get("MAX_MESSAGE_CHARS", 32000),
        "MAX_MESSAGE_CHARS",
        1,
        100000,
    )
    max_total_prompt_chars = parse_bounded_int(
        source_env.get("MAX_TOTAL_PROMPT_CHARS", 128000),
        "MAX_TOTAL_PROMPT_CHARS",
        1,
        500000,
    )
    if max_total_prompt_chars < max_message_chars:
        raise ConfigurationError(
            f"Configuration error: MAX_TOTAL_PROMPT_CHARS ({max_total_prompt_chars}) "
            f"cannot be less than MAX_MESSAGE_CHARS ({max_message_chars})."
        )

    # 9. Step 27: Cache configuration with bounds validation
    cache_enabled = parse_bool(source_env.get("CACHE_ENABLED", True))
    cache_ttl_seconds = parse_bounded_int(
        source_env.get("CACHE_TTL_SECONDS", 30),
        "CACHE_TTL_SECONDS",
        1,
        300,
    )
    cache_max_entries = parse_bounded_int(
        source_env.get("CACHE_MAX_ENTRIES", 128),
        "CACHE_MAX_ENTRIES",
        1,
        1000,
    )
    cache_max_entry_bytes = parse_bounded_int(
        source_env.get("CACHE_MAX_ENTRY_BYTES", 1_000_000),
        "CACHE_MAX_ENTRY_BYTES",
        1,
        10_000_000,
    )

    # 10. Step 28: Chart configuration with bounds validation and path containment
    chart_enabled = parse_bool(source_env.get("CHART_ENABLED", True))
    chart_max_points = parse_bounded_int(
        source_env.get("CHART_MAX_POINTS", 500),
        "CHART_MAX_POINTS",
        1,
        5000,
    )
    chart_max_categories = parse_bounded_int(
        source_env.get("CHART_MAX_CATEGORIES", 30),
        "CHART_MAX_CATEGORIES",
        1,
        100,
    )
    chart_dpi = parse_bounded_int(
        source_env.get("CHART_DPI", 120),
        "CHART_DPI",
        72,
        200,
    )
    chart_output_dir = validate_chart_output_dir(
        source_env.get("CHART_OUTPUT_DIR", "reports/charts")
    )

    # Step 29: Deterministic Report Settings
    report_enabled = parse_bool(source_env.get("REPORT_ENABLED", True))
    report_output_dir = validate_report_output_dir(
        source_env.get("REPORT_OUTPUT_DIR", "reports/pdfs")
    )
    report_max_evidence_refs = parse_bounded_int(
        source_env.get("REPORT_MAX_EVIDENCE_REFS", 8),
        "REPORT_MAX_EVIDENCE_REFS",
        1,
        20,
    )
    report_max_charts = parse_bounded_int(
        source_env.get("REPORT_MAX_CHARTS", 5),
        "REPORT_MAX_CHARTS",
        0,
        10,
    )
    report_max_table_rows = parse_bounded_int(
        source_env.get("REPORT_MAX_TABLE_ROWS", 50),
        "REPORT_MAX_TABLE_ROWS",
        1,
        200,
    )
    report_max_table_columns = parse_bounded_int(
        source_env.get("REPORT_MAX_TABLE_COLUMNS", 12),
        "REPORT_MAX_TABLE_COLUMNS",
        1,
        50,
    )
    report_max_total_table_rows = parse_bounded_int(
        source_env.get("REPORT_MAX_TOTAL_TABLE_ROWS", 100),
        "REPORT_MAX_TOTAL_TABLE_ROWS",
        1,
        500,
    )
    report_max_pages = parse_bounded_int(
        source_env.get("REPORT_MAX_PAGES", 20),
        "REPORT_MAX_PAGES",
        1,
        100,
    )
    report_max_file_bytes = parse_bounded_int(
        source_env.get("REPORT_MAX_FILE_BYTES", 10_000_000),
        "REPORT_MAX_FILE_BYTES",
        100_000,
        50_000_000,
    )
    report_max_summary_chars = parse_bounded_int(
        source_env.get("REPORT_MAX_SUMMARY_CHARS", 2000),
        "REPORT_MAX_SUMMARY_CHARS",
        100,
        10_000,
    )
    report_max_cell_chars = parse_bounded_int(
        source_env.get("REPORT_MAX_CELL_CHARS", 300),
        "REPORT_MAX_CELL_CHARS",
        10,
        2000,
    )

    return Settings(
        local_only=local_only,
        ollama_host=ollama_host,
        ollama_model=str(source_env["OLLAMA_MODEL"]).strip(),
        mysql_host=str(source_env["MYSQL_HOST"]).strip(),
        mysql_port=mysql_port,
        mysql_business_db=str(source_env["MYSQL_BUSINESS_DB"]).strip(),
        mysql_agent_db=str(source_env["MYSQL_AGENT_DB"]).strip(),
        mysql_read_user=str(source_env["MYSQL_READ_USER"]).strip(),
        mysql_read_password=str(source_env["MYSQL_READ_PASSWORD"]),
        mysql_app_user=str(source_env["MYSQL_APP_USER"]).strip(),
        mysql_app_password=str(source_env["MYSQL_APP_PASSWORD"]),
        mysql_import_user=mysql_import_user,
        mysql_import_password=mysql_import_password,
        mysql_import_db=mysql_import_db,
        max_query_rows=max_query_rows,
        query_timeout_seconds=query_timeout_seconds,
        audit_log_path=audit_log_path,
        app_env=app_env,
        ollama_timeout_seconds=ollama_timeout_seconds,
        ollama_temperature=ollama_temperature,
        ollama_num_predict=ollama_num_predict,
        max_messages=max_messages,
        max_message_chars=max_message_chars,
        max_total_prompt_chars=max_total_prompt_chars,
        cache_enabled=cache_enabled,
        cache_ttl_seconds=cache_ttl_seconds,
        cache_max_entries=cache_max_entries,
        cache_max_entry_bytes=cache_max_entry_bytes,
        chart_enabled=chart_enabled,
        chart_max_points=chart_max_points,
        chart_max_categories=chart_max_categories,
        chart_dpi=chart_dpi,
        chart_output_dir=chart_output_dir,
        report_enabled=report_enabled,
        report_output_dir=report_output_dir,
        report_max_evidence_refs=report_max_evidence_refs,
        report_max_charts=report_max_charts,
        report_max_table_rows=report_max_table_rows,
        report_max_table_columns=report_max_table_columns,
        report_max_total_table_rows=report_max_total_table_rows,
        report_max_pages=report_max_pages,
        report_max_file_bytes=report_max_file_bytes,
        report_max_summary_chars=report_max_summary_chars,
        report_max_cell_chars=report_max_cell_chars,
    )


# Provide module-level settings instance when environment is already configured
settings: Settings | None = None
try:
    settings = load_settings()
except ConfigurationError:
    settings = None


def get_settings(dotenv_path: Path | str | None = None) -> Settings:
    """Retrieve active validated settings, loading them if necessary."""
    global settings
    if dotenv_path is not None:
        return load_settings(dotenv_path=dotenv_path)
    if settings is None:
        settings = load_settings()
    return settings

