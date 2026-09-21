"""Central Single-Agent Controller implementing the D.A.T.A. loop.

Orchestrates deterministic tools through an explicit Python state machine:
- D: Diagnose (intent classification, constraint extraction, schema relevance, knowledge retrieval)
- A: Assemble (bounded context formatting, strict prompt delimiter isolation)
- T: Take Action (query local Ollama model for structured JSON action proposals, execute deterministic tools)
- A: Assess (grounding verification, typed evidence gate, secondary numeric verification)

Security & Architectural Guarantees:
- Exactly ONE runtime AI agent class: BusinessIntelligenceAgent.
- Local Ollama only (via tools/ollama_tool.py and tools/runtime_guard.py); zero cloud LLMs.
- Strict Pydantic v2 action contracts; model emits passive proposals only, zero direct execution authority.
- SQL queries validated via SQL firewall (tools/sql_tool.py) before execution by bi_reader.
- Calculations governed by deterministic Python mathematics (tools/analytics_tool.py).
- Run-scoped in-memory EvidenceLedger; model may read bounded representations, Python owns mutation.
- Step 24 audit integration; failures fail closed with AUDIT_PERSISTENCE_FAILED.
- Completely database-agnostic core: zero hardcoded table/column names.
- Zero direct database client library imports; zero shell execution calls.
"""

from __future__ import annotations

import copy
import datetime
import decimal
from decimal import Decimal, InvalidOperation
import json
import logging
import re
from pathlib import Path
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
import uuid

from pydantic import TypeAdapter, ValidationError

from config import BASE_DIR, Settings, get_settings
from database.database_context import (
    ActiveDatabaseContext,
    compute_schema_fingerprint,
    validate_database_identifier,
)
from models.schemas import (
    ActionTypeEnum,
    AgentRunResult,
    AnalyticsRequestContract,
    AnalyticsResultContract,
    AnswerActionProposal,
    AskClarificationActionProposal,
    AuditEventContract,
    ChartArtifactContract,
    ChartRequestContract,
    DatabaseContextContract,
    ErrorContract,
    KnowledgeEvidenceContract,
    LocalModelResponseContract,
    ModelActionEnvelope,
    ModelActionProposal,
    ProposeSQLActionProposal,
    QueryResultContract,
    RelevantSchemaContract,
    ReportArtifactContract,
    ReportNarrativeContract,
    ReportRequestContract,
    RequestAnalyticsActionProposal,
    RequestChartActionProposal,
    RequestReportActionProposal,
    RunRecordContract,
    SQLProposalContract,
    SQLValidationContract,
    AnswerabilityEnum,
    QuestionUnderstandingContract,
    SchemaSufficiencyStatus,
    StructuredAnalyticalPlan,
)
from tools.analytics_tool import (
    AnalyticsError,
    AnalyticsRequest,
    AnalyticsResult,
    DerivedMetricRequest,
    run_analytics,
)
from tools.audit_tool import (
    AuditServiceError,
    check_audit_schema_ready,
    complete_run,
    create_session,
    fail_run,
    record_event,
    start_run,
)
from tools.cache_tool import VerifiedResultCache
from tools.chart_tool import ChartGenerationError, generate_chart
from tools.knowledge_tool import (
    DEFAULT_TOP_K,
    format_knowledge_context,
    retrieve_knowledge,
)
from tools.ollama_tool import (
    LocalModelResponse,
    OllamaAdapter,
    OllamaAdapterError,
)
from tools.question_understanding import (
    build_structured_analytical_plan,
    understand_question,
    validate_analytical_plan,
)
from tools.report_tool import (
    ReportGenerationError,
    _build_default_narrative,
    generate_pdf_report,
)
from tools.runtime_guard import validate_local_runtime
from tools.schema_relevance_tool import (
    check_schema_sufficiency,
    expand_schema_subset,
    format_schema_subset,
    select_relevant_schema,
)
from tools.schema_tool import get_schema_snapshot
from tools.semantic_catalog import (
    DatabaseSemanticCatalog,
    build_semantic_catalog,
)
from tools.sql_tool import (
    QueryResult,
    SQLExecutionError,
    SQLValidationError,
    SQLValidationResult,
    execute_safe_query,
    validate_sql,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# ACTION LIMITS & BUDGETS
# ==============================================================================

MAX_AGENT_ACTIONS: int = 8
MAX_MODEL_FORMAT_RETRIES: int = 1
MAX_SQL_PROPOSAL_RETRIES: int = 2
MAX_ASSESS_RETRIES: int = 2
MAX_CHART_PROPOSAL_RETRIES: int = 1
MAX_REPORT_PROPOSAL_RETRIES: int = 1

# ==============================================================================
# PROHIBITED MODEL ACTIONS (TRUST BOUNDARY ENFORCEMENT)
# ==============================================================================

PROHIBITED_ACTION_NAMES: frozenset[str] = frozenset({
    "EXECUTE_SQL",
    "EXECUTE_QUERY",
    "RUN_SQL",
    "RUN_PYTHON",
    "RUN_SHELL",
    "WRITE_DATABASE",
    # Step 28: Prohibited execution / file / plotting actions
    "GENERATE_PYTHON",
    "EXECUTE_CHART",
    "RUN_MATPLOTLIB",
    "SAVE_FILE",
    "WRITE_FILE",
    "OPEN_FILE",
    "CHART_CODE",
    # Step 29: Prohibited execution / report actions
    "GENERATE_PDF",
    "EXECUTE_REPORT",
    "RUN_REPORTLAB",
    "EXPORT_PDF",
    "RENDER_REPORT",
})

# ==============================================================================
# SQL REASON CODE CLASSIFICATION (MANDATORY CORRECTION 1)
# ==============================================================================

# Security-policy rejections: DO NOT RETRY, terminate safely / block
SECURITY_SQL_REJECTION_CODES: frozenset[str] = frozenset({
    "NON_SELECT_STATEMENT",
    "PROHIBITED_OPERATION",
    "PROHIBITED_SCHEMA",
    "MULTIPLE_STATEMENTS",
    "COMMENT_NOT_ALLOWED",
    "UNSAFE_LIMIT",
    "MAX_ROWS_EXCEEDED",
})

# Correctable proposal errors: Allowed to enter the SQL repair loop
CORRECTABLE_SQL_REJECTION_CODES: frozenset[str] = frozenset({
    "UNKNOWN_TABLE",
    "UNKNOWN_COLUMN",
    "AMBIGUOUS_COLUMN",
    "SELECT_STAR_NOT_ALLOWED",
    "SQL_PARSE_ERROR",
    "EMPTY_STATEMENT",
})


# ==============================================================================
# DELIMITER-SAFE PROMPT ENCODING HELPERS (STEP 25 HARDENING)
# ==============================================================================

def escape_untrusted_prompt_text(text: str) -> str:
    """Safely escape XML delimiters in untrusted text so it cannot break prompt structure.

    Converts XML special characters:
      '&' -> '&amp;'
      '<' -> '&lt;'
      '>' -> '&gt;'
      '"' -> '&quot;'
      "'" -> '&apos;'

    Guarantees that user questions, database cell values, and knowledge rows
    cannot inject structural tags like </USER_QUESTION>, </VERIFIED_EVIDENCE>,
    or <SYSTEM_RULES>.
    """
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def serialize_untrusted_data(data: Any) -> str:
    """Deterministically serialize untrusted data to JSON with escaped delimiters.

    Serializes to JSON and escapes angle brackets ('<' to '\\u003c', '>' to '\\u003e')
    so that structured payloads (evidence rows, action histories) cannot inject
    structural prompt tags.
    """
    raw_json = json.dumps(data, default=str, ensure_ascii=False)
    return raw_json.replace("<", "\\u003c").replace(">", "\\u003e")


# ==============================================================================
# EXCEPTIONS
# ==============================================================================

class AgentExecutionError(Exception):
    """Base exception for agent execution errors."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class AuditPersistenceFailure(AgentExecutionError):
    """Raised when an audit record cannot be written to agent_system (fails closed)."""
    pass


# ==============================================================================
# RUN-SCOPED EVIDENCE LEDGER (MANDATORY CORRECTIONS 3 & 5)
# ==============================================================================

@dataclass(frozen=True)
class EvidenceItem:
    """Immutable entry in the run-scoped evidence ledger."""

    evidence_id: str
    run_id: str
    source_type: str  # "KNOWLEDGE", "QUERY_RESULT", "ANALYTICS_RESULT"
    data: Any  # KnowledgeEvidenceContract | QueryResultContract | AnalyticsResultContract
    summary: dict[str, Any]


class EvidenceLedger:
    """Run-scoped in-memory ledger storing verified empirical facts and calculations.

    Python exclusively owns ledger mutation.
    The model receives a bounded, read-only representation to read and cite.
    """

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._items: dict[str, EvidenceItem] = {}
        self._e_counter: int = 1
        self._k_counter: int = 1

    def add_knowledge(self, item: KnowledgeEvidenceContract) -> str:
        kid = f"K{self._k_counter}"
        self._k_counter += 1
        summary = {
            "source_type": "KNOWLEDGE",
            "knowledge_id": item.knowledge_id,
            "topic": item.topic,
            "statement": item.statement,
        }
        self._items[kid] = EvidenceItem(
            evidence_id=kid,
            run_id=self.run_id,
            source_type="KNOWLEDGE",
            data=item,
            summary=summary,
        )
        return kid

    def add_query_result(self, qr: QueryResultContract) -> str:
        eid = f"E{self._e_counter}"
        self._e_counter += 1
        sample_rows = qr.rows[:5] if qr.rows else []
        summary = {
            "source_type": "QUERY_RESULT",
            "row_count": qr.row_count,
            "columns": list(qr.columns),
            "sample_rows": sample_rows,
            "validated_sql": qr.validated_sql,
        }
        self._items[eid] = EvidenceItem(
            evidence_id=eid,
            run_id=self.run_id,
            source_type="QUERY_RESULT",
            data=qr,
            summary=summary,
        )
        return eid

    def add_analytics_result(self, ar: AnalyticsResultContract) -> str:
        eid = f"E{self._e_counter}"
        self._e_counter += 1
        summary = {
            "source_type": "ANALYTICS_RESULT",
            "operation": ar.operation,
            "formula": ar.formula,
            "result": ar.result,
            "columns_used": ar.columns_used,
            "provenance": ar.provenance,
        }
        self._items[eid] = EvidenceItem(
            evidence_id=eid,
            run_id=self.run_id,
            source_type="ANALYTICS_RESULT",
            data=ar,
            summary=summary,
        )
        return eid

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def all_items(self) -> list[EvidenceItem]:
        return list(self._items.values())

    def contains(self, evidence_id: str) -> bool:
        return evidence_id in self._items

    def format_for_prompt(self, max_chars: int = 16000) -> str:
        """Format bounded read-only representation for the LLM prompt."""
        if not self._items:
            return "(No evidence gathered yet)"
        lines: list[str] = []
        for eid, item in self._items.items():
            lines.append(f"{eid}:")
            for k, v in item.summary.items():
                if isinstance(v, (list, dict)):
                    val_str = serialize_untrusted_data(v)
                    if len(val_str) > 1000:
                        val_str = val_str[:1000] + "... (truncated)"
                    lines.append(f"  {k}: {val_str}")
                else:
                    lines.append(f"  {k}: {escape_untrusted_prompt_text(str(v))}")
            lines.append("")
        rendered = "\n".join(lines).strip()
        if len(rendered) > max_chars:
            rendered = rendered[:max_chars] + "\n... (truncated to fit prompt limit)"
        return rendered


# ==============================================================================
# SECONDARY NUMERIC SCANNER (PRECISION-AWARE & TYPE-AWARE)
# ==============================================================================

@dataclass(frozen=True)
class ExtractedNumber:
    token: str
    value: Decimal
    is_percentage: bool
    is_integer: bool
    is_id_candidate: bool
    is_date_or_year: bool


@dataclass
class VerifiedEvidenceCatalog:
    """Type-aware catalog of numbers from verified evidence items."""
    exact_integers: set[int]
    decimals: set[Decimal]
    decimal_precisions: dict[Decimal, int]
    percentages: set[Decimal]
    percentage_precisions: dict[Decimal, int]
    id_values: set[Any]


_NUM_PATTERN = re.compile(r"[-+]?[\$€£]?\d+(?:,\d{3})*(?:\.\d+)?(?:[eE][+-]?\d+)?%?")
_DATE_ISO_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_DATE_SLASH_PATTERN = re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b")
_DATE_MONTH_PATTERN = re.compile(
    r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,\s*\d{4})?\b",
    re.IGNORECASE,
)
_ID_PREFIX_PATTERN = re.compile(r"(?i)\b(?:id|#|pk|fk|code|num|no|ref|item|record|row|entity)\s*[:#]?\s*$")


def _extract_numbers_from_text(text: str) -> list[ExtractedNumber]:
    """Extract candidate metric numbers from response text with type and semantic classification."""
    results: list[ExtractedNumber] = []
    if not text:
        return results

    # Record date spans to avoid treating calendar dates as free metric claims
    date_spans = [m.span() for m in _DATE_ISO_PATTERN.finditer(text)]
    date_spans.extend([m.span() for m in _DATE_SLASH_PATTERN.finditer(text)])
    date_spans.extend([m.span() for m in _DATE_MONTH_PATTERN.finditer(text)])

    for match in _NUM_PATTERN.finditer(text):
        token = match.group(0)
        start, end = match.span()

        # Skip hyphenated alphanumeric codes (e.g. 'NC-17', 'UTF-8', 'item-1')
        if (token.startswith("-") or token.startswith("+")) and start > 0 and text[start - 1].isalnum():
            continue

        # Check if inside a date span
        in_date = any(d_start <= start and end <= d_end for d_start, d_end in date_spans)

        cleaned = token.replace("$", "").replace("€", "").replace("£", "").replace(",", "").strip()
        is_pct = cleaned.endswith("%")
        if is_pct:
            cleaned = cleaned[:-1]

        try:
            val = Decimal(cleaned)
        except (InvalidOperation, ValueError):
            continue

        is_int = (val == val.to_integral_value()) and ("." not in cleaned or val == int(val))

        # Check for year (1900 - 2099)
        is_year = False
        if is_int and not is_pct and not in_date:
            if 1900 <= int(val) <= 2099:
                prefix = text[max(0, start - 15) : start].lower()
                if any(w in prefix for w in ("in ", "year ", "since ", "during ", "for ", "from ")):
                    is_year = True
                elif not any(c in token for c in ("$", "€", "£", "%")):
                    is_year = True

        is_date_or_year = in_date or is_year

        # Check if preceded by an ID label
        prefix_id = text[max(0, start - 20) : start]
        is_id_candidate = bool(_ID_PREFIX_PATTERN.search(prefix_id))

        # Check if structural enumeration / list bullet (e.g. "1. ", "2) ")
        if is_int and not is_pct and not is_date_or_year and not is_id_candidate:
            if start == 0 or text[start - 1] in "\n\r":
                if end < len(text) and text[end : end + 2] in (". ", ") "):
                    if 1 <= int(val) <= 20:
                        is_id_candidate = True  # treat structural bullet as non-metric

        results.append(
            ExtractedNumber(
                token=token,
                value=val,
                is_percentage=is_pct,
                is_integer=is_int,
                is_id_candidate=is_id_candidate,
                is_date_or_year=is_date_or_year,
            )
        )
    return results


def _register_value_in_catalog(val: Any, catalog: VerifiedEvidenceCatalog, is_ratio: bool = False) -> None:
    if val is None:
        return
    if isinstance(val, (int, bool)) and not isinstance(val, bool):
        catalog.exact_integers.add(int(val))
        catalog.decimals.add(Decimal(val))
        catalog.decimal_precisions[Decimal(val)] = 0
        if is_ratio:
            catalog.percentages.add(Decimal(val) * Decimal("100"))
    elif isinstance(val, (float, Decimal)):
        try:
            d = Decimal(str(val))
            catalog.decimals.add(d)
            prec = abs(d.as_tuple().exponent) if d.as_tuple().exponent < 0 else 0
            catalog.decimal_precisions[d] = prec
            if d == d.to_integral_value():
                catalog.exact_integers.add(int(d))
            if is_ratio:
                pct = d * Decimal("100")
                catalog.percentages.add(pct)
                catalog.percentage_precisions[pct] = prec
        except (InvalidOperation, ValueError):
            pass
    elif isinstance(val, dict):
        for v in val.values():
            _register_value_in_catalog(v, catalog, is_ratio=is_ratio)
    elif isinstance(val, (list, tuple)):
        for elem in val:
            _register_value_in_catalog(elem, catalog, is_ratio=is_ratio)


def _build_verified_evidence_catalog(evidence_items: Sequence[EvidenceItem]) -> VerifiedEvidenceCatalog:
    """Build type-aware verified number catalog from cited evidence items."""
    catalog = VerifiedEvidenceCatalog(
        exact_integers=set(),
        decimals=set(),
        decimal_precisions={},
        percentages=set(),
        percentage_precisions={},
        id_values=set(),
    )
    for item in evidence_items:
        if item.source_type == "QUERY_RESULT" and isinstance(item.data, QueryResultContract):
            catalog.exact_integers.add(int(item.data.row_count))
            catalog.decimals.add(Decimal(item.data.row_count))

            for row in item.data.rows:
                for col, v in row.items():
                    col_lower = col.lower()
                    if col_lower.endswith("_id") or col_lower == "id":
                        catalog.id_values.add(v)
                        catalog.id_values.add(str(v))
                        continue
                    is_pct_col = any(p in col_lower for p in ("pct", "percent", "percentage", "rate"))
                    _register_value_in_catalog(v, catalog, is_ratio=is_pct_col)
                    if is_pct_col and v is not None:
                        try:
                            d = Decimal(str(v))
                            catalog.percentages.add(d)
                            prec = abs(d.as_tuple().exponent) if d.as_tuple().exponent < 0 else 0
                            catalog.percentage_precisions[d] = prec
                        except Exception:
                            pass

        elif item.source_type == "ANALYTICS_RESULT" and isinstance(item.data, AnalyticsResultContract):
            catalog.exact_integers.add(int(item.data.rows_used))
            catalog.exact_integers.add(int(item.data.row_count_input))
            catalog.decimals.add(Decimal(item.data.rows_used))
            catalog.decimals.add(Decimal(item.data.row_count_input))

            op = item.data.operation.lower()
            is_ratio = op == "ratio" or op.endswith("_rate")
            _register_value_in_catalog(item.data.result, catalog, is_ratio=is_ratio)

    if 0 in catalog.exact_integers:
        catalog.percentages.add(Decimal("0"))
    return catalog


def _verify_candidate_number(
    candidate: ExtractedNumber,
    catalog: VerifiedEvidenceCatalog,
) -> tuple[bool, str]:
    """Precision-aware and type-aware verification of a candidate metric number.

    Rules:
    - Dates / calendar years: skipped (not classified as business metric claims)
    - IDs: skipped (not treated as business metric claims)
    - COUNT / integer: requires exact integer match in catalog.exact_integers or decimal equivalent
    - 100 vs 101: strictly rejected
    - Decimal / currency: formatting equivalents ($1,250.50, 1250.5) match via Decimal equality or declared precision
    - Percent / rate: matches catalog.percentages with declared precision
    """
    # 1. Dates / calendar years
    if candidate.is_date_or_year:
        return True, "DATE_OR_YEAR"

    # 2. IDs
    if candidate.is_id_candidate:
        return True, "ID_CANDIDATE"
    if str(candidate.value) in catalog.id_values or (candidate.is_integer and int(candidate.value) in catalog.id_values):
        return True, "ID_VALUE"

    # 3. Percentages
    if candidate.is_percentage:
        if candidate.value in catalog.percentages:
            return True, "PERCENTAGE_EXACT"
        for pct_val, prec in catalog.percentage_precisions.items():
            if prec > 0:
                try:
                    quantized = pct_val.quantize(Decimal(10) ** -prec)
                    if candidate.value == quantized:
                        return True, "PERCENTAGE_QUANTIZED"
                except Exception:
                    pass
            if candidate.is_integer:
                try:
                    if candidate.value == round(pct_val, 0):
                        return True, "PERCENTAGE_ROUNDED_INT"
                except Exception:
                    pass
        return False, f"Percentage {candidate.token} is not grounded in evidence."

    # 4. Integer / COUNT
    if candidate.is_integer:
        int_v = int(candidate.value)
        if int_v in catalog.exact_integers:
            return True, "EXACT_INTEGER_MATCH"
        if candidate.value in catalog.decimals:
            return True, "DECIMAL_EQUIVALENCE"
        return False, f"Integer/count {candidate.token} does not match verified evidence."

    # 5. Decimal / Currency
    if candidate.value in catalog.decimals:
        return True, "DECIMAL_EXACT_MATCH"

    for dec_val, prec in catalog.decimal_precisions.items():
        if prec > 0:
            try:
                cand_prec = abs(candidate.value.as_tuple().exponent)
                if cand_prec <= prec:
                    quantized_ev = dec_val.quantize(Decimal(10) ** -cand_prec)
                    if candidate.value == quantized_ev:
                        return True, "DECIMAL_QUANTIZED_MATCH"
            except Exception:
                pass

    return False, f"Decimal value {candidate.token} is not grounded in evidence."


# ==============================================================================
# CENTRAL BUSINESS INTELLIGENCE AGENT (ONE AGENT ONLY)
# ==============================================================================

class BusinessIntelligenceAgent:
    """The single runtime Business Intelligence Agent orchestrating the D.A.T.A. loop.

    Enforces deterministic state transitions:
    DIAGNOSE -> ASSEMBLE -> TAKE_ACTION -> ASSESS -> COMPLETE/NEEDS_CLARIFICATION/FAILED.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        ollama_adapter: OllamaAdapter | None = None,
        result_cache: VerifiedResultCache | None = None,
    ) -> None:
        """Initialize the agent with configuration and mandatory local runtime guard."""
        self._settings = settings or get_settings()

        # Enforce local runtime guard before proceeding
        guard = validate_local_runtime(settings=self._settings)
        if not guard.is_safe:
            raise AgentExecutionError(
                code="LOCAL_RUNTIME_REJECTED",
                message=f"Local runtime security policy violation: {guard.error_message}",
                details={"reason_code": guard.reason_code},
            )

        # Local Ollama adapter
        if ollama_adapter is not None:
            self._ollama = ollama_adapter
        else:
            self._ollama = OllamaAdapter(settings=self._settings)

        # Step 27: Verified-result cache (no global mutable singleton)
        if result_cache is not None:
            self._cache: VerifiedResultCache | None = result_cache
        elif self._settings.cache_enabled:
            self._cache = VerifiedResultCache(
                max_entries=self._settings.cache_max_entries,
                max_entry_bytes=self._settings.cache_max_entry_bytes,
                ttl_seconds=self._settings.cache_ttl_seconds,
            )
        else:
            self._cache = None

        self._action_adapter = TypeAdapter(ModelActionProposal)
        self.last_ledger: EvidenceLedger | None = None

    # --------------------------------------------------------------------------
    # AUDIT INTEGRATION HELPERS (FAIL-CLOSED)
    # --------------------------------------------------------------------------

    def _safe_record_event(
        self,
        run_id: str,
        event_type: str,
        component: str,
        status: str,
        **kwargs: Any,
    ) -> AuditEventContract:
        """Record an operational audit event. FAILS CLOSED on persistence error."""
        try:
            return record_event(
                run_id=run_id,
                event_type=event_type,
                component=component,
                status=status,
                custom_settings=self._settings,
                **kwargs,
            )
        except Exception as exc:
            logger.error("Critical audit failure on event '%s': %s", event_type, exc)
            raise AuditPersistenceFailure(
                code="AUDIT_PERSISTENCE_FAILED",
                message=f"Critical failure recording audit event '{event_type}': {exc}",
            ) from exc

    def _safe_complete_run(
        self,
        run_id: str,
        status: str = "SUCCESS",
        execution_time_ms: float | None = None,
        row_count: int | None = None,
        assessment_passed: bool | None = True,
        sql_generated: str | None = None,
        sql_valid: bool = False,
    ) -> RunRecordContract:
        """Mark run as complete. FAILS CLOSED on persistence error."""
        try:
            return complete_run(
                run_id=run_id,
                status=status,
                execution_time_ms=int(execution_time_ms) if execution_time_ms is not None else None,
                row_count=row_count or 0,
                assessment_passed=assessment_passed,
                sql_generated=sql_generated,
                sql_valid=bool(sql_valid),
                custom_settings=self._settings,
            )
        except Exception as exc:
            logger.error("Critical audit failure completing run '%s': %s", run_id, exc)
            raise AuditPersistenceFailure(
                code="AUDIT_PERSISTENCE_FAILED",
                message=f"Critical failure completing run '{run_id}': {exc}",
            ) from exc

    def _safe_fail_run(
        self,
        run_id: str,
        reason_code: str,
        error_message: str | None = None,
        execution_time_ms: float | None = None,
    ) -> RunRecordContract | None:
        """Safely record run failure without throwing an unhandled exception."""
        try:
            return fail_run(
                run_id=run_id,
                reason_code=reason_code,
                error_message=error_message,
                execution_time_ms=execution_time_ms,
                custom_settings=self._settings,
            )
        except Exception as exc:
            logger.error("Could not record run failure in database: %s", exc)
            return None

    # --------------------------------------------------------------------------
    # PUBLIC ENTRYPOINT
    # --------------------------------------------------------------------------

    def run(
        self,
        question: str,
        database_context: ActiveDatabaseContext | None = None,
        session_id: str | None = None,
        force_refresh: bool = False,
    ) -> AgentRunResult:
        """Execute the D.A.T.A. business intelligence loop for a user question.

        Args:
            question: Business query in natural language.
            database_context: Active business database context.
            session_id: Optional existing session ID.
            force_refresh: If True, bypass cache and execute fresh SQL.
                          Python/application-controlled only; model cannot set this.

        Returns:
            Auditable AgentRunResult with typed execution outcome and evidence refs.
        """
        start_time = time.perf_counter()
        clean_question = question.strip() if question else ""
        if not clean_question:
            return AgentRunResult(
                run_id=str(uuid.uuid4()),
                session_id=session_id or str(uuid.uuid4()),
                status="FAILED",
                error=ErrorContract(code="EMPTY_QUESTION", message="User question cannot be empty or whitespace."),
            )

        # 1. PRE-FLIGHT AUDIT READINESS CHECK
        try:
            audit_ready = check_audit_schema_ready(custom_settings=self._settings)
        except Exception as exc:
            audit_ready = False

        if not audit_ready:
            return AgentRunResult(
                run_id=str(uuid.uuid4()),
                session_id=session_id or str(uuid.uuid4()),
                status="FAILED",
                error=ErrorContract(
                    code="AUDIT_SCHEMA_NOT_READY",
                    message="Agent audit schema in agent_system is not provisioned or ready.",
                ),
            )

        # 2. RESOLVE DATABASE CONTEXT
        if database_context is None:
            # Build default context from settings
            try:
                db_name = validate_database_identifier(self._settings.mysql_business_db)
                database_context = ActiveDatabaseContext(
                    context_id=f"ctx_{db_name}",
                    display_name=db_name,
                    database_name=db_name,
                    host=self._settings.mysql_host,
                    port=self._settings.mysql_port,
                )
            except Exception as exc:
                return AgentRunResult(
                    run_id=str(uuid.uuid4()),
                    session_id=session_id or str(uuid.uuid4()),
                    status="FAILED",
                    error=ErrorContract(code="INVALID_DATABASE_CONTEXT", message=f"Cannot initialize database context: {exc}"),
                )

        # Compute schema fingerprint if not present
        if not database_context.schema_fingerprint:
            try:
                snapshot = get_schema_snapshot(custom_settings=self._settings, database_context=database_context)
                fingerprint = compute_schema_fingerprint(snapshot)
                object.__setattr__(database_context, "schema_fingerprint", fingerprint)
                if database_context.approved_objects is None:
                    raw_objects = [
                        str(obj["object_name"]).strip()
                        for obj in snapshot.get("objects", [])
                        if obj.get("object_name")
                    ]
                    if raw_objects:
                        object.__setattr__(database_context, "approved_objects", tuple(sorted(raw_objects)))
            except Exception as exc:
                logger.warning("Could not pre-compute schema fingerprint: %s", exc)

        # 3. SESSION & RUN INITIALIZATION
        db_contract = DatabaseContextContract.from_database_context(database_context)
        active_session_id = session_id
        if not active_session_id:
            try:
                session_record = create_session(custom_settings=self._settings)
                active_session_id = session_record.session_id
            except Exception as exc:
                return AgentRunResult(
                    run_id=str(uuid.uuid4()),
                    session_id=str(uuid.uuid4()),
                    status="FAILED",
                    error=ErrorContract(code="AUDIT_PERSISTENCE_FAILED", message=f"Failed to create session: {exc}"),
                )

        try:
            run_record = start_run(
                session_id=active_session_id,
                question=clean_question,
                database_context=db_contract,
                custom_settings=self._settings,
            )
            run_id = run_record.run_id
        except Exception as exc:
            return AgentRunResult(
                run_id=str(uuid.uuid4()),
                session_id=active_session_id,
                status="FAILED",
                error=ErrorContract(code="AUDIT_PERSISTENCE_FAILED", message=f"Failed to start run: {exc}"),
            )

        # Initialize run-scoped evidence ledger and loop state
        ledger = EvidenceLedger(run_id=run_id)
        self.last_ledger = ledger
        action_count = 0
        format_retries = 0
        sql_retries = 0
        assess_retries = 0
        chart_retries = 0
        chart_counter = 0
        report_retries = 0
        pending_report_request: ReportRequestContract | None = None

        executed_sqls: list[str] = []
        analytics_operations: list[str] = []
        chart_artifacts: list[ChartArtifactContract] = []
        report_artifacts: list[ReportArtifactContract] = []
        action_history: list[dict[str, str]] = []
        run_cache_hit: bool = False

        try:
            # ==================================================================
            # PHASE 1: DIAGNOSE (D)
            # ==================================================================
            self._safe_record_event(
                run_id=run_id,
                event_type="DIAGNOSE",
                component="agent",
                status="IN_PROGRESS",
                evidence_summary="Diagnosing intent, discovering relevant schema, and retrieving business knowledge.",
            )

            # 1. Build / Retrieve Semantic Catalog (Tier 1 cached)
            try:
                semantic_catalog = build_semantic_catalog(
                    database_context=database_context,
                )
            except Exception as exc:
                logger.warning("Failed to build semantic catalog: %s", exc)
                semantic_catalog = None

            # 2. Generalized Question Understanding
            understanding = None
            if semantic_catalog is not None:
                try:
                    understanding = understand_question(
                        question=clean_question,
                        catalog=semantic_catalog,
                    )
                except Exception as exc:
                    logger.warning("Question understanding failed: %s", exc)
                    understanding = None

            # 3. Security Boundary Gate
            if understanding and understanding.answerability == AnswerabilityEnum.SECURITY_BLOCKED:
                self._safe_record_event(
                    run_id=run_id,
                    event_type="SECURITY_BLOCKED",
                    component="agent",
                    status="REJECTED",
                    reason_code="SECURITY_POLICY_VIOLATION",
                    evidence_summary="Question rejected by security policy.",
                )
                self._safe_fail_run(
                    run_id=run_id,
                    reason_code="SECURITY_POLICY_VIOLATION",
                    error_message="Question rejected by security policy.",
                )
                return AgentRunResult(
                    run_id=run_id,
                    session_id=active_session_id,
                    status="SECURITY_BLOCKED",
                    error=ErrorContract(
                        code="SECURITY_POLICY_VIOLATION",
                        message="Query violates security policy or contains prohibited statements.",
                    ),
                )

            # A. Select Relevant Schema progressively
            schema_expansion_rounds = 0
            try:
                rel_schema_raw = select_relevant_schema(
                    query=clean_question,
                    database_context=database_context,
                    semantic_catalog=semantic_catalog,
                )
                # Check Schema Sufficiency & Progressive Expansion if needed
                if understanding and semantic_catalog:
                    suff_status, suff_reasons = check_schema_sufficiency(
                        understanding=understanding,
                        relevant_snapshot=rel_schema_raw,
                        catalog=semantic_catalog,
                    )
                    if suff_status == SchemaSufficiencyStatus.MORE_SCHEMA_REQUIRED and suff_reasons:
                        rel_schema_raw = expand_schema_subset(
                            current_snapshot=rel_schema_raw,
                            additional_tables=suff_reasons,
                            database_context=database_context,
                            catalog=semantic_catalog,
                            max_objects=12,
                        )
                        schema_expansion_rounds += 1
                rel_schema_text = format_schema_subset(rel_schema_raw, max_chars=8000)
            except Exception as exc:
                rel_schema_text = "No schema could be discovered."

            # Observability: schema chars & token estimation
            schema_context_chars = len(rel_schema_text)
            schema_context_tokens_est = schema_context_chars // 4

            # B. Retrieve Knowledge
            try:
                raw_knowledge = retrieve_knowledge(query=clean_question, top_k=DEFAULT_TOP_K)
                knowledge_text = format_knowledge_context(raw_knowledge, max_chars=4000)
                for k in raw_knowledge:
                    item_contract = KnowledgeEvidenceContract.from_knowledge_row(k)
                    ledger.add_knowledge(item_contract)
            except Exception as exc:
                knowledge_text = "No relevant knowledge available."

            # Construct Structured Analytical Plan
            analytical_plan = None
            if understanding and semantic_catalog:
                try:
                    analytical_plan = build_structured_analytical_plan(
                        understanding=understanding,
                        relevant_snapshot=rel_schema_raw,
                        catalog=semantic_catalog,
                    )
                    is_plan_valid, plan_errors = validate_analytical_plan(
                        plan=analytical_plan,
                        catalog=semantic_catalog,
                        database_context=database_context,
                    )
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="QUESTION_UNDERSTANDING",
                        component="question_understanding_engine",
                        status="SUCCESS" if is_plan_valid else "WARNING",
                        evidence_summary=(
                            f"Intent: {understanding.primary_intent} | Ops: {','.join(understanding.analytical_operations)} | "
                            f"Answerability: {understanding.answerability.value} | Sufficiency: {analytical_plan.sufficiency_status.value} | "
                            f"Schema Chars: {schema_context_chars} (Est Tokens: {schema_context_tokens_est}) | Expansion: {schema_expansion_rounds}"
                        ),
                    )
                except Exception as exc:
                    logger.warning("Failed to construct structured analytical plan: %s", exc)

            # Determine if question is empirical (requires database facts)
            is_empirical = self._is_empirical_question(clean_question)

            # ==================================================================
            # D.A.T.A. ACTION LOOP
            # ==================================================================
            while action_count < MAX_AGENT_ACTIONS:
                action_count += 1

                # PHASE 2: ASSEMBLE (A)
                prompt = self._assemble_prompt(
                    question=clean_question,
                    schema_text=rel_schema_text,
                    knowledge_text=knowledge_text,
                    ledger=ledger,
                    action_history=action_history,
                    chart_artifacts=chart_artifacts,
                    report_artifacts=report_artifacts,
                    analytical_plan=analytical_plan,
                )

                # PHASE 3: TAKE ACTION (T) - Query Local Ollama Model
                t_model_start = time.perf_counter()
                try:
                    model_res = self._ollama.chat(
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0,
                    )
                    t_model_dur = (time.perf_counter() - t_model_start) * 1000.0
                except OllamaAdapterError as exc:
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="LOCAL_MODEL_INFERENCE",
                        component="ollama_adapter",
                        status="FAILED",
                        reason_code=exc.reason_code,
                        evidence_summary=f"Model call failed: {exc}",
                    )
                    self._safe_fail_run(run_id=run_id, reason_code=exc.reason_code, error_message=str(exc))
                    return AgentRunResult(
                        run_id=run_id,
                        session_id=active_session_id,
                        status="FAILED",
                        error=ErrorContract(code=exc.reason_code, message=str(exc)),
                    )

                # Record model inference event
                self._safe_record_event(
                    run_id=run_id,
                    event_type="LOCAL_MODEL_INFERENCE",
                    component="ollama_adapter",
                    status="SUCCESS",
                    model_name=model_res.model,
                    prompt_tokens=model_res.prompt_tokens,
                    completion_tokens=model_res.completion_tokens,
                    duration_ms=int(t_model_dur),
                )

                # Parse JSON proposal from model output
                proposal = self._parse_action_proposal(model_res.content)
                if proposal is None:
                    # Model emitted invalid JSON or schema violation
                    if format_retries < MAX_MODEL_FORMAT_RETRIES:
                        format_retries += 1
                        action_history.append({
                            "type": "FORMAT_ERROR",
                            "message": "Your output was not valid JSON conforming to the allowed action schema. Emit only a valid JSON action object.",
                        })
                        continue
                    else:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="ERROR",
                            component="agent",
                            status="FAILED",
                            reason_code="MODEL_INVALID_FORMAT",
                            evidence_summary="Model failed to produce valid JSON action proposal after retry.",
                        )
                        self._safe_fail_run(
                            run_id=run_id,
                            reason_code="MODEL_INVALID_FORMAT",
                            error_message="Model failed to produce a valid JSON action proposal.",
                        )
                        return AgentRunResult(
                            run_id=run_id,
                            session_id=active_session_id,
                            status="FAILED",
                            error=ErrorContract(
                                code="MODEL_INVALID_FORMAT",
                                message="Model output could not be parsed into a valid action proposal.",
                            ),
                        )

                # Dispatch Action Proposal
                # --------------------------------------------------------------
                # CASE 1: ASK_CLARIFICATION
                # --------------------------------------------------------------
                if isinstance(proposal, AskClarificationActionProposal):
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="ASSESSMENT",
                        component="agent",
                        status="NEEDS_REVIEW",
                        evidence_summary=f"Agent requested clarification: {proposal.clarification_question}",
                    )
                    elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                    self._safe_complete_run(
                        run_id=run_id,
                        status="NEEDS_REVIEW",
                        execution_time_ms=elapsed_ms,
                        row_count=0,
                        assessment_passed=True,
                    )
                    return AgentRunResult(
                        run_id=run_id,
                        session_id=active_session_id,
                        status="NEEDS_CLARIFICATION",
                        clarification_question=proposal.clarification_question,
                        clarification_options=proposal.options,
                        execution_time_ms=elapsed_ms,
                    )

                # --------------------------------------------------------------
                # CASE 2: PROPOSE_SQL
                # --------------------------------------------------------------
                if isinstance(proposal, ProposeSQLActionProposal):
                    sql_str = proposal.sql_proposal.sql
                    # Audit proposed SQL
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="PROPOSE_SQL",
                        component="agent",
                        status="SUCCESS",
                        proposed_sql=sql_str,
                        evidence_summary=proposal.purpose or "Model proposed SQL query.",
                    )

                    # Validate with Step 18 deterministic firewall
                    val_res = validate_sql(
                        sql=sql_str,
                        custom_settings=self._settings,
                        database_context=database_context,
                    )

                    if not val_res.is_valid:
                        reason = val_res.reason_code or "SQL_VALIDATION_ERROR"
                        # Mandatory Correction 1: Classify SQL rejections before retry
                        if reason in SECURITY_SQL_REJECTION_CODES:
                            # Security-policy rejection: Audit, do not retry, terminate safely
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="SQL_VALIDATION",
                                component="firewall",
                                status="SECURITY_BLOCKED",
                                reason_code=reason,
                                proposed_sql=sql_str,
                                evidence_summary=f"Security rejection: {val_res.error_message}",
                            )
                            self._safe_fail_run(
                                run_id=run_id,
                                reason_code=reason,
                                error_message=val_res.error_message,
                            )
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="SECURITY_BLOCKED",
                                database_context_id=database_context.context_id,
                                database_name=database_context.database_name,
                                schema_fingerprint=database_context.schema_fingerprint,
                                executed_sql=executed_sqls,
                                error=ErrorContract(
                                    code=reason,
                                    message=f"SQL blocked by firewall security policy: {val_res.error_message}",
                                ),
                                execution_time_ms=elapsed_ms,
                            )
                        elif reason in CORRECTABLE_SQL_REJECTION_CODES:
                            # Correctable proposal error: Can retry if budget allows
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="SQL_VALIDATION",
                                component="firewall",
                                status="REJECTED",
                                reason_code=reason,
                                proposed_sql=sql_str,
                                evidence_summary=f"Correctable SQL error: {val_res.error_message}",
                            )
                            if sql_retries < MAX_SQL_PROPOSAL_RETRIES:
                                sql_retries += 1
                                action_history.append({
                                    "type": "SQL_ERROR",
                                    "sql": sql_str,
                                    "reason": reason,
                                    "message": f"SQL validation rejected [{reason}]: {val_res.error_message}. Please adjust query syntax, table, or column names.",
                                })
                                continue
                            else:
                                self._safe_fail_run(
                                    run_id=run_id,
                                    reason_code="SQL_REPAIR_EXHAUSTED",
                                    error_message=f"Exhausted SQL repair retries. Last error: {val_res.error_message}",
                                )
                                elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                                return AgentRunResult(
                                    run_id=run_id,
                                    session_id=active_session_id,
                                    status="FAILED",
                                    error=ErrorContract(
                                        code="SQL_REPAIR_EXHAUSTED",
                                        message=f"SQL proposal repair attempts exhausted: {val_res.error_message}",
                                    ),
                                    execution_time_ms=elapsed_ms,
                                )
                        else:
                            # Unknown or generic validation error
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="SQL_VALIDATION",
                                component="firewall",
                                status="REJECTED",
                                reason_code=reason,
                                proposed_sql=sql_str,
                                evidence_summary=val_res.error_message,
                            )
                            self._safe_fail_run(run_id=run_id, reason_code=reason, error_message=val_res.error_message)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=reason, message=val_res.error_message or "SQL validation failed."),
                            )

                    # SQL is VALID! Audit validation success
                    validated_sql = val_res.validated_sql or sql_str
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="SQL_VALIDATION",
                        component="firewall",
                        status="SUCCESS",
                        proposed_sql=sql_str,
                        validated_sql=validated_sql,
                    )

                    # -------------------------------------------------------
                    # STEP 27: CACHE LOOKUP (after firewall, never before)
                    # -------------------------------------------------------
                    cache_hit_used = False
                    approved_fp: str | None = None
                    if self._cache is not None:
                        try:
                            approved_fp = VerifiedResultCache.compute_approved_objects_fingerprint(
                                database_context.approved_objects
                            )
                            # Audit cache lookup
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="CACHE_LOOKUP",
                                component="cache",
                                status="IN_PROGRESS",
                                validated_sql=validated_sql,
                            )

                            if not force_refresh:
                                cache_hit = self._cache.get(
                                    session_id=active_session_id,
                                    database_context_id=database_context.context_id,
                                    schema_fingerprint=database_context.schema_fingerprint,
                                    approved_objects_fingerprint=approved_fp,
                                    validated_sql=validated_sql,
                                )
                            else:
                                cache_hit = None

                            if cache_hit is not None:
                                # CACHE HIT: use verified cached result
                                qr_contract = cache_hit.result
                                eid = ledger.add_query_result(qr_contract)
                                # Do NOT append to executed_sqls (no MySQL executed this run)
                                # Do NOT emit SQL_EXECUTION audit event

                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="CACHE_HIT",
                                    component="cache",
                                    status="SUCCESS",
                                    validated_sql=validated_sql,
                                    evidence_summary=(
                                        f"Cache hit (age={cache_hit.age_seconds:.1f}s, "
                                        f"key={cache_hit.key_digest[:12]}). "
                                        f"Evidence {eid} from cached verified result."
                                    ),
                                )
                                action_history.append({
                                    "type": "SQL_SUCCESS",
                                    "sql": validated_sql,
                                    "evidence_id": eid,
                                    "row_count": str(qr_contract.row_count),
                                    "cache": "HIT",
                                })
                                cache_hit_used = True
                                run_cache_hit = True
                            else:
                                # CACHE MISS
                                miss_reason = "FORCE_REFRESH" if force_refresh else "MISS"
                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="CACHE_MISS",
                                    component="cache",
                                    status="IN_PROGRESS",
                                    validated_sql=validated_sql,
                                    reason_code=miss_reason,
                                )
                        except Exception as cache_exc:
                            # Cache internal error: safe fallback to fresh execution
                            logger.warning("Cache lookup error (safe fallback): %s", cache_exc)
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="CACHE_BYPASS",
                                component="cache",
                                status="IN_PROGRESS",
                                reason_code="CACHE_INTERNAL_ERROR",
                                evidence_summary=f"Cache error, falling back to fresh query: {type(cache_exc).__name__}",
                            )

                    if cache_hit_used:
                        continue

                    # Execute query via least-privileged bi_reader (CACHE MISS path)
                    t_exec_start = time.perf_counter()
                    try:
                        raw_qr = execute_safe_query(
                            sql=validated_sql,
                            custom_settings=self._settings,
                            database_context=database_context,
                        )
                        t_exec_dur = (time.perf_counter() - t_exec_start) * 1000.0
                    except (SQLValidationError, SQLExecutionError) as exc:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="SQL_EXECUTION",
                            component="mysql_adapter",
                            status="FAILED",
                            validated_sql=validated_sql,
                            evidence_summary=f"SQL execution error: {exc}",
                        )
                        self._safe_fail_run(run_id=run_id, reason_code="SQL_EXECUTION_ERROR", error_message=str(exc))
                        return AgentRunResult(
                            run_id=run_id,
                            session_id=active_session_id,
                            status="FAILED",
                            error=ErrorContract(code="SQL_EXECUTION_ERROR", message=str(exc)),
                        )

                    # Convert to typed QueryResultContract and add to EvidenceLedger
                    qr_contract = QueryResultContract.from_query_result(raw_qr)
                    eid = ledger.add_query_result(qr_contract)
                    executed_sqls.append(validated_sql)

                    # Audit SQL execution success
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="SQL_EXECUTION",
                        component="mysql_adapter",
                        status="SUCCESS",
                        validated_sql=validated_sql,
                        executed_sql=validated_sql,
                        duration_ms=int(t_exec_dur),
                        evidence_summary=f"Query returned {qr_contract.row_count} rows. Stored in evidence ledger as {eid}.",
                    )

                    # -------------------------------------------------------
                    # STEP 27: CACHE STORE (after successful execution)
                    # -------------------------------------------------------
                    if self._cache is not None and approved_fp is not None:
                        try:
                            store_result = self._cache.put(
                                session_id=active_session_id,
                                database_context_id=database_context.context_id,
                                schema_fingerprint=database_context.schema_fingerprint,
                                approved_objects_fingerprint=approved_fp,
                                validated_sql=validated_sql,
                                result=qr_contract,
                            )
                            if store_result.stored:
                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="CACHE_STORE",
                                    component="cache",
                                    status="SUCCESS",
                                    validated_sql=validated_sql,
                                    evidence_summary=f"Cached verified result (key={store_result.key_digest[:12]}).",
                                )
                            elif store_result.bypass_reason:
                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="CACHE_BYPASS",
                                    component="cache",
                                    status="IN_PROGRESS",
                                    validated_sql=validated_sql,
                                    reason_code=store_result.bypass_reason,
                                )
                        except Exception as cache_exc:
                            # Cache store error: log but do not fail the run
                            logger.warning("Cache store error (non-fatal): %s", cache_exc)

                    action_history.append({
                        "type": "SQL_SUCCESS",
                        "sql": validated_sql,
                        "evidence_id": eid,
                        "row_count": str(qr_contract.row_count),
                    })
                    continue

                # --------------------------------------------------------------
                # CASE 3: REQUEST_ANALYTICS
                # --------------------------------------------------------------
                if isinstance(proposal, RequestAnalyticsActionProposal):
                    req_contract = proposal.analytics_request
                    # Find matching QueryResult in EvidenceLedger
                    target_item = None
                    for itm in reversed(ledger.all_items()):
                        if itm.source_type == "QUERY_RESULT" and isinstance(itm.data, QueryResultContract):
                            target_item = itm
                            break

                    if target_item is None:
                        action_history.append({
                            "type": "ANALYTICS_ERROR",
                            "message": "Cannot perform analytics: No QueryResult data is available in the evidence ledger. Propose a SQL query first.",
                        })
                        continue

                    target_qr = QueryResult(
                        original_sql=target_item.data.original_sql,
                        validated_sql=target_item.data.validated_sql,
                        columns=list(target_item.data.columns),
                        rows=[dict(r) for r in target_item.data.rows],
                        row_count=target_item.data.row_count,
                        execution_status=target_item.data.status,
                        execution_time_ms=target_item.data.execution_time_ms or 0.0,
                    )

                    derived_req = None
                    if req_contract.derived_metric:
                        derived_req = DerivedMetricRequest(
                            operation=req_contract.derived_metric.operation,
                            left_column=req_contract.derived_metric.left_column,
                            right_column=req_contract.derived_metric.right_column,
                            output_name=req_contract.derived_metric.output_name,
                        )

                    analytics_req = AnalyticsRequest(
                        operation=req_contract.operation,
                        value_column=req_contract.value_column,
                        numerator_column=req_contract.numerator_column,
                        denominator_column=req_contract.denominator_column,
                        group_by=req_contract.group_by,
                        date_column=req_contract.date_column,
                        period=req_contract.period,
                        top_n=req_contract.top_n,
                        sort_direction=req_contract.sort_direction,
                        precision=req_contract.precision,
                        derived_metric=derived_req,
                    )

                    try:
                        raw_ar = run_analytics(
                            query_result=target_qr,
                            request=analytics_req,
                            custom_settings=self._settings,
                        )
                        ar_contract = AnalyticsResultContract.from_analytics_result(raw_ar)
                    except AnalyticsError as exc:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="ANALYTICS_EXECUTION",
                            component="analytics_engine",
                            status="FAILED",
                            reason_code=exc.reason_code,
                            analytics_operation=req_contract.operation,
                            evidence_summary=f"Analytics error: {exc.message}",
                        )
                        action_history.append({
                            "type": "ANALYTICS_ERROR",
                            "message": f"Analytics calculation error [{exc.reason_code}]: {exc.message}",
                        })
                        continue

                    # Add to EvidenceLedger
                    eid = ledger.add_analytics_result(ar_contract)
                    analytics_operations.append(ar_contract.operation)

                    # Audit analytics execution success
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="ANALYTICS_EXECUTION",
                        component="analytics_engine",
                        status="SUCCESS",
                        analytics_operation=ar_contract.operation,
                        formula=ar_contract.formula,
                        evidence_summary=f"Calculated result: {ar_contract.result}. Stored in evidence ledger as {eid}.",
                    )

                    action_history.append({
                        "type": "ANALYTICS_SUCCESS",
                        "operation": ar_contract.operation,
                        "evidence_id": eid,
                        "result": str(ar_contract.result),
                    })
                    continue

                # --------------------------------------------------------------
                # CASE 3B: REQUEST_CHART (STEP 28: DETERMINISTIC CHART GENERATION)
                # --------------------------------------------------------------
                if isinstance(proposal, RequestChartActionProposal):
                    chart_req = proposal.chart_request
                    src_ref = chart_req.source_evidence_ref.strip()

                    # Avoid redundant duplicate chart generation for the same evidence in the same run
                    existing_chart = next((c for c in chart_artifacts if src_ref in c.source_evidence_refs and c.chart_type == chart_req.chart_type.value), None)
                    if existing_chart:
                        action_history.append({
                            "type": "CHART_NOTICE",
                            "message": f"Chart {existing_chart.chart_id} ({existing_chart.chart_type}) for evidence {src_ref} has ALREADY been rendered at '{existing_chart.relative_path}'. Do NOT request another chart. You MUST now proceed to ANSWER_FROM_EVIDENCE.",
                        })
                        continue

                    # Audit CHART_REQUEST
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="CHART_REQUEST",
                        component="chart_tool",
                        status="IN_PROGRESS",
                        evidence_summary=f"Model requested {chart_req.chart_type.value} chart using evidence {src_ref}.",
                    )

                    # Hardening Correction 8 & 16: Validate source evidence exists in CURRENT run's ledger
                    target_item = ledger.get(src_ref)
                    if target_item is None or target_item.run_id != run_id or target_item.source_type not in ("QUERY_RESULT", "ANALYTICS_RESULT"):
                        reason = "CROSS_RUN_EVIDENCE" if (target_item and target_item.run_id != run_id) else "CHART_INVALID_EVIDENCE"
                        err_msg = f"Source evidence '{src_ref}' not found in current run or is not chartable."
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="CHART_VALIDATION",
                            component="chart_tool",
                            status="REJECTED",
                            reason_code=reason,
                            evidence_summary=err_msg,
                        )
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="CHART_REJECTED",
                            component="chart_tool",
                            status="REJECTED",
                            reason_code=reason,
                            evidence_summary=err_msg,
                        )
                        if reason == "CROSS_RUN_EVIDENCE":
                            self._safe_fail_run(run_id=run_id, reason_code=reason, error_message=err_msg)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="REJECTED",
                                error=ErrorContract(code=reason, message=err_msg),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                            )
                        if chart_retries < MAX_CHART_PROPOSAL_RETRIES:
                            chart_retries += 1
                            action_history.append({
                                "type": "CHART_ERROR",
                                "message": f"Chart validation error [{reason}]: {err_msg}. Propose SQL or reference valid current evidence.",
                            })
                            continue
                        else:
                            self._safe_fail_run(run_id=run_id, reason_code=reason, error_message=err_msg)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=reason, message=err_msg),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                            )

                    # Render chart deterministically
                    chart_counter += 1
                    cid = f"C{chart_counter}"
                    try:
                        artifact = generate_chart(
                            request=chart_req,
                            source_evidence=target_item.data,
                            settings=self._settings,
                            chart_id=cid,
                        )
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="CHART_VALIDATION",
                            component="chart_tool",
                            status="SUCCESS",
                            evidence_summary=f"Evidence {src_ref} validated for {chart_req.chart_type.value} chart.",
                        )
                    except ChartGenerationError as exc:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="CHART_VALIDATION",
                            component="chart_tool",
                            status="REJECTED",
                            reason_code=exc.reason_code,
                            evidence_summary=f"Chart validation failed: {exc.message}",
                        )
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="CHART_REJECTED",
                            component="chart_tool",
                            status="REJECTED",
                            reason_code=exc.reason_code,
                            evidence_summary=f"Chart generation failed: {exc.message}",
                        )
                        if chart_retries < MAX_CHART_PROPOSAL_RETRIES and exc.reason_code in ("CHART_FIELD_NOT_FOUND", "CHART_INCOMPATIBLE_TYPE"):
                            chart_retries += 1
                            action_history.append({
                                "type": "CHART_ERROR",
                                "message": f"Chart generation rejected [{exc.reason_code}]: {exc.message}. Please correct the field selection.",
                            })
                            continue
                        else:
                            self._safe_fail_run(run_id=run_id, reason_code=exc.reason_code, error_message=exc.message)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=exc.reason_code, message=exc.message),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                            )

                    chart_artifacts.append(artifact)
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="CHART_GENERATION",
                        component="chart_tool",
                        status="SUCCESS",
                        evidence_summary=f"Generated {artifact.chart_type} chart ({artifact.chart_id}) with {artifact.plotted_point_count} points at {artifact.relative_path}. SHA-256: {artifact.sha256[:16]}...",
                    )
                    action_history.append({
                        "type": "CHART_SUCCESS",
                        "chart_id": artifact.chart_id,
                        "chart_type": artifact.chart_type,
                        "path": artifact.relative_path,
                        "point_count": artifact.plotted_point_count,
                        "message": f"Successfully rendered {artifact.chart_type} chart ({artifact.chart_id}) at '{artifact.relative_path}'. Now emit ANSWER_FROM_EVIDENCE citing evidence {src_ref} and mentioning chart {artifact.chart_id}.",
                    })
                    continue

                # --------------------------------------------------------------
                # CASE 3C: REQUEST_REPORT (STEP 29: DETERMINISTIC PDF REPORT GENERATION)
                # --------------------------------------------------------------
                if isinstance(proposal, RequestReportActionProposal):
                    rpt_req = proposal.report_request

                    # Check feature enabled
                    if not self._settings.report_enabled:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_REQUEST",
                            component="report_tool",
                            status="IN_PROGRESS",
                            evidence_summary=f"Model requested report '{rpt_req.title}'.",
                        )
                        err_msg = "Report generation is disabled by configuration."
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_REJECTED",
                            component="report_tool",
                            status="REJECTED",
                            reason_code="REPORT_DISABLED",
                            evidence_summary=err_msg,
                        )
                        self._safe_fail_run(run_id=run_id, reason_code="REPORT_DISABLED", error_message=err_msg)
                        elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                        return AgentRunResult(
                            run_id=run_id,
                            session_id=active_session_id,
                            status="FAILED",
                            error=ErrorContract(code="REPORT_DISABLED", message=err_msg),
                            execution_time_ms=elapsed_ms,
                            chart_artifacts=chart_artifacts,
                            report_artifacts=report_artifacts,
                        )

                    # Hardening: Check if report was already requested or generated in this run
                    if pending_report_request is not None or report_artifacts:
                        action_history.append({
                            "type": "REPORT_NOTICE",
                            "message": "A report has ALREADY been requested/generated for this run. Do NOT request another report. You MUST now proceed to ANSWER_FROM_EVIDENCE.",
                        })
                        continue

                    # Audit REPORT_REQUEST
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="REPORT_REQUEST",
                        component="report_tool",
                        status="IN_PROGRESS",
                        evidence_summary=f"Model requested report '{rpt_req.title}' with {len(rpt_req.source_evidence_refs)} evidence refs and {len(rpt_req.source_chart_ids)} charts.",
                    )

                    # Lightweight precheck: Validate evidence references exist in CURRENT run's ledger
                    has_invalid_evidence = False
                    invalid_reason = "REPORT_INVALID_EVIDENCE"
                    invalid_msg = ""
                    for ref in rpt_req.source_evidence_refs:
                        target_item = ledger.get(ref)
                        if target_item is None or target_item.run_id != run_id or target_item.source_type not in ("QUERY_RESULT", "ANALYTICS_RESULT"):
                            has_invalid_evidence = True
                            if target_item and target_item.run_id != run_id:
                                invalid_reason = "CROSS_RUN_EVIDENCE"
                                invalid_msg = f"Evidence '{ref}' belongs to a different run."
                            else:
                                invalid_reason = "REPORT_INVALID_EVIDENCE"
                                invalid_msg = f"Source evidence '{ref}' not found in current run or is not empirical evidence."
                            break

                    if has_invalid_evidence:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_VALIDATION",
                            component="report_tool",
                            status="REJECTED",
                            reason_code=invalid_reason,
                            evidence_summary=invalid_msg,
                        )
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_REJECTED",
                            component="report_tool",
                            status="REJECTED",
                            reason_code=invalid_reason,
                            evidence_summary=invalid_msg,
                        )
                        if invalid_reason == "CROSS_RUN_EVIDENCE":
                            self._safe_fail_run(run_id=run_id, reason_code=invalid_reason, error_message=invalid_msg)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="REJECTED",
                                error=ErrorContract(code=invalid_reason, message=invalid_msg),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                                report_artifacts=report_artifacts,
                            )
                        if report_retries < MAX_REPORT_PROPOSAL_RETRIES:
                            report_retries += 1
                            action_history.append({
                                "type": "REPORT_ERROR",
                                "message": f"Report validation error [{invalid_reason}]: {invalid_msg}. Propose SQL or cite valid current evidence.",
                            })
                            continue
                        else:
                            self._safe_fail_run(run_id=run_id, reason_code=invalid_reason, error_message=invalid_msg)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=invalid_reason, message=invalid_msg),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                                report_artifacts=report_artifacts,
                            )

                    # Validate chart references exist in current run's chart_artifacts
                    has_missing_chart = False
                    missing_cid = ""
                    available_cids = {c.chart_id for c in chart_artifacts}
                    for cid in rpt_req.source_chart_ids:
                        if cid not in available_cids:
                            has_missing_chart = True
                            missing_cid = cid
                            break

                    if has_missing_chart:
                        reason = "REPORT_CHART_NOT_FOUND"
                        err_msg = f"Chart '{missing_cid}' was not found in active run artifacts."
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_VALIDATION",
                            component="report_tool",
                            status="REJECTED",
                            reason_code=reason,
                            evidence_summary=err_msg,
                        )
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_REJECTED",
                            component="report_tool",
                            status="REJECTED",
                            reason_code=reason,
                            evidence_summary=err_msg,
                        )
                        if report_retries < MAX_REPORT_PROPOSAL_RETRIES:
                            report_retries += 1
                            action_history.append({
                                "type": "REPORT_ERROR",
                                "message": f"Report validation error [{reason}]: {err_msg}. Request valid chart or omit.",
                            })
                            continue
                        else:
                            self._safe_fail_run(run_id=run_id, reason_code=reason, error_message=err_msg)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=reason, message=err_msg),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                                report_artifacts=report_artifacts,
                            )

                    # Hardening Correction 2: Register pending report request WITHOUT emitting REPORT_VALIDATION SUCCESS yet.
                    # Validation and generation occur ONLY after _assess_answer succeeds!
                    pending_report_request = rpt_req
                    action_history.append({
                        "type": "REPORT_REQUEST_ACCEPTED",
                        "message": f"Report request for '{rpt_req.title}' registered. You MUST now provide the final answer and executive summary narrative via ANSWER_FROM_EVIDENCE.",
                    })
                    continue

                # --------------------------------------------------------------
                # CASE 4: ANSWER_FROM_EVIDENCE (PHASE 4: ASSESS)
                # --------------------------------------------------------------
                if isinstance(proposal, AnswerActionProposal):
                    # Execute Evidence Assessment Gate
                    passed, reason_code, error_msg = self._assess_answer(
                        proposal=proposal,
                        ledger=ledger,
                        is_empirical=is_empirical,
                        current_run_id=run_id,
                        question=clean_question,
                    )

                    if not passed:
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="ASSESSMENT",
                            component="agent",
                            status="REJECTED",
                            reason_code=reason_code,
                            evidence_summary=f"Assessment failed: {error_msg}",
                        )
                        has_empirical = any(
                            itm.source_type in ("QUERY_RESULT", "ANALYTICS_RESULT")
                            for itm in ledger.all_items()
                        )
                        if assess_retries < MAX_ASSESS_RETRIES:
                            assess_retries += 1
                            if reason_code == "MISSING_EVIDENCE_REFS" or not has_empirical:
                                corrective_msg = (
                                    f"Proposed answer failed evidence assessment [{reason_code}]: {error_msg}. "
                                    "No verified database evidence is currently available in the ledger. "
                                    "A factual answer cannot be produced without evidence. "
                                    "You must either acquire evidence using PROPOSE_SQL on available schema tables, "
                                    "or ask for clarification using ASK_CLARIFICATION if the request is too broad."
                                )
                            else:
                                corrective_msg = (
                                    f"Proposed answer failed evidence assessment [{reason_code}]: {error_msg}. "
                                    "Ground your answer strictly in the evidence ledger."
                                )
                            action_history.append({
                                "type": "ASSESSMENT_REJECTION",
                                "reason": reason_code,
                                "message": corrective_msg,
                            })
                            continue
                        else:
                            is_broad_request = any(
                                w in clean_question.lower()
                                for w in ("schema", "database", "dataset", "insights", "overview", "tables", "patterns", "structure")
                            )
                            if is_broad_request and not has_empirical:
                                # Safe clarification fallback on empty evidence ledger (Section 1D)
                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="ASSESSMENT",
                                    component="agent",
                                    status="NEEDS_REVIEW",
                                    evidence_summary="Assessment retries exhausted on empty evidence ledger; returning safe clarification.",
                                )
                                elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                                self._safe_complete_run(
                                    run_id=run_id,
                                    status="NEEDS_REVIEW",
                                    execution_time_ms=elapsed_ms,
                                    row_count=0,
                                    assessment_passed=True,
                                )
                                return AgentRunResult(
                                    run_id=run_id,
                                    session_id=active_session_id,
                                    status="NEEDS_CLARIFICATION",
                                    clarification_question="Your request is broad and requires specific business evidence. Which aspect or table of the database would you like insights on?",
                                    clarification_options=["Overview of available tables", "Key summary metrics", "Specific record details"],
                                    execution_time_ms=elapsed_ms,
                                    chart_artifacts=chart_artifacts,
                                    report_artifacts=report_artifacts,
                                )
                            else:
                                self._safe_fail_run(
                                    run_id=run_id,
                                    reason_code="ASSESSMENT_FAILED",
                                    error_message=f"Assessment retries exhausted: {error_msg}",
                                )
                                elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                                return AgentRunResult(
                                    run_id=run_id,
                                    session_id=active_session_id,
                                    status="FAILED",
                                    error=ErrorContract(
                                        code="ASSESSMENT_FAILED",
                                        message=f"Final answer could not be verified against evidence ledger: {error_msg}",
                                    ),
                                    execution_time_ms=elapsed_ms,
                                    chart_artifacts=chart_artifacts,
                                    report_artifacts=report_artifacts,
                                )

                    # ASSESSMENT PASSED!
                    self._safe_record_event(
                        run_id=run_id,
                        event_type="ASSESSMENT",
                        component="agent",
                        status="SUCCESS",
                        evidence_summary=f"Answer passed evidence assessment. Cited: {proposal.evidence_refs}",
                    )

                    # If a report was requested, validate and generate it NOW (Hardening Correction 2)
                    if pending_report_request is not None:
                        # 1. Emit REPORT_VALIDATION SUCCESS
                        self._safe_record_event(
                            run_id=run_id,
                            event_type="REPORT_VALIDATION",
                            component="report_tool",
                            status="SUCCESS",
                            evidence_summary=f"Evidence assessed successfully; report parameters validated for '{pending_report_request.title}'.",
                        )

                        # 2. Build Evidence Ledger & Chart Maps
                        evidence_ledger_map = {
                            itm.evidence_id: itm.data
                            for itm in ledger.all_items()
                            if itm.source_type in ("QUERY_RESULT", "ANALYTICS_RESULT")
                        }
                        chart_map = {c.chart_id: c for c in chart_artifacts}

                        narrative = proposal.report_narrative or _build_default_narrative(
                            response_text=proposal.response_text,
                            max_summary_chars=self._settings.report_max_summary_chars,
                        )

                        # 3. Generate PDF Report deterministically
                        try:
                            rpt_id = f"RPT_{uuid.uuid4().hex[:8]}"
                            report_art = generate_pdf_report(
                                request=pending_report_request,
                                evidence_ledger=evidence_ledger_map,
                                chart_artifacts=chart_map,
                                narrative=narrative,
                                database_name=database_context.database_name,
                                schema_fingerprint=database_context.schema_fingerprint,
                                cfg=self._settings,
                                report_id=rpt_id,
                            )
                            report_artifacts.append(report_art)

                            # 4. Audit REPORT_GENERATION (Hardening Correction 10: Fail closed & delete PDF on audit error)
                            try:
                                self._safe_record_event(
                                    run_id=run_id,
                                    event_type="REPORT_GENERATION",
                                    component="report_tool",
                                    status="SUCCESS",
                                    evidence_summary=(
                                        f"Generated PDF report {report_art.report_id} ({report_art.page_count} pages, "
                                        f"{report_art.file_size_bytes} bytes) at {report_art.relative_path}. "
                                        f"External SHA-256: {report_art.sha256[:16]}..."
                                    ),
                                )
                            except Exception as audit_exc:
                                pdf_full_path = (Path(BASE_DIR) / report_art.relative_path).resolve()
                                pdf_full_path.unlink(missing_ok=True)
                                raise AuditPersistenceFailure(
                                    code="AUDIT_PERSISTENCE_FAILED",
                                    message=f"Critical failure recording REPORT_GENERATION audit event: {audit_exc}",
                                ) from audit_exc

                        except ReportGenerationError as rpt_exc:
                            self._safe_record_event(
                                run_id=run_id,
                                event_type="REPORT_REJECTED",
                                component="report_tool",
                                status="REJECTED",
                                reason_code=rpt_exc.reason_code,
                                evidence_summary=f"Report generation failed: {rpt_exc.message}",
                            )
                            self._safe_fail_run(run_id=run_id, reason_code=rpt_exc.reason_code, error_message=rpt_exc.message)
                            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                            return AgentRunResult(
                                run_id=run_id,
                                session_id=active_session_id,
                                status="FAILED",
                                error=ErrorContract(code=rpt_exc.reason_code, message=rpt_exc.message),
                                execution_time_ms=elapsed_ms,
                                chart_artifacts=chart_artifacts,
                                report_artifacts=report_artifacts,
                            )

                    elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
                    total_rows = sum(
                        itm.data.row_count
                        for itm in ledger.all_items()
                        if itm.source_type == "QUERY_RESULT" and isinstance(itm.data, QueryResultContract)
                    )

                    self._safe_complete_run(
                        run_id=run_id,
                        status="SUCCESS",
                        execution_time_ms=elapsed_ms,
                        row_count=total_rows,
                        assessment_passed=True,
                        sql_generated=executed_sqls[-1] if executed_sqls else None,
                        sql_valid=bool(executed_sqls),
                    )

                    return AgentRunResult(
                        run_id=run_id,
                        session_id=active_session_id,
                        status="SUCCESS",
                        answer=proposal.response_text,
                        database_context_id=database_context.context_id,
                        database_name=database_context.database_name,
                        schema_fingerprint=database_context.schema_fingerprint,
                        evidence_refs=proposal.evidence_refs,
                        executed_sql=executed_sqls,
                        analytics_used=analytics_operations,
                        execution_time_ms=elapsed_ms,
                        chart_artifacts=chart_artifacts,
                        report_artifacts=report_artifacts,
                        cache_hit=run_cache_hit,
                    )

            # Max actions exceeded
            self._safe_record_event(
                run_id=run_id,
                event_type="ERROR",
                component="agent",
                status="FAILED",
                reason_code="MAX_ACTIONS_EXCEEDED",
                evidence_summary=f"Agent exceeded maximum allowed actions ({MAX_AGENT_ACTIONS}).",
            )
            self._safe_fail_run(
                run_id=run_id,
                reason_code="MAX_ACTIONS_EXCEEDED",
                error_message=f"Loop terminated after reaching limit of {MAX_AGENT_ACTIONS} actions.",
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
            return AgentRunResult(
                run_id=run_id,
                session_id=active_session_id,
                status="FAILED",
                error=ErrorContract(
                    code="MAX_ACTIONS_EXCEEDED",
                    message=f"Agent exceeded maximum allowed action budget ({MAX_AGENT_ACTIONS}).",
                ),
                execution_time_ms=elapsed_ms,
                chart_artifacts=chart_artifacts,
                report_artifacts=report_artifacts,
            )

        except AuditPersistenceFailure as exc:
            # Re-raise or return fail-closed result
            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
            return AgentRunResult(
                run_id=run_id,
                session_id=active_session_id,
                status="FAILED",
                error=ErrorContract(code=exc.code, message=exc.message),
                execution_time_ms=elapsed_ms,
                chart_artifacts=chart_artifacts,
                report_artifacts=report_artifacts,
            )
        except Exception as exc:
            logger.exception("Unexpected exception in agent loop: %s", exc)
            self._safe_fail_run(run_id=run_id, reason_code="UNEXPECTED_ERROR", error_message=str(exc))
            elapsed_ms = int((time.perf_counter() - start_time) * 1000.0)
            return AgentRunResult(
                run_id=run_id,
                session_id=active_session_id,
                status="FAILED",
                error=ErrorContract(code="UNEXPECTED_ERROR", message=f"Internal agent error: {exc}"),
                execution_time_ms=elapsed_ms,
                chart_artifacts=chart_artifacts,
                report_artifacts=report_artifacts,
            )

    # --------------------------------------------------------------------------
    # ASSESS GATE & NUMERIC VERIFICATION (MANDATORY CORRECTIONS 2 & 5)
    # --------------------------------------------------------------------------

    def _assess_answer(
        self,
        proposal: AnswerActionProposal,
        ledger: EvidenceLedger,
        is_empirical: bool,
        current_run_id: str,
        question: str = "",
    ) -> tuple[bool, str, str]:
        """Verify the final answer against the current run's evidence ledger.

        Enforces:
        1. Strict evidence reference existence and run-scope (no cross-run / stale IDs).
        2. Empirical database question requirement (must cite QUERY_RESULT or ANALYTICS_RESULT).
        3. Primary typed evidence check.
        4. Secondary numeric consistency check (hallucination detection).
        """
        refs = list(proposal.evidence_refs)
        if not refs:
            empirical_ids = [
                itm.evidence_id
                for itm in ledger.all_items()
                if itm.source_type in ("QUERY_RESULT", "ANALYTICS_RESULT")
            ]
            if empirical_ids:
                refs = empirical_ids
                proposal.evidence_refs.extend(empirical_ids)
            else:
                return False, "MISSING_EVIDENCE_REFS", "Answer must cite at least one verified evidence reference."

        # 1. Strict evidence-reference validation
        cited_items: list[EvidenceItem] = []
        for ref in refs:
            itm = ledger.get(ref)
            if itm is None:
                return False, "NONEXISTENT_EVIDENCE_REF", f"Evidence reference '{ref}' does not exist in the current run's evidence ledger."
            if itm.run_id != current_run_id:
                return False, "CROSS_RUN_EVIDENCE_REJECTED", f"Evidence reference '{ref}' belongs to a different run."
            cited_items.append(itm)

        # 2. Empirical Database Question Check
        if is_empirical:
            has_empirical_evidence = any(
                itm.source_type in ("QUERY_RESULT", "ANALYTICS_RESULT")
                for itm in cited_items
            )
            if not has_empirical_evidence:
                return (
                    False,
                    "EMPIRICAL_EVIDENCE_REQUIRED",
                    "Factual database questions require verified QueryResult or AnalyticsResult evidence. Knowledge items alone cannot prove database facts.",
                )

        # 3. Secondary Numeric Consistency Check (Precision-Aware & Type-Aware)
        text_numbers = _extract_numbers_from_text(proposal.response_text)
        narrative_numbers = []
        if proposal.report_narrative:
            narr_parts = [
                proposal.report_narrative.direct_answer,
                *(kf.headline + " " + kf.body for kf in proposal.report_narrative.key_findings),
                *(m.displayed_value for m in proposal.report_narrative.key_metrics),
                *(df.heading + " " + df.body for df in proposal.report_narrative.detailed_findings),
            ]
            narrative_numbers = _extract_numbers_from_text(" ".join(narr_parts))

        all_numbers = text_numbers + narrative_numbers
        if all_numbers:
            catalog = _build_verified_evidence_catalog(cited_items)
            q_numbers = {n.value for n in _extract_numbers_from_text(question)} if question else set()
            has_evidence_metric = any(
                cand.value in catalog.exact_integers
                or cand.value in catalog.decimals
                or cand.value in catalog.percentages
                for cand in all_numbers
            )
            for cand in all_numbers:
                if cand.value in q_numbers and has_evidence_metric:
                    continue
                is_valid, msg = _verify_candidate_number(cand, catalog)
                if not is_valid:
                    return (
                        False,
                        "UNVERIFIED_NUMERIC_CLAIM",
                        f"Figure '{cand.token}' in the answer or narrative is not backed by the cited evidence: {msg}",
                    )

        return True, "SUCCESS", ""

    # --------------------------------------------------------------------------
    # PROMPT ASSEMBLY & DELIMITERS
    # --------------------------------------------------------------------------

    def _assemble_prompt(
        self,
        question: str,
        schema_text: str,
        knowledge_text: str,
        ledger: EvidenceLedger,
        action_history: list[dict[str, str]],
        chart_artifacts: list[ChartArtifactContract] | None = None,
        report_artifacts: list[ReportArtifactContract] | None = None,
        analytical_plan: StructuredAnalyticalPlan | None = None,
    ) -> str:
        """Assemble structured prompt with strict XML delimiter isolation."""
        history_lines = []
        for h in action_history:
            history_lines.append(f"- [{h.get('type')}]: {escape_untrusted_prompt_text(h.get('message', h.get('sql', '')))}")
        history_text = "\n".join(history_lines) if history_lines else "(No previous actions)"

        evidence_text = ledger.format_for_prompt(max_chars=12000)
        safe_schema = escape_untrusted_prompt_text(schema_text)
        safe_knowledge = escape_untrusted_prompt_text(knowledge_text)
        safe_question = escape_untrusted_prompt_text(question)

        plan_section = ""
        if analytical_plan is not None:
            u = analytical_plan.understanding
            ops_str = ", ".join(u.analytical_operations) if u.analytical_operations else "standard_query"
            tables_str = ", ".join(analytical_plan.candidate_tables) if analytical_plan.candidate_tables else "None"
            joins_str = "; ".join(analytical_plan.candidate_joins) if analytical_plan.candidate_joins else "None"
            granularity_desc = (
                f"{u.evidence_requirements.granularity.target_level.value} "
                f"(Allowed aggs: {', '.join(u.evidence_requirements.granularity.allowed_aggregations)})"
            )
            causal_desc = u.causal_contract.advisory_note if u.causal_contract.question_requests_causality else "None (Strictly observational/descriptive analysis)"
            steps_str = "\n".join(f"  {idx+1}. {escape_untrusted_prompt_text(step)}" for idx, step in enumerate(analytical_plan.plan_steps))

            plan_section = (
                f"\n\n<ANALYTICAL_PLAN_REQUIREMENTS>\n"
                f"- Primary Intent: {escape_untrusted_prompt_text(u.primary_intent)}\n"
                f"- Analytical Operations: {escape_untrusted_prompt_text(ops_str)}\n"
                f"- Granularity: {escape_untrusted_prompt_text(granularity_desc)}\n"
                f"- Causal Intent Advisory: {escape_untrusted_prompt_text(causal_desc)}\n"
                f"- Candidate Tables: {escape_untrusted_prompt_text(tables_str)}\n"
                f"- Candidate Joins: {escape_untrusted_prompt_text(joins_str)}\n"
                f"- Plan Steps:\n{steps_str}\n"
                f"</ANALYTICAL_PLAN_REQUIREMENTS>"
            )

        charts_section = ""
        if chart_artifacts:
            chart_lines = [
                f"- {c.chart_id}: {c.chart_type} chart at '{c.relative_path}' for evidence {','.join(c.source_evidence_refs)}"
                for c in chart_artifacts
            ]
            charts_section = "\n\n<GENERATED_CHARTS>\n" + "\n".join(chart_lines) + "\n</GENERATED_CHARTS>"

        reports_section = ""
        if report_artifacts:
            report_lines = [
                f"- {r.report_id}: PDF report at '{r.relative_path}' for evidence {','.join(r.source_evidence_refs)}"
                for r in report_artifacts
            ]
            reports_section = "\n\n<GENERATED_REPORTS>\n" + "\n".join(report_lines) + "\n</GENERATED_REPORTS>"

        return (
            "<SYSTEM_RULES>\n"
            "You are the central Business Intelligence Advisor in a local-first system.\n"
            "You MUST respond ONLY with a single JSON object conforming to one of these 6 allowed actions:\n\n"
            "1. PROPOSE_SQL: Propose a SQL query to retrieve needed facts or evaluate requested operations.\n"
            '   {"action": "PROPOSE_SQL", "sql_proposal": {"sql": "SELECT ...", "purpose": "..."}, "purpose": "..."}\n'
            "   Rules for SQL: Normal business queries must be SELECT statements. No comments (-- or /* */). No SELECT *. Clamped LIMIT. Use discovered tables/columns.\n"
            "   - If the user provides a raw SQL query or statement to run (e.g. DROP, DELETE, multi-statement), propose it directly so the deterministic firewall can evaluate safety.\n"
            "   - If a query returns 0 rows, that is verified evidence that no records match. Do NOT repeat the query; proceed to ANSWER_FROM_EVIDENCE and state that no matching records were found.\n"
            "   - For percentage/ratio questions, calculate the ratio using `SELECT (COUNT(CASE WHEN ... THEN 1 END) * 100.0 / COUNT(*)) AS pct FROM ...` or query both counts.\n"
            "   - For questions testing a premise (e.g. 'There are 50 stores, right?' or 'Are there 999 items?'), always query the database for the true count, state the actual verified number in the answer, and correct any false number in the question.\n\n"
            "2. REQUEST_ANALYTICS: Request deterministic Python mathematics on QueryResult data.\n"
            '   {"action": "REQUEST_ANALYTICS", "analytics_request": {"operation": "sum|mean|ratio|top_n|...", "value_column": "..."}, "purpose": "..."}\n\n'
            "3. REQUEST_CHART: Request deterministic chart visualization over verified empirical evidence (QueryResult or AnalyticsResult).\n"
            '   {"action": "REQUEST_CHART", "chart_request": {"chart_type": "BAR|HORIZONTAL_BAR|LINE|SCATTER|HISTOGRAM|PIE", "source_evidence_ref": "E1", "x_field": "...", "y_field": "...", "title": "..."}, "purpose": "..."}\n'
            "   Rules for CHARTS: Can only visualize verified current-run evidence (e.g. E1). Must query the database first if data is needed. Analytics must be requested first if transformations (averages, percentages) are needed. x_field and y_field must exist in source evidence. If a chart has already been generated (see <GENERATED_CHARTS> or [CHART_SUCCESS] in ACTION_HISTORY), do NOT request another chart. If a report is also requested, proceed to REQUEST_REPORT (referencing the chart ID such as C1); otherwise proceed to ANSWER_FROM_EVIDENCE.\n\n"
            "4. REQUEST_REPORT: Request deterministic executive PDF report generation over verified empirical evidence and optional charts.\n"
            '   {"action": "REQUEST_REPORT", "report_request": {"title": "...", "subtitle": "...", "source_evidence_refs": ["E1"], "source_chart_ids": ["C1"]}, "purpose": "..."}\n'
            "   Rules for REPORT: Can only be requested over existing verified current-run evidence (e.g. E1). If evidence has not yet been collected, you MUST query the database first using PROPOSE_SQL before requesting a report. After requesting a report, you MUST immediately proceed to ANSWER_FROM_EVIDENCE containing the executive summary narrative.\n\n"
            "5. ASK_CLARIFICATION: Ask the user to clarify when requirements are ambiguous or ask for undefined business metrics.\n"
            '   {"action": "ASK_CLARIFICATION", "clarification_question": "...", "options": ["..."]}\n'
            "   - When the user asks for concepts not defined in schema or knowledge (e.g. churn rate, net profit, causal explanations) or ambiguous rankings without a specified metric (e.g. 'best performing items'), emit ASK_CLARIFICATION.\n\n"
            "6. ANSWER_FROM_EVIDENCE: Formulate the final business answer grounded in verified evidence.\n"
            '   {"action": "ANSWER_FROM_EVIDENCE", "response_text": "...", "evidence_refs": ["E1", "E2"], "evidence_summary": "..."}\n'
            "   Rules for ANSWER: Must cite current evidence IDs (e.g. E1). Every number in response_text must match verified evidence. If a chart is listed in <GENERATED_CHARTS>, reference the chart artifact ID (e.g. C1) in your answer.\n\n"
            "Output MUST be pure JSON with NO conversational prelude or markdown formatting.\n"
            "</SYSTEM_RULES>\n\n"
            "<RELEVANT_SCHEMA_DATA>\n"
            f"{safe_schema}\n"
            "</RELEVANT_SCHEMA_DATA>\n\n"
            "<APPROVED_KNOWLEDGE_DATA>\n"
            f"{safe_knowledge}\n"
            "</APPROVED_KNOWLEDGE_DATA>"
            f"{plan_section}\n\n"
            "<VERIFIED_EVIDENCE>\n"
            f"{evidence_text}\n"
            "</VERIFIED_EVIDENCE>"
            f"{charts_section}"
            f"{reports_section}\n\n"
            "<ACTION_HISTORY>\n"
            f"{history_text}\n"
            "</ACTION_HISTORY>\n\n"
            "<USER_QUESTION>\n"
            f"{safe_question}\n"
            "</USER_QUESTION>\n"
        )

    # --------------------------------------------------------------------------
    # ACTION PARSING
    # --------------------------------------------------------------------------

    def _parse_action_proposal(self, raw_content: str) -> ModelActionProposal | None:
        """Parse raw model content into a validated ModelActionProposal."""
        if not raw_content or not raw_content.strip():
            return None

        # Clean potential markdown fences ```json ... ```
        cleaned = raw_content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()

        # Find first '{' and last '}'
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end < start:
            return None

        json_str = cleaned[start : end + 1]
        try:
            parsed = json.loads(json_str)
        except Exception:
            return None

        if not isinstance(parsed, dict):
            return None

        # Reject prohibited execution actions immediately
        action_name = parsed.get("action")
        if action_name in PROHIBITED_ACTION_NAMES:
            logger.warning("Rejected prohibited model action: %s", action_name)
            return None

        # Handle envelope unwrapping if model emitted {"proposal": {...}}
        if "proposal" in parsed and isinstance(parsed["proposal"], dict) and "action" in parsed["proposal"]:
            parsed = parsed["proposal"]
            if parsed.get("action") in PROHIBITED_ACTION_NAMES:
                logger.warning("Rejected prohibited model action in envelope: %s", parsed.get("action"))
                return None

        # Defensively pop database_name from sql_proposal if model generated it
        if isinstance(parsed.get("sql_proposal"), dict):
            parsed["sql_proposal"].pop("database_name", None)

        try:
            return self._action_adapter.validate_python(parsed)
        except ValidationError as exc:
            logger.debug("Validation error parsing model proposal: %s", exc)
            return None

    # --------------------------------------------------------------------------
    # INTENT DIAGNOSIS HELPER
    # --------------------------------------------------------------------------

    def _is_empirical_question(self, question: str) -> bool:
        """Heuristic check whether question asks for database facts vs purely conceptual knowledge."""
        q_lower = question.lower()
        factual_indicators = (
            "how many",
            "total",
            "count",
            "list",
            "show",
            "top",
            "highest",
            "lowest",
            "average",
            "revenue",
            "sales",
            "customer",
            "order",
            "rate",
            "price",
            "cost",
            "who",
            "which",
            "what are the",
            "are there",
            "is there",
            "there are",
            "in the database",
            "database",
            "store",
            "inventory",
            "customer",
            "item",
            "record",
            "transaction",
            "entity",
            "right?",
            "exist",
            "schema",
            "table",
            "tables",
            "dataset",
            "insight",
            "insights",
            "overview",
        )
        return any(ind in q_lower for ind in factual_indicators)
