# Step 33: Dependency Vulnerability & Static Code Security Audit

**Audit Date:** 2026-09-21  
**Target System:** Local Business Intelligence & Reporting AI Agent  
**Environment:** Local Python 3.14.2 Virtualenv, Local MySQL 8.0, Local Ollama (Qwen 2.5-Coder 7B)  
**Final Verdict:** `STEP 33 PIP-AUDIT + BANDIT SECURITY AUDIT = TRUE`

---

## 1. Executive Summary & Audit Objectives

Step 33 conducted a comprehensive dependency-vulnerability and static-code security audit of the complete Local Business Intelligence Agent codebase using:
1. **`pip-audit` (v2.10.1)** for known vulnerability scanning across installed packages and declared project requirements.
2. **`Bandit` (v1.9.4)** for AST-based security analysis of production code and test suites.

The audit verified that:
- No known vulnerable Python packages are present in the runtime or development environments;
- Production Python code exhibits zero critical or high-severity vulnerabilities;
- Legitimate static analysis warnings are triaged, and genuine code quality issues are resolved with minimal, non-breaking remediation;
- Frozen security invariants (deterministic SQL firewall, strict least-privilege database roles, offline operation, and evidence-ledger provenance) remain completely intact;
- All 857 automated tests pass with 100% success.

---

## 2. Tooling & Environment Specifications

- **Python Version:** 3.14.2 (Windows 64-bit)
- **pip-audit Version:** 2.10.1
- **Bandit Version:** 1.9.4
- **Audited Runtime Requirements:** `requirements.txt` (11 direct dependencies)
- **Audited Development Requirements:** `requirements-dev.txt` (4 dev dependencies)

---

## 3. Dependency Vulnerability Audit (`pip-audit`)

### Audit Commands & Execution Results

1. **Installed Virtualenv Scan:**
   ```powershell
   .\.venv\Scripts\python.exe -m pip_audit
   ```
   **Result:** `No known vulnerabilities found` (0 vulnerabilities across 83 installed packages).

2. **Declared Runtime Dependencies Scan:**
   ```powershell
   .\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
   ```
   **Result:** `No known vulnerabilities found` (0 vulnerabilities in declared runtime requirements).

3. **Declared Development Dependencies Scan:**
   ```powershell
   .\.venv\Scripts\python.exe -m pip_audit -r requirements-dev.txt
   ```
   **Result:** `No known vulnerabilities found` (0 vulnerabilities in declared dev requirements).

### Runtime vs. Development Dependency Distinction

| Package Name | Category | Installed Version | Declared Scope | Status |
| :--- | :--- | :--- | :--- | :--- |
| `streamlit` | Runtime | 1.64.0 | `requirements.txt` | **CLEAN** (0 advisories) |
| `ollama` | Runtime | 0.6.2 | `requirements.txt` | **CLEAN** (0 advisories) |
| `mysql-connector-python` | Runtime | 26.7.0 | `requirements.txt` | **CLEAN** (0 advisories) |
| `pandas` | Runtime | 3.0.6 | `requirements.txt` | **CLEAN** (0 advisories) |
| `pydantic` | Runtime | 2.13.5 | `requirements.txt` | **CLEAN** (0 advisories) |
| `python-dotenv` | Runtime | 1.2.3 | `requirements.txt` | **CLEAN** (0 advisories) |
| `matplotlib` | Runtime | 3.11.2 | `requirements.txt` | **CLEAN** (0 advisories) |
| `reportlab` | Runtime | 5.0.1 | `requirements.txt` | **CLEAN** (0 advisories) |
| `sqlglot` | Runtime | 30.18.0 | `requirements.txt` | **CLEAN** (0 advisories) |
| `pypdf` | Runtime | 6.19.0 | `requirements.txt` | **CLEAN** (0 advisories) |
| `Pillow` | Runtime | 12.3.0 | `requirements.txt` | **CLEAN** (0 advisories) |
| `pytest` | Development | 9.1.1 | `requirements-dev.txt` | **CLEAN** (0 advisories) |
| `pip-audit` | Development | 2.10.1 | `requirements-dev.txt` | **CLEAN** (0 advisories) |
| `bandit` | Development | 1.9.4 | `requirements-dev.txt` | **CLEAN** (0 advisories) |
| `pypdfium2` | Development | 5.13.0 | `requirements-dev.txt` | **CLEAN** (0 advisories) |

- **Direct-Runtime Vulnerabilities:** 0
- **Transitive-Runtime Vulnerabilities:** 0
- **Development-Only Vulnerabilities:** 0
- **Unresolved Dependency Vulnerabilities:** 0

---

## 4. Static Code Security Analysis (`Bandit`)

### Production Code Scan

**Target Scope:** `app.py`, `agent.py`, `config.py`, `database/`, `tools/`, `models/`, `ui/`, `scripts/`  
**Exclusions:** `.venv/`, `tests/`, `scratch/`, `.git/`, `.agents/`  
**Command:**
```powershell
.\.venv\Scripts\python.exe -m bandit -r app.py agent.py config.py database tools models ui scripts
```

**Run Metrics:**
- Total Lines of Code: 12,095
- Total Issues: 18 (High: 0, Medium: 2, Low: 16)
- False Positives / Accepted Safe Patterns: 18
- True Positive Vulnerabilities: 0

### Production Finding Matrix & Triage Details

| Bandit ID | Severity | Confidence | Location | Description | Classification & Technical Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B608** | Medium | Low | `agent.py:2104` | Possible SQL injection vector through string-based query construction | **FALSE POSITIVE**. Prose instruction within an LLM system prompt template (`"<SYSTEM_RULES>... Rules for SQL: Normal business queries must be SELECT statements..."`). This is a static instruction string sent to local Qwen, not an executed SQL statement. Zero database execution. |
| **B608** | Medium | Low | `database/onboarding.py:395` | Possible SQL injection vector through string-based query construction | **ACCEPTED SAFE PATTERN**. Dynamic statement construction for CSV staging table insertion: `INSERT INTO \`{schema}\`.\`{table}\` ({cols}) VALUES (%s, %s, ...)`. All identifiers are strictly sanitized using `sanitize_sql_identifier` (regex `^[a-z0-9_]+$`) and validated against schema rules. Data rows are parameterized via `%s` tuples in `cursor.executemany`. Executed via `dataset_importer` role (least privilege). |
| **B110** | Low | High | `agent.py:530` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Metric number extraction in `_register_value_in_catalog`. Catches `Decimal(str(v))` parsing failures on non-numeric cell values without disrupting remaining evidence parsing. |
| **B110** | Low | High | `agent.py:582` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Quantization trial in `_verify_candidate_number` for percentage precision matching. Catches `InvalidOperation` on non-matching quantize bounds. |
| **B110** | Low | High | `agent.py:588` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Integer rounding trial in `_verify_candidate_number`. Fails safe by continuing to next candidate match. |
| **B110** | Low | High | `agent.py:613` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Exponent inspection and quantization in `_verify_candidate_number`. Fails safe to ungrounded status if quantization fails. |
| **B110** | Low | High | `database/onboarding.py:500` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Pre-existing table lookup in `information_schema.tables` before CSV staging. Failure leaves `pre_existing_tables` empty, causing clean fallback. |
| **B110** | Low | High | `database/onboarding.py:534` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive rollback guard in exception handler `conn.rollback()` before executing compensating DDL cleanup. |
| **B110** | Low | High | `database/onboarding.py:543` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive commit guard following compensating DDL cleanup (`DROP TABLE IF EXISTS`) during failed import rollback. |
| **B110** | Low | High | `database/onboarding.py:563` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive `conn.close()` guard inside `finally` block to prevent masking upstream exceptions if connection is already closed. |
| **B110** | Low | High | `database/onboarding.py:867` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Pre-existing table lookup in `information_schema.tables` before SQL dump staging. |
| **B110** | Low | High | `database/onboarding.py:900` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive rollback guard before SQL dump compensating DDL cleanup. |
| **B110** | Low | High | `database/onboarding.py:909` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive commit guard following SQL dump compensating DDL cleanup. |
| **B110** | Low | High | `database/onboarding.py:929` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive `conn.close()` guard inside SQL dump `finally` block. |
| **B110** | Low | High | `tools/sql_tool.py:251` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. SQLGlot comment tokenizer check in `_has_comments`. If tokenizer raises on malformed input, execution immediately falls through to the secondary regex comment detector. |
| **B110** | Low | High | `tools/sql_tool.py:752` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Server-side query execution timeout (`SET SESSION max_execution_time`). If the underlying MySQL engine does not support this variable, connection-level timeout provides defense-in-depth. |
| **B110** | Low | High | `tools/sql_tool.py:789` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive `cursor.close()` inside `finally` block to ensure `conn.close()` executes even if cursor close raises. |
| **B110** | Low | High | `tools/sql_tool.py:794` | Try, Except, Pass detected | **ACCEPTED SAFE PATTERN**. Defensive `conn.close()` inside `finally` block. |

---

### Test-Only Code Scan

**Target Scope:** `tests/`  
**Command:**
```powershell
.\.venv\Scripts\python.exe -m bandit -r tests
```

**Run Metrics:**
- Total Lines of Code: 12,009
- Total Issues: 1,659 (High: 0, Medium: 6, Low: 1,653)
- **Low Severity (1,653 issues):** Predominantly `B101:assert_used` statements standard across pytest automated test fixtures.
- **Medium Severity (6 issues):**
  - `B608` (5 instances): Parameterized SQL query strings in test fixtures (`test_adversarial_security.py:375`, `test_schema_tool.py:308`, `test_sql_safety.py:315, 319, 435`) constructing attack test payloads.
  - `B310` (1 instance): `urllib.request.urlopen` in `test_adversarial_security.py:1602` performing a local Ollama service liveness check (`http://127.0.0.1:11434/api/version`) within a test skip fixture.
- **Test-Only Verdict:** Zero true-positive production security issues.

---

## 5. Security Hardening Remediations Applied in Step 33

During the Step 33 audit review, two opportunities for defensive code hardening were identified and remediated without breaking API contracts:

1. **Replaced Assert with Explicit Exception in `tools/sql_tool.py` (B101):**
   - *Previous Code:* `assert validation.validated_sql is not None` (line 736).
   - *Issue:* If executed under `python -O`, assertions are removed by bytecode optimization.
   - *Remediation:* Replaced with an explicit runtime check:
     ```python
     if validation.validated_sql is None:
         raise SQLExecutionError("Validation produced no executable SQL statement.")
     ```
   - *Status:* Cleanly resolved; eliminates B101 warning in production code.

2. **Added Debug Logging to Font Registration Fallback in `tools/report_style.py` (B112):**
   - *Previous Code:* `except Exception: continue` (line 125).
   - *Issue:* Silent `continue` inside exception handler flagged by Bandit B112.
   - *Remediation:* Added explicit debug logging:
     ```python
     except Exception as e:
         logging.getLogger(__name__).debug("Candidate font registration failed for %s: %s", family_name, e)
         continue
     ```
   - *Status:* Cleanly resolved; eliminates B112 warning in production code.

3. **Explicit Runtime Dependency Declaration in `requirements.txt`:**
   - Explicitly added `Pillow` to `requirements.txt` to guarantee that direct imports (`from PIL import Image` in `ui/artifacts.py`) do not rely solely on transitive installation via matplotlib or reportlab.

---

## 6. Verification & Regression Testing

### 1. Offline Dependency Import Smoke Test
All 11 direct runtime dependencies import successfully without network activity:
```
streamlit, ollama, mysql.connector, pandas, pydantic, dotenv,
matplotlib, reportlab, sqlglot, pypdf, PIL
-> ALL_IMPORTS_SUCCESSFUL
```

### 2. Targeted Security Suites
- `tests/test_adversarial_security.py`: **146 passed in 69.14s (0 failed)**
- `tests/test_sql_safety.py`: **65 passed in 3.28s (0 failed)**
- `tests/test_streamlit_app.py`: **23 passed in 23.16s (0 failed)**

### 3. Full Codebase Regression
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
**Result:** **857 passed in 116.81s (0 failed, 0 skipped, 100% pass rate)**.

### 4. Database Immutability Verification
- **Schema Fingerprint:** `c93e0b53813762d8cdb2083f1c38e73d54715aaf6418f7d87b08028d4ae70cbb` (**MATCH** — identical to baseline).
- **14 Base-Table Row Counts:** `actor: 0, category: 8, city: 5, country: 5, customer_event: 9, film: 5, film_actor: 0, film_category: 5, film_text: 5, inventory: 9, language: 4, payment: 4, rental: 3, store: 2` (Total: `64` rows; **UNMUTATED**).

### 5. Secret Hygiene
- In-memory credential scan of Step 33 changes: **`SECRET_MATCHES = 0`**.
- `git diff --check`: **CLEAN** (0 errors).

---

## 7. Final Step 33 Verdict

Zero unresolved vulnerabilities identified within the tested Step 33 dependency and static analysis scope after remediation. All frozen security invariants, database schemas, and architectural boundaries remain verified and intact.

**`STEP 33 PIP-AUDIT + BANDIT SECURITY AUDIT = TRUE`**
