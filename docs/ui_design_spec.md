# Business Intelligence Agent — UI/UX Design Specification

## 1. Executive Overview

The Business Intelligence Agent Streamlit interface provides an auditable, deterministic, and human-centered presentation layer for enterprise database analytics. 

The application adheres strictly to the permanent trust and authority hierarchy:
$$\text{FUNCTIONALITY} > \text{USABILITY} > \text{CLARITY} > \text{TRUST} > \text{ACCESSIBILITY} > \text{AESTHETICS} > \text{EMOTIONALITY}$$

The Streamlit UI acts exclusively as a **presentation and orchestration client**. It delegates all reasoning, SQL proposal, validation, database execution, mathematical analytics, chart generation, PDF reporting, and audit persistence to the single authoritative runtime agent: `BusinessIntelligenceAgent`.

---

## 2. Theoretical Design Foundations

The interface architecture is synthesized from 7 foundational design treatises, calibrated with development-time design intelligence from UI UX Pro Max v2.15.0:

1. **The Principles of Beautiful Web Design** (*Jason Beaird*):
   - **8px Baseline Spatial Grid**: Spacing, padding, and vertical rhythm are structured in multiples of $8\text{ px}$ (with $4\text{ px}$ micro-steps) to create harmonious alignment.
   - **Asymmetric Equilibrium**: A structured utility control rail ($300\text{--}320\text{ px}$) on the left balances a spacious analytical workspace on the right.
   - **Visual Unity**: Consistent border radii ($8\text{ px}$), restrained shadows, and unified slate/navy accents anchor components across the application.

2. **Color Design Workbook** (*Adams Morioka, Terry Stone*):
   - **60-30-10 Dominance**: 60% neutral slate background (`#F8FAFC`), 30% white card surfaces (`#FFFFFF`) with structural borders (`#E2E8F0`), and 10% purposeful corporate navy accent (`#1E40AF`).
   - **Semantic Color Discipline**: Color conveys operational state, not decoration: Emerald (`#166534`) for verified success, Amber (`#9A3412`) for clarification, and Crimson (`#991B1B`) for blocked security rejections.

3. **Interaction Design: Beyond Human-Computer Interaction** (*Preece, Rogers, Sharp*):
   - **Conceptual Fidelity**: The UI mental model maps 1:1 with backend reality: `Active Schema -> User Question -> Verified Evidence -> Grounded Answer`.
   - **Immediate Feedback**: Clear transitions for all execution states (`IDLE`, `RUNNING` spinner, `SUCCESS`, `CLARIFICATION`, `SECURITY_BLOCKED`).

4. **Universal Principles of Design** (*Lidwell, Holden, Butler*):
   - **Visibility**: Active database name, object counts, and schema fingerprint prefix are anchored in the persistent context strip.
   - **Progressive Disclosure**: High-level business answers and KPI callouts are displayed first; raw SQL, full data tables, and execution provenance are sequestered into default-collapsed expanders.
   - **Error Prevention & Forgiveness**: Safe context switching with confirmation prompts; safe failure closed on audit persistence issues.
   - **Fitts's Law**: Minimum $44\text{ px}$ interactive touch targets on buttons and form inputs.

5. **Storytelling for Designers**:
   - **Analytical Sensemaking**: Responses structure empirical evidence as an executive story: `Direct Grounded Answer -> Verified KPI Callouts -> Visual Chart -> Executive PDF -> Tabular Evidence -> Technical Provenance`.

6. **Universal Principles of Typography**:
   - **Measure & Comfort**: Narrative prose is constrained to comfortable reading measure ($\approx 720\text{--}850\text{ px}$, $45\text{--}75$ characters per line).
   - **Typographic Scale**: Strict hierarchy (Title: $28\text{ px}$, Section: $22\text{ px}$, Subheading: $18\text{ px}$, Body: $16\text{ px}$, Metadata: $13\text{--}14\text{ px}$; $12\text{ px}$ is prohibited for normal metadata).
   - **Tabular Numerals**: Lining monospace figures for financial figures, counts, and timestamps.

7. **Universal Principles of UX**:
   - **User First**: Analytical clarity takes precedence over showing off raw AI prompts or model tokens.
   - **Actionable Error Microcopy**: Friendly, plain-English error messages that explain the issue and the remedy without leaking raw infrastructure IPs or stack traces.

---

## 3. Design Tokens

All visual constants are centralized in `ui/design_tokens.py`:

| Token Name | Value | Purpose / Usage |
| :--- | :--- | :--- |
| `COLOR_BG_PAGE` | `#F8FAFC` (Slate 50) | Main page background |
| `COLOR_BG_CARD` | `#FFFFFF` (White) | Card surfaces, modals |
| `COLOR_BG_SIDEBAR` | `#F1F5F9` (Slate 100) | Sidebar rail background |
| `COLOR_TEXT_PRIMARY` | `#0F172A` (Slate 900) | Headings, primary text (> 14:1 contrast) |
| `COLOR_TEXT_SECONDARY`| `#475569` (Slate 600) | Secondary body text (> 6:1 contrast) |
| `COLOR_TEXT_MUTED` | `#64748B` (Slate 500) | Metadata, captions (> 4.5:1 contrast) |
| `COLOR_PRIMARY` | `#1E40AF` (Blue 800) | Primary actions, buttons |
| `COLOR_PRIMARY_HOVER`| `#1D4ED8` (Blue 700) | Interactive hover states |
| `COLOR_BORDER` | `#E2E8F0` (Slate 200) | Card and table borders |
| `COLOR_BORDER_STRONG`| `#CBD5E1` (Slate 300) | Active boundaries, dividers |
| `COLOR_SUCCESS` | `#166534` (Green 800) | Success text, verified badges |
| `COLOR_SUCCESS_BG` | `#DCFCE7` (Green 100) | Success badge backgrounds |
| `COLOR_WARNING` | `#9A3412` (Orange 800) | Warning text, clarification badges |
| `COLOR_WARNING_BG` | `#FFEDD5` (Orange 100) | Warning badge backgrounds |
| `COLOR_DANGER` | `#991B1B` (Red 800) | Security alerts, error badges |
| `COLOR_DANGER_BG` | `#FEE2E2` (Red 100) | Error alert backgrounds |
| `RADIUS_SM` | `4px` | Badges, small pills |
| `RADIUS_MD` | `8px` | Cards, containers, buttons |
| `RADIUS_LG` | `12px` | Large dialogs, hero callouts |
| `MAX_READING_MEASURE_PX` | `850px` | Max width for narrative prose |
| `MIN_INTERACTIVE_TARGET_PX` | `44px` | Accessibility touch target |

---

## 4. Architectural Rules & Invariants

### 4.1 Strict KPI Authority Invariant
Streamlit displays 0–4 KPI cards **only** when explicit, verified scalar metrics exist in an approved contract (`AnalyticsResultContract`).
- If an agent run gathered only tabular data without scalar operations, **exactly zero KPI cards are rendered**.
- Streamlit is **strictly prohibited** from inspecting raw `QueryResultContract` rows to invent, compute, or summarize KPIs.

### 4.2 Artifact Integrity Invariant
Before rendering any chart (`st.image`) or providing a PDF download button (`st.download_button`):
1. The file path is verified to reside strictly within `reports/charts/` or `reports/pdfs/`.
2. Path traversal attempts (e.g. `../../config.py`) are caught and rejected.
3. The file bytes are read from disk and re-hashed using SHA-256.
4. The calculated digest is compared against `contract.sha256`.
5. If verified, the artifact is rendered with a SHA-256 badge; if mismatched or missing, an error card is shown and rendering/downloading is suppressed.

### 4.3 Exactly-Once Nonce Execution
- To prevent Streamlit rerun loops, each user submission event mints a unique UUIDv4 `submission_nonce`.
- Streamlit widget interactions (expanding expanders, downloading artifacts, window resizing) do not re-execute the agent.
- An explicit resubmission of an identical question mints a fresh nonce, allowing the agent to run and transparently demonstrate Step 27 `CACHE_HIT` behavior.

### 4.4 Database-Agnostic Production Code
- `app.py` and all files under `ui/*.py` contain **zero hardcoded database or domain names** (e.g., `sakila`, `film`, `rental`, `payment`, `actor`).
- Schema metadata, table lists, and context details are discovered dynamically at runtime.

### 4.5 Error Microcopy & Information Sanitization
- Primary user-facing messages communicate problems and remedies in plain, respectful English.
- Primary alerts never leak internal IP addresses (`127.0.0.1`), database usernames (`bi_reader`, `agent_app`), port numbers, schema tables (`agent_system`), or Python stack traces.
- Technical reason codes (`NON_SELECT_STATEMENT`, `AUDIT_PERSISTENCE_FAILED`) are segregated into the collapsed Technical Provenance expander.

---

## 5. Component Inventory

| Component | Source File | Function / Description |
| :--- | :--- | :--- |
| **Page Shell** | `app.py` | Wide responsive layout, page config, and message loop |
| **Theme Engine** | `ui/theme.py` | Injects static CSS for cards, badges, and typography |
| **State Manager** | `ui/state.py` | Initializes and guards session state, resets conversations |
| **Artifact Checker**| `ui/artifacts.py` | Enforces filesystem containment and SHA-256 verification |
| **Sidebar Rail** | `ui/onboarding.py` | System health, dataset onboarding, schema inspector |
| **Context Strip** | `ui/components.py` | Persistent horizontal banner showing active schema details |
| **Direct Answer** | `ui/components.py` | Narrative response constrained to $850\text{ px}$ reading measure |
| **KPI Metric Cards**| `ui/components.py` | 0-4 cards displaying strictly verified scalar calculations |
| **Chart Artifact** | `ui/components.py` | Verified chart display with integrity badge and download button |
| **Report Artifact**| `ui/components.py` | Verified executive PDF card with download button |
| **Evidence View** | `ui/components.py` | Collapsed expander with interactive `st.dataframe` evidence |
| **Provenance View**| `ui/components.py` | Collapsed expander with run ID, cache status, and SQL |
| **Status Alerts** | `ui/components.py` | Clarification cards with buttons, security blocked, and error cards |

---

## 6. Verification & Test Suite

The UI implementation is covered by a test suite in `tests/test_streamlit_app.py`:
- `test_startup_no_context`: Verifies initial `NO_CONTEXT` state.
- `test_active_context_rendered`: Verifies context strip rendering.
- `test_chat_execution_success_flow`: Verifies full end-to-end question run.
- `test_kpi_authority_invariant_zero_kpis_when_no_scalar`: Enforces zero KPI cards without verified scalar contract.
- `test_clarification_flow_with_structured_options`: Verifies clickable clarification buttons.
- `test_security_blocked_friendly_message`: Verifies friendly read-only message on blocked operations.
- `test_error_sanitization_no_credentials_or_ips`: Verifies zero credential/IP leakage.
- `test_rerun_idempotency_does_not_re_execute`: Verifies nonce execution guard.
- `test_session_isolation`: Verifies state isolation between multiple users.
- `test_database_context_switch_resets_chat`: Verifies conversation reset on schema switch.
- `test_artifact_integrity_verification`: Verifies path containment and SHA-256 validation.
- `test_static_security_scans`: Verifies zero direct DB/Ollama imports, zero CoT, and zero hardcoded domain terms.
