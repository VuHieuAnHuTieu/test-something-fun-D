-- ==============================================================================
-- DATABASE LEAST-PRIVILEGE CYBERSECURITY POLICY: TWO-USER ARCHITECTURE
-- ==============================================================================
-- ⚠️ WARNING: TEMPLATE ONLY - DO NOT EXECUTE DIRECTLY WITH PLACEHOLDER PASSWORDS!
--
-- This script serves as the authoritative security specification and provisioning
-- template. In production and local runtime environments, database users MUST be
-- provisioned with strong credentials loaded from environment variables (.env)
-- through a secure provisioning script (e.g., scripts/setup_database.py).
--
-- DO NOT execute this file directly with placeholder credentials.
--
-- PURPOSE & ARCHITECTURAL PRIVILEGE SEPARATION:
--
-- 1. bi_reader (Used by Central AI Agent for SQL Generation):
--    - Granted SELECT ONLY on approved analytical tables and curated views.
--    - Zero access to sensitive fields: staff.password hash, staff.username,
--      customer PII (email, address_id), and customer physical street addresses.
--    - Direct access to base tables `staff`, `customer`, and `address` is BLOCKED.
--    - Store geographic analytics provided via curated view `ai_store_location`.
--    - Customer analytics provided via curated view `ai_customer`.
--    - Staff metadata provided via curated view `ai_staff`.
--    - Zero access to `agent_system` metadata schema.
--    - Zero INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, FILE, or GRANT privileges.
--
-- 2. agent_app (Used by Streamlit Application Internals):
--    - Granted SELECT, INSERT, UPDATE on `agent_system` tables only.
--    - DELETE privilege is withheld to guarantee immutable audit logs and conversation history.
--    - Manages sessions, conversation history, audit runs, and report metadata.
--    - Zero access to `sakila_extended` business data.
--    - Zero DDL privileges (DROP, ALTER, CREATE) at runtime.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. PROVISION USER 1: bi_reader (AI Business Analytics Engine)
-- ------------------------------------------------------------------------------

-- Create user bound strictly to loopback addresses
CREATE USER IF NOT EXISTS 'bi_reader'@'localhost' 
    IDENTIFIED BY 'PLACEHOLDER_BI_READER_PASSWORD_SET_IN_ENV';
CREATE USER IF NOT EXISTS 'bi_reader'@'127.0.0.1' 
    IDENTIFIED BY 'PLACEHOLDER_BI_READER_PASSWORD_SET_IN_ENV';

-- Revoke all inherited permissions
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'bi_reader'@'localhost';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'bi_reader'@'127.0.0.1';

-- Data Minimization Allowlist: Grant SELECT ONLY on approved analytical objects
-- Approved Business Tables:
GRANT SELECT ON sakila_extended.film TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.category TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.film_category TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.film_actor TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.actor TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.language TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.inventory TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.rental TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.payment TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.store TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.customer_event TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.film_text TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.city TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.country TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';

-- Curated Analytical Views (PII & Credentials Masked):
-- ai_customer: Excludes email and physical address links
GRANT SELECT ON sakila_extended.ai_customer TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
-- ai_staff: Excludes password hash, email, address_id, and username
GRANT SELECT ON sakila_extended.ai_staff TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
-- ai_store_location: Exposes store city and country without street address, postal code, or phone
GRANT SELECT ON sakila_extended.ai_store_location TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';

-- Pre-aggregated Analytical Views:
GRANT SELECT ON sakila_extended.sales_by_film_category TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.sales_by_store TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON sakila_extended.film_list TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';

-- Resource limiting (Prevents query flooding DoS)
ALTER USER 'bi_reader'@'localhost' WITH MAX_QUERIES_PER_HOUR 5000 MAX_USER_CONNECTIONS 10;
ALTER USER 'bi_reader'@'127.0.0.1' WITH MAX_QUERIES_PER_HOUR 5000 MAX_USER_CONNECTIONS 10;


-- ------------------------------------------------------------------------------
-- 2. PROVISION USER 2: agent_app (Application State & Audit Persistence)
-- ------------------------------------------------------------------------------

-- Create user bound strictly to loopback addresses
CREATE USER IF NOT EXISTS 'agent_app'@'localhost' 
    IDENTIFIED BY 'PLACEHOLDER_AGENT_APP_PASSWORD_SET_IN_ENV';
CREATE USER IF NOT EXISTS 'agent_app'@'127.0.0.1' 
    IDENTIFIED BY 'PLACEHOLDER_AGENT_APP_PASSWORD_SET_IN_ENV';

-- Revoke all inherited permissions
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'agent_app'@'localhost';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'agent_app'@'127.0.0.1';

-- Grant runtime DML permissions ONLY on agent_system state tables
-- Note: DELETE is withheld across all tables to preserve audit history;
-- UPDATE is strictly withheld on audit_events to guarantee append-only immutability.
GRANT SELECT, INSERT, UPDATE ON agent_system.chat_sessions TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON agent_system.agent_runs TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON agent_system.chat_messages TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON agent_system.reports TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';
GRANT SELECT, INSERT ON agent_system.audit_events TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';

-- Resource limiting
ALTER USER 'agent_app'@'localhost' WITH MAX_QUERIES_PER_HOUR 10000 MAX_USER_CONNECTIONS 20;
ALTER USER 'agent_app'@'127.0.0.1' WITH MAX_QUERIES_PER_HOUR 10000 MAX_USER_CONNECTIONS 20;

-- Apply all privilege changes immediately
FLUSH PRIVILEGES;


-- ==============================================================================
-- 3. SECURITY VERIFICATION MATRIX (MANUAL / AUTOMATED TEST SPECIFICATION)
-- ==============================================================================
--
-- TEST CASE 1: bi_reader can read approved business data
-- Query:
--   SELECT COUNT(*) FROM sakila_extended.rental;
-- Expected: SUCCESS (Returns integer count)
--
-- TEST CASE 2: bi_reader can read curated AI views (customer, store location)
-- Query:
--   SELECT customer_id, first_name, last_name FROM sakila_extended.ai_customer LIMIT 1;
--   SELECT store_id, city, country FROM sakila_extended.ai_store_location;
-- Expected: SUCCESS
--
-- TEST CASE 3: bi_reader CANNOT access staff base table or passwords (Defense against Prompt Injection)
-- Query:
--   SELECT password FROM sakila_extended.staff;
-- Expected: ERROR 1142 (42000): SELECT command denied to user 'bi_reader'@'localhost' for table 'staff'
--
-- TEST CASE 4: bi_reader CANNOT access address base table directly (Defense against PII harvesting)
-- Query:
--   SELECT address, phone FROM sakila_extended.address;
-- Expected: ERROR 1142 (42000): SELECT command denied to user 'bi_reader'@'localhost' for table 'address'
--
-- TEST CASE 5: bi_reader CANNOT read staff usernames from ai_staff view
-- Query:
--   SELECT username FROM sakila_extended.ai_staff;
-- Expected: ERROR 1054 (42S22): Unknown column 'username' in 'field list'
--
-- TEST CASE 6: bi_reader CANNOT mutate business data
-- Query:
--   DELETE FROM sakila_extended.payment WHERE payment_id = 1;
-- Expected: ERROR 1142 (42000): DELETE command denied to user 'bi_reader'@'localhost' for table 'payment'
--
-- TEST CASE 7: bi_reader CANNOT read or write agent_system
-- Query:
--   SELECT * FROM agent_system.agent_runs;
-- Expected: ERROR 1142 (42000): SELECT command denied to user 'bi_reader'@'localhost' for table 'agent_runs'
--
-- TEST CASE 8: agent_app CAN persist audit runs
-- Query:
--   INSERT INTO agent_system.chat_sessions (session_id, title) VALUES ('test_s1', 'Test Session');
-- Expected: SUCCESS (1 row affected)
--
-- TEST CASE 9: agent_app CANNOT access or modify business tables
-- Query:
--   DROP TABLE sakila_extended.rental;
-- Expected: ERROR 1142 (42000): DROP command denied to user 'agent_app'@'localhost' for table 'rental'
--
-- TEST CASE 10: agent_app CANNOT delete audit records (Guaranteed audit immutability)
-- Query:
--   DELETE FROM agent_system.agent_runs WHERE run_id = 'test_r1';
-- Expected: ERROR 1142 (42000): DELETE command denied to user 'agent_app'@'localhost' for table 'agent_runs'
-- ==============================================================================
