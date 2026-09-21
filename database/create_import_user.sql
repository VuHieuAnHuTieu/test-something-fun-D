-- ==============================================================================
-- DATABASE LEAST-PRIVILEGE CYBERSECURITY POLICY: DEDICATED IMPORT ACCOUNT
-- ==============================================================================
-- ⚠️ WARNING: TEMPLATE ONLY - DO NOT EXECUTE DIRECTLY WITH PLACEHOLDER PASSWORDS!
--
-- This script serves as the authoritative security specification and provisioning
-- template for the dedicated dataset import account (`dataset_importer`).
--
-- SECURITY GUARANTEES & ROLE SEPARATION:
--
-- 1. dataset_importer (Dedicated User-Triggered Onboarding Importer):
--    - Purpose: Executing verified CSV and safe SQL-dump imports into the managed
--      target schema namespace (`managed_import`).
--    - Bound strictly to local loopback addresses (localhost, 127.0.0.1).
--    - Granted DDL (CREATE, DROP, ALTER) and DML (SELECT, INSERT, UPDATE, DELETE)
--      STRICTLY on `managed_import.*`.
--    - ZERO access to `sakila_extended` or any existing production business datasets.
--    - ZERO access to `agent_system` metadata schema.
--    - ZERO access to `mysql` or system schemas.
--    - ZERO global administrative privileges (SUPER, FILE, PROCESS, RELOAD).
--    - NEVER used for business analytics, schema inspection by agent, or Qwen LLM calls.
--
-- 2. bi_reader Integration:
--    - Granted SELECT ONLY on `managed_import.*` so that once an import is validated
--      and committed, the read-only analytics engine can inspect and query it.
--    - bi_reader remains strictly READ-ONLY at all times.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. CREATE MANAGED IMPORT SCHEMA
-- ------------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS managed_import;

-- ------------------------------------------------------------------------------
-- 2. PROVISION USER: dataset_importer (Scoped Strictly to managed_import)
-- ------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dataset_importer'@'localhost'
    IDENTIFIED BY 'PLACEHOLDER_DATASET_IMPORTER_PASSWORD_SET_IN_ENV';
CREATE USER IF NOT EXISTS 'dataset_importer'@'127.0.0.1'
    IDENTIFIED BY 'PLACEHOLDER_DATASET_IMPORTER_PASSWORD_SET_IN_ENV';

-- Revoke all inherited or global permissions
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'dataset_importer'@'localhost';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'dataset_importer'@'127.0.0.1';

-- Grant DDL and DML ONLY on the managed import schema namespace
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER ON managed_import.* TO 'dataset_importer'@'localhost', 'dataset_importer'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER ON `managed_import\_%`.* TO 'dataset_importer'@'localhost', 'dataset_importer'@'127.0.0.1';

-- Grant read-only analytical access to bi_reader on approved imported data
GRANT SELECT ON managed_import.* TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';
GRANT SELECT ON `managed_import\_%`.* TO 'bi_reader'@'localhost', 'bi_reader'@'127.0.0.1';

-- Enforce resource caps to prevent runaway import exhaustion
ALTER USER 'dataset_importer'@'localhost' WITH MAX_QUERIES_PER_HOUR 1000 MAX_USER_CONNECTIONS 5;
ALTER USER 'dataset_importer'@'127.0.0.1' WITH MAX_QUERIES_PER_HOUR 1000 MAX_USER_CONNECTIONS 5;

FLUSH PRIVILEGES;
