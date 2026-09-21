-- ==============================================================================
-- RESET_DEV.SQL: EXPLICIT DESTRUCTIVE DEVELOPMENT RESET
-- ==============================================================================
-- WARNING: This script drops and wipes both the business database and the
-- agent system database. Run ONLY in development environments when performing
-- a clean teardown.
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- 1. Drop and recreate business analytical database
DROP SCHEMA IF EXISTS sakila_extended;
CREATE SCHEMA sakila_extended;

-- 2. Drop and recreate agent runtime state database
DROP SCHEMA IF EXISTS agent_system;
CREATE SCHEMA agent_system;

SET FOREIGN_KEY_CHECKS = 1;

-- After running this script, run:
-- 1. schema.sql              (Builds sakila_extended business schema & analytical views)
-- 2. agent_system_schema.sql (Builds agent_system tables: sessions, messages, runs, reports)
-- 3. create_users.sql        (Configures least-privilege bi_reader and agent_app users)
-- 4. seed.sql                (Populates deterministic test data for unit tests)
