-- ==============================================================================
-- DATABASE LEAST-PRIVILEGE PATCH: AUDIT PERSISTENCE SCHEMA (STEP 24)
-- ==============================================================================
-- WARNING: TO BE EXECUTED BY MYSQL DBA / ROOT ACCOUNT IN MYSQL WORKBENCH OR CLI
--
-- This migration extends the agent_system database schema for Step 24 audit
-- and persistence while strictly preserving privilege boundaries:
-- 1. Adds 'status' column to chat_sessions (defaults to 'ACTIVE').
-- 2. Adds durable provenance columns to agent_runs (database_context_id,
--    database_name, schema_fingerprint, started_at, completed_at).
-- 3. Creates dedicated append-only 'audit_events' table (ON DELETE RESTRICT).
-- 4. Configures least-privilege DML for 'agent_app':
--    - SELECT, INSERT on audit_events (APPEND-ONLY: UPDATE & DELETE strictly withheld).
--    - SELECT, INSERT, UPDATE on chat_sessions and agent_runs (Lifecycle state transitions).
--    - ZERO access to business databases or MySQL system schemas.
-- ==============================================================================

USE agent_system;

-- ------------------------------------------------------------------------------
-- 1. Temporary Stored Procedure for Idempotent Column Additions (MySQL 8.0)
-- ------------------------------------------------------------------------------
DELIMITER //

DROP PROCEDURE IF EXISTS apply_step24_patch //

CREATE PROCEDURE apply_step24_patch()
BEGIN
    -- 1a. chat_sessions.status
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'chat_sessions'
          AND COLUMN_NAME = 'status'
    ) THEN
        ALTER TABLE agent_system.chat_sessions
            ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE';
    END IF;

    -- 1b. agent_runs.database_context_id
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'agent_runs'
          AND COLUMN_NAME = 'database_context_id'
    ) THEN
        ALTER TABLE agent_system.agent_runs
            ADD COLUMN database_context_id VARCHAR(64) DEFAULT NULL;
    END IF;

    -- 1c. agent_runs.database_name
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'agent_runs'
          AND COLUMN_NAME = 'database_name'
    ) THEN
        ALTER TABLE agent_system.agent_runs
            ADD COLUMN database_name VARCHAR(64) DEFAULT NULL;
    END IF;

    -- 1d. agent_runs.schema_fingerprint
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'agent_runs'
          AND COLUMN_NAME = 'schema_fingerprint'
    ) THEN
        ALTER TABLE agent_system.agent_runs
            ADD COLUMN schema_fingerprint VARCHAR(128) DEFAULT NULL;
    END IF;

    -- 1e. agent_runs.started_at
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'agent_runs'
          AND COLUMN_NAME = 'started_at'
    ) THEN
        ALTER TABLE agent_system.agent_runs
            ADD COLUMN started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6);
    END IF;

    -- 1f. agent_runs.completed_at
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = 'agent_system'
          AND TABLE_NAME = 'agent_runs'
          AND COLUMN_NAME = 'completed_at'
    ) THEN
        ALTER TABLE agent_system.agent_runs
            ADD COLUMN completed_at TIMESTAMP(6) NULL DEFAULT NULL;
    END IF;

END //

DELIMITER ;

-- Execute the idempotent procedure
CALL apply_step24_patch();

-- Clean up temporary procedure
DROP PROCEDURE IF EXISTS apply_step24_patch;

-- ------------------------------------------------------------------------------
-- 2. Create dedicated audit_events table (Append-Only, ON DELETE RESTRICT)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    audit_id VARCHAR(64) NOT NULL,
    run_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    component VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    reason_code VARCHAR(64) DEFAULT NULL,
    proposed_sql TEXT DEFAULT NULL,
    validated_sql TEXT DEFAULT NULL,
    executed_sql TEXT DEFAULT NULL,
    analytics_operation VARCHAR(64) DEFAULT NULL,
    formula VARCHAR(255) DEFAULT NULL,
    evidence_summary TEXT DEFAULT NULL,
    model_name VARCHAR(128) DEFAULT NULL,
    prompt_tokens INT UNSIGNED DEFAULT NULL,
    completion_tokens INT UNSIGNED DEFAULT NULL,
    duration_ms BIGINT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (audit_id),
    KEY idx_audit_run (run_id),
    KEY idx_audit_created (created_at),
    CONSTRAINT fk_audit_run FOREIGN KEY (run_id) 
        REFERENCES agent_runs (run_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- 3. Configure exact least-privilege permissions for agent_app
-- ------------------------------------------------------------------------------

-- Grant SELECT, INSERT on audit_events (APPEND-ONLY: UPDATE, DELETE, CREATE, ALTER, DROP strictly withheld)
GRANT SELECT, INSERT ON agent_system.audit_events TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';

-- Grant SELECT, INSERT, UPDATE on lifecycle state tables
GRANT SELECT, INSERT, UPDATE ON agent_system.chat_sessions TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON agent_system.agent_runs TO 'agent_app'@'localhost', 'agent_app'@'127.0.0.1';

FLUSH PRIVILEGES;
