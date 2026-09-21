-- ==============================================================================
-- AGENT SYSTEM SCHEMA: RUNTIME STATE, AUDIT & PERSISTENCE
-- ==============================================================================
-- Purpose:
-- Completely separates agent application metadata, conversation history,
-- run provenance, detailed audit events, and report tracking from business data
-- (sakila_extended).
--
-- Security:
-- Managed exclusively by the 'agent_app' MySQL user. The 'bi_reader' account
-- has ZERO permissions on this schema.
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS agent_system;
USE agent_system;

-- ------------------------------------------------------------------------------
-- Table 1: chat_sessions (Conversation Session Management)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'New Conversation',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Table 2: agent_runs (D.A.T.A. Execution Audit & SQL Provenance)
-- ------------------------------------------------------------------------------
-- Canonical source of truth for agent execution attempts, tool runs, generated SQL,
-- and assessment results with full database context provenance.
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    user_prompt TEXT NOT NULL,
    diagnosed_intent VARCHAR(255) DEFAULT NULL,
    database_context_id VARCHAR(64) DEFAULT NULL,
    database_name VARCHAR(64) DEFAULT NULL,
    schema_fingerprint VARCHAR(128) DEFAULT NULL,
    sql_generated TEXT DEFAULT NULL,
    sql_valid BOOLEAN NOT NULL DEFAULT 0,
    execution_status ENUM(
        'IN_PROGRESS', 'SUCCESS', 'VALIDATION_FAILED', 'SQL_ERROR',
        'SECURITY_BLOCKED', 'MODEL_ERROR', 'TIMEOUT', 'NEEDS_REVIEW'
    ) NOT NULL DEFAULT 'IN_PROGRESS',
    attempt_count TINYINT UNSIGNED NOT NULL DEFAULT 1,
    assessment_passed BOOLEAN DEFAULT NULL,
    execution_time_ms BIGINT UNSIGNED DEFAULT NULL,
    row_count INT UNSIGNED DEFAULT NULL,
    error_message TEXT DEFAULT NULL,
    started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at TIMESTAMP(6) NULL DEFAULT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (run_id),
    KEY idx_run_session (session_id),
    KEY idx_run_status (execution_status),
    KEY idx_run_time (created_at),
    CONSTRAINT fk_run_session FOREIGN KEY (session_id) 
        REFERENCES chat_sessions (session_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Table 3: chat_messages (Conversation History & UI Presentation)
-- ------------------------------------------------------------------------------
-- Normalized message log linked to canonical agent_runs for execution provenance.
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id VARCHAR(64) NOT NULL,
    run_id VARCHAR(64) DEFAULT NULL,
    role ENUM('user', 'assistant', 'system') NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (message_id),
    KEY idx_session_time (session_id, created_at),
    KEY idx_message_run (run_id),
    CONSTRAINT fk_chat_session FOREIGN KEY (session_id) 
        REFERENCES chat_sessions (session_id) ON DELETE CASCADE,
    CONSTRAINT fk_chat_run FOREIGN KEY (run_id) 
        REFERENCES agent_runs (run_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Table 4: reports (Generated ReportLab PDFs, CSVs, and Visual Exports)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    report_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    run_id VARCHAR(64) DEFAULT NULL,
    title VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    format ENUM('PDF', 'CSV', 'PNG') NOT NULL,
    summary TEXT DEFAULT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (report_id),
    KEY idx_report_session (session_id),
    KEY idx_report_run (run_id),
    CONSTRAINT fk_report_session FOREIGN KEY (session_id) 
        REFERENCES chat_sessions (session_id) ON DELETE CASCADE,
    CONSTRAINT fk_report_run FOREIGN KEY (run_id) 
        REFERENCES agent_runs (run_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Table 5: audit_events (Granular Operational & Security Audit Events)
-- ------------------------------------------------------------------------------
-- Append-only event store recording discrete tool calls, firewall decisions,
-- analytics operations, and local model inference metrics.
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
