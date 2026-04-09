-- V1: Audit log schema
--
-- COMPLIANCE: This table is append-only. The tokenization_audit_app database user
-- has INSERT SELECT privileges only — no UPDATE or DELETE.
-- This is enforced at the PostgreSQL user privilege level AND in application code
-- (AuditLog.AppendOnlyListener) for defense in depth.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE audit_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    requester_id   VARCHAR(256) NOT NULL,
    requester_role VARCHAR(64),
    operation      VARCHAR(32)  NOT NULL
                   CHECK (operation IN ('TOKENIZE','DETOKENIZE','MASK','ROTATE_KEY','LIST_TOKENS','VIEW_AUDIT')),
    data_type      VARCHAR(64)  NOT NULL,
    token_id       VARCHAR(256),
    source_ip      VARCHAR(64),
    tenant_id      VARCHAR(128) NOT NULL,
    success        BOOLEAN      NOT NULL,
    failure_reason VARCHAR(512)
);

CREATE INDEX idx_audit_requester  ON audit_logs (requester_id);
CREATE INDEX idx_audit_timestamp  ON audit_logs (timestamp DESC);
CREATE INDEX idx_audit_tenant     ON audit_logs (tenant_id);
CREATE INDEX idx_audit_operation  ON audit_logs (operation);

COMMENT ON TABLE audit_logs IS
    'Immutable audit trail for all tokenization operations. '
    'Satisfies PCI DSS Req 10, HIPAA §164.312(b), and SOX Sec 404.';
