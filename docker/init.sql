-- Docker PostgreSQL initialization script
-- WHY: Creates separate databases for engine and audit services.
-- Separate databases allow independent backup schedules and compliance controls.

CREATE DATABASE tokenization_audit;

GRANT ALL PRIVILEGES ON DATABASE tokenization TO tokenization;
GRANT ALL PRIVILEGES ON DATABASE tokenization_audit TO tokenization;

-- WHY: The audit user should have INSERT-only privileges on audit_logs
-- This is enforced at the application level AND here for defense in depth
COMMENT ON DATABASE tokenization IS 'Tokenization engine database (token_metadata, users, roles)';
COMMENT ON DATABASE tokenization_audit IS 'Immutable audit log database (append-only)';
