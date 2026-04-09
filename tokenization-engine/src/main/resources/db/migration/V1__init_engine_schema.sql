-- V1: Tokenization Engine schema
-- WHY: Flyway manages schema migrations to ensure the database state
-- matches the application version. Schema changes are version-controlled.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE token_metadata (
    token_id    VARCHAR(256) PRIMARY KEY,
    data_type   VARCHAR(64)  NOT NULL,
    format      VARCHAR(64)  NOT NULL,
    -- WHY: key_version is critical for key rotation support.
    -- We must use the same key version that was used during tokenization.
    key_version INTEGER      NOT NULL,
    tenant_id   VARCHAR(128) NOT NULL,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX idx_token_tenant   ON token_metadata (tenant_id);
CREATE INDEX idx_token_datatype ON token_metadata (tenant_id, data_type);

COMMENT ON TABLE token_metadata IS
    'Vaultless tokenization metadata. Does NOT store plaintext or token-to-plaintext mappings. '
    'Key version stored here enables detokenization after key rotation.';

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(256) UNIQUE NOT NULL,
    -- SECURITY: BCrypt hash with cost factor 12 minimum
    password_hash VARCHAR(512) NOT NULL,
    enabled       BOOLEAN DEFAULT true,
    tenant_id     VARCHAR(128) NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE roles (
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Seed default roles
INSERT INTO roles (name) VALUES
    ('ROLE_ADMIN'),
    ('ROLE_TOKENIZER'),
    ('ROLE_DETOKENIZER'),
    ('ROLE_AUDITOR'),
    ('ROLE_READ_ONLY');
