# Functional Requirements — Data Tokenization Service

## Overview
This document defines the functional requirements for the vaultless Data Tokenization Service API, a production-grade system for replacing sensitive data with format-preserving surrogate tokens using NIST-approved FF1 Format-Preserving Encryption.

## FR-001: Format-Preserving Tokenization
- The system SHALL replace sensitive input data with a token of identical length and character set
- Numeric inputs SHALL produce numeric tokens (e.g., 16-digit PAN → 16-digit token)
- Alphanumeric inputs SHALL produce alphanumeric tokens
- The domain size MUST be ≥ 1,000,000 possible values to prevent mathematical recovery attacks (NIST SP 800-38G requirement)

## FR-002: RBAC-Enforced Detokenization
- Only principals with the `DETOKENIZE` permission SHALL be allowed to reverse a token to plaintext
- The system SHALL evaluate both Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) policies before granting detokenization
- Roles: ADMIN, TOKENIZER, DETOKENIZER, AUDITOR, READ_ONLY
- Permissions: TOKENIZE, DETOKENIZE_PAN, DETOKENIZE_PHI, VIEW_AUDIT, MANAGE_KEYS

## FR-003: Batch Tokenization
- The system SHALL accept up to 1,000 records in a single batch tokenization request
- Each record in the batch SHALL be processed independently; partial failures SHALL be reported
- Batch responses SHALL include successCount and failureCount

## FR-004: Dynamic Data Masking
- The system SHALL support partial masking of tokens based on configurable mask patterns
- Supported mask patterns: FIRST_4, LAST_4, FIRST_6_LAST_4, FULL_MASK
- Example: Credit card 4716234512839012 → ****-****-****-9012 (LAST_4 pattern)

## FR-005: Deterministic Tokenization
- Given the same plaintext input and the same cryptographic key, the system SHALL always produce the same token
- This property enables cross-database analytics and data correlation without exposing sensitive data

## FR-006: Key Rotation Without Data Loss
- The system SHALL support cryptographic key rotation
- Token metadata SHALL store the key version used during tokenization
- Upon rotation, the system SHALL support re-tokenization migration using the old key to decrypt and new key to re-encrypt

## FR-007: Immutable Audit Trail
- The system SHALL record every tokenization, detokenization, masking, and key rotation operation
- Audit records SHALL include: timestamp, requester identity, role, operation type, data type, token ID, source IP, success/failure status
- Audit records SHALL be append-only (no UPDATE or DELETE operations permitted on the audit table)
- The system SHALL expose a paginated, filterable audit log API endpoint

## FR-008: Admin UI Portal
- The system SHALL provide a web-based admin portal for:
  - User and role management (CRUD)
  - Viewing and filtering audit logs
  - Monitoring key status and triggering key rotation
  - Viewing system health and token issuance statistics

## FR-009: Multi-Tenancy
- The system SHALL support multiple tenants, each with isolated key namespaces and audit logs
- Cross-tenant access SHALL be explicitly forbidden

## FR-010: API Authentication
- All API endpoints SHALL require authentication via JWT or API Key
- Machine-to-machine integrations SHALL use API Key authentication
- Human-facing integrations SHALL use JWT authentication
