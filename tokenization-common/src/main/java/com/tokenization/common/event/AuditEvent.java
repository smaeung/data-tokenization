package com.tokenization.common.event;

import java.time.Instant;

/**
 * Immutable audit event record capturing the metadata of every tokenization operation.
 *
 * <p>WHY: Audit events are immutable records (Java record type) to prevent accidental
 * modification after creation. Every field is required — the audit trail must be complete.</p>
 *
 * <p>COMPLIANCE: This event structure satisfies PCI DSS Requirement 10 (logging and monitoring),
 * HIPAA §164.312(b) (audit controls), and SOX audit trail requirements.</p>
 *
 * <p>SECURITY: The 'plaintext' field is intentionally absent — audit events NEVER contain
 * original sensitive data. Token IDs are safe to log as they cannot be reversed without
 * the cryptographic key and RBAC authorization.</p>
 */
public record AuditEvent(

    /** UTC timestamp of the operation. */
    Instant timestamp,

    /** Identity of the requester (username or service account ID). */
    String requesterId,

    /** Role of the requester at the time of the operation. */
    String requesterRole,

    /** The operation performed: TOKENIZE, DETOKENIZE, MASK, ROTATE_KEY. */
    Operation operation,

    /** The category of data involved (CREDIT_CARD, SSN, etc.). Not the actual value. */
    String dataType,

    /**
     * The token ID involved. Safe to log — cannot be reversed without key + RBAC.
     * WHY: Logging tokenId enables correlating audit records across tokenize/detokenize pairs.
     */
    String tokenId,

    /** Source IP address of the request. Used for anomaly detection. */
    String sourceIp,

    /** Tenant context of the operation. */
    String tenantId,

    /** Whether the operation succeeded. */
    boolean success,

    /**
     * Failure reason if the operation failed. MUST NOT contain plaintext data.
     * WHY: Logging failure reasons helps security teams investigate unauthorized access attempts.
     */
    String failureReason

) {

    /**
     * Enumeration of audit-tracked operations.
     * WHY: Using an enum prevents typos in operation names and enables type-safe
     * filtering in audit log queries.
     */
    public enum Operation {
        TOKENIZE,
        DETOKENIZE,
        MASK,
        ROTATE_KEY,
        LIST_TOKENS,
        VIEW_AUDIT
    }
}
