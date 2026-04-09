package com.tokenization.audit.entity;

import com.tokenization.common.event.AuditEvent;
import jakarta.persistence.*;
import java.time.Instant;

/**
 * JPA entity for the immutable audit log.
 *
 * <p>WHY: The audit_logs table is APPEND-ONLY by design:
 * <ul>
 *   <li>The application database user has INSERT privileges only — no UPDATE/DELETE</li>
 *   <li>The @PreUpdate and @PreRemove callbacks throw exceptions as an extra guard</li>
 *   <li>This ensures the audit trail cannot be tampered with even if the application is compromised</li>
 * </ul></p>
 *
 * <p>COMPLIANCE: Immutable audit logs satisfy:
 * - PCI DSS Req 10.3: Protect audit logs from modification
 * - HIPAA §164.312(b): Implement hardware, software, and procedural mechanisms to record activity
 * - SOX Section 404: Maintain records to demonstrate internal controls</p>
 *
 * <p>SECURITY: This entity intentionally contains NO plaintext sensitive data.
 * The tokenId is safe to log — it cannot be reversed without the cryptographic key
 * AND passing RBAC authorization checks.</p>
 */
@Entity
@Table(name = "audit_logs", indexes = {
    // WHY: Index on requester_id for querying a user's activity (anomaly detection)
    @Index(name = "idx_audit_requester", columnList = "requester_id"),
    // WHY: Index on timestamp for time-range queries in the audit UI
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    // WHY: Index on tenant_id for multi-tenant audit isolation
    @Index(name = "idx_audit_tenant", columnList = "tenant_id")
})
@EntityListeners(AuditLog.AppendOnlyListener.class)
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;

    @Column(name = "requester_id", nullable = false, length = 256)
    private String requesterId;

    @Column(name = "requester_role", length = 64)
    private String requesterRole;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation", nullable = false, length = 32)
    private AuditEvent.Operation operation;

    @Column(name = "data_type", nullable = false, length = 64)
    private String dataType;

    /** Token ID — safe to log, cannot be reversed without key + RBAC. */
    @Column(name = "token_id", length = 256)
    private String tokenId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId;

    @Column(name = "success", nullable = false)
    private boolean success;

    /**
     * Failure reason — may contain error codes but NEVER sensitive data.
     * WHY: Logging failure reasons helps security teams analyze access patterns.
     */
    @Column(name = "failure_reason", length = 512)
    private String failureReason;

    public String getId() { return id; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getRequesterId() { return requesterId; }
    public void setRequesterId(String requesterId) { this.requesterId = requesterId; }
    public String getRequesterRole() { return requesterRole; }
    public void setRequesterRole(String requesterRole) { this.requesterRole = requesterRole; }
    public AuditEvent.Operation getOperation() { return operation; }
    public void setOperation(AuditEvent.Operation operation) { this.operation = operation; }
    public String getDataType() { return dataType; }
    public void setDataType(String dataType) { this.dataType = dataType; }
    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }

    /**
     * JPA entity listener that enforces the append-only constraint in application code.
     *
     * <p>WHY: While the database enforces this via user privilege restrictions,
     * this listener provides a defense-in-depth guard at the JPA layer.
     * An accidental update in code fails loudly rather than silently corrupting the audit trail.</p>
     */
    public static class AppendOnlyListener {
        @PreUpdate
        public void preUpdate(AuditLog log) {
            throw new IllegalStateException(
                "Audit log records are immutable. Update denied for id: " + log.getId());
        }

        @PreRemove
        public void preRemove(AuditLog log) {
            throw new IllegalStateException(
                "Audit log records are immutable. Delete denied for id: " + log.getId());
        }
    }
}
