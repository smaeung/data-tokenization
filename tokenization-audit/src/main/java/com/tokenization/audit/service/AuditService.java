package com.tokenization.audit.service;

import com.tokenization.audit.entity.AuditLog;
import com.tokenization.audit.repository.AuditLogRepository;
import com.tokenization.audit.service.AnomalyDetector;
import com.tokenization.common.event.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for recording audit events to the immutable audit log.
 *
 * <p>WHY: @Async + @EventListener makes audit logging non-blocking.
 * The tokenization engine publishes events via Spring's ApplicationEventPublisher,
 * and this service picks them up in a separate thread pool.
 * This design ensures audit logging never contributes to P99 latency (NFR-001).</p>
 *
 * <p>COMPLIANCE: Every call to logEvent produces a permanent, immutable record
 * satisfying PCI DSS Req 10.2 (log all individual access to cardholder data).</p>
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository auditLogRepository;
    private final AnomalyDetector anomalyDetector;

    public AuditService(AuditLogRepository auditLogRepository, AnomalyDetector anomalyDetector) {
        this.auditLogRepository = auditLogRepository;
        this.anomalyDetector = anomalyDetector;
    }

    /**
     * Records an audit event asynchronously.
     *
     * <p>WHY: @Async means this method runs in a thread pool separate from the HTTP request thread.
     * @EventListener makes this the handler for AuditEvent Spring application events.
     * The combination enables fire-and-forget audit logging with no impact on request latency.</p>
     *
     * <p>SECURITY: This method must NEVER be called with plaintext sensitive data.
     * The AuditEvent type enforces this by design (it has no plaintext field).</p>
     */
    @Async
    @EventListener
    @Transactional
    public void logEvent(AuditEvent event) {
        try {
            AuditLog auditLog = mapToEntity(event);
            auditLogRepository.save(auditLog);

            // Check for anomalous patterns (e.g., mass detokenization)
            anomalyDetector.analyze(event);

            log.debug("Audit event recorded: operation={}, requesterId={}, tokenId={}",
                event.operation(), event.requesterId(), event.tokenId());
        } catch (Exception e) {
            // WHY: Log audit failures but DO NOT propagate the exception.
            // A failure in audit logging must not fail the original business operation.
            // Alert monitoring systems separately via structured log output.
            log.error("AUDIT_FAILURE: Failed to record audit event for operation={}, requesterId={}. " +
                "This is a compliance incident — investigate immediately.",
                event.operation(), event.requesterId(), e);
        }
    }

    private AuditLog mapToEntity(AuditEvent event) {
        AuditLog entity = new AuditLog();
        entity.setTimestamp(event.timestamp());
        entity.setRequesterId(event.requesterId());
        entity.setRequesterRole(event.requesterRole());
        entity.setOperation(event.operation());
        entity.setDataType(event.dataType());
        entity.setTokenId(event.tokenId());
        entity.setSourceIp(event.sourceIp());
        entity.setTenantId(event.tenantId());
        entity.setSuccess(event.success());
        entity.setFailureReason(event.failureReason());
        return entity;
    }
}
