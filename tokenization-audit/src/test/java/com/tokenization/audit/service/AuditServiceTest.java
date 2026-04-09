package com.tokenization.audit.service;

import com.tokenization.audit.entity.AuditLog;
import com.tokenization.audit.repository.AuditLogRepository;
import com.tokenization.common.event.AuditEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock AuditLogRepository auditLogRepository;
    @Mock AnomalyDetector anomalyDetector;

    AuditService auditService;

    @BeforeEach
    void setUp() {
        auditService = new AuditService(auditLogRepository, anomalyDetector);
    }

    @Test
    void logEvent_savesAuditLogWithAllFields() {
        AuditEvent event = buildEvent(AuditEvent.Operation.TOKENIZE, true, null);

        auditService.logEvent(event);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog log = captor.getValue();
        assertThat(log.getRequesterId()).isEqualTo("alice");
        assertThat(log.getRequesterRole()).isEqualTo("ROLE_TOKENIZER");
        assertThat(log.getOperation()).isEqualTo(AuditEvent.Operation.TOKENIZE);
        assertThat(log.getDataType()).isEqualTo("CREDIT_CARD");
        assertThat(log.getTokenId()).isEqualTo("tok_abc");
        assertThat(log.getTenantId()).isEqualTo("tenant-1");
        assertThat(log.isSuccess()).isTrue();
        assertThat(log.getFailureReason()).isNull();
    }

    @Test
    void logEvent_delegatesToAnomalyDetector() {
        AuditEvent event = buildEvent(AuditEvent.Operation.DETOKENIZE, true, null);

        auditService.logEvent(event);

        verify(anomalyDetector).analyze(event);
    }

    @Test
    void logEvent_onRepositoryFailure_doesNotPropagateException() {
        doThrow(new RuntimeException("DB error")).when(auditLogRepository).save(any());
        AuditEvent event = buildEvent(AuditEvent.Operation.TOKENIZE, true, null);

        // Must not throw — audit failure must never fail the original operation
        auditService.logEvent(event);
    }

    @Test
    void logEvent_recordsFailedOperation() {
        AuditEvent event = buildEvent(AuditEvent.Operation.TOKENIZE, false, "FF1 error");

        auditService.logEvent(event);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        assertThat(captor.getValue().isSuccess()).isFalse();
        assertThat(captor.getValue().getFailureReason()).isEqualTo("FF1 error");
    }

    private AuditEvent buildEvent(AuditEvent.Operation operation, boolean success, String failureReason) {
        return new AuditEvent(
            Instant.now(), "alice", "ROLE_TOKENIZER", operation,
            "CREDIT_CARD", "tok_abc", "127.0.0.1", "tenant-1", success, failureReason
        );
    }
}
