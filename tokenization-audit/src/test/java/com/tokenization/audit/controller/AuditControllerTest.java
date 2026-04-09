package com.tokenization.audit.controller;

import com.tokenization.audit.entity.AuditLog;
import com.tokenization.audit.repository.AuditLogRepository;
import com.tokenization.common.event.AuditEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditControllerTest {

    @Mock AuditLogRepository auditLogRepository;

    AuditController controller;

    @BeforeEach
    void setUp() {
        controller = new AuditController(auditLogRepository);
    }

    @Test
    void getLogs_returns200WithPage() {
        Page<AuditLog> page = new PageImpl<>(List.of(new AuditLog()));
        when(auditLogRepository.findByFilters(any(), any(), any(), any(), any(), any()))
            .thenReturn(page);

        ResponseEntity<Page<AuditLog>> result = controller.getLogs(
            "tenant-1", null, null, null, null, 0, 50);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().getContent()).hasSize(1);
    }

    @Test
    void getLogs_capsPageSizeAt200() {
        Page<AuditLog> page = new PageImpl<>(List.of());
        when(auditLogRepository.findByFilters(any(), any(), any(), any(), any(), any()))
            .thenReturn(page);

        // Request size=1000, should be capped to 200
        controller.getLogs("tenant-1", null, null, null, null, 0, 1000);

        verify(auditLogRepository).findByFilters(
            eq("tenant-1"), isNull(), isNull(), isNull(), isNull(),
            argThat(pr -> pr instanceof PageRequest &&
                ((PageRequest) pr).getPageSize() == 200));
    }

    @Test
    void getLogs_withAllFilters_passesThemToRepository() {
        Instant from = Instant.parse("2026-01-01T00:00:00Z");
        Instant to = Instant.parse("2026-12-31T23:59:59Z");
        Page<AuditLog> page = new PageImpl<>(List.of());
        when(auditLogRepository.findByFilters(any(), any(), any(), any(), any(), any()))
            .thenReturn(page);

        controller.getLogs("tenant-1", from, to, AuditEvent.Operation.TOKENIZE, "alice", 0, 25);

        verify(auditLogRepository).findByFilters(
            eq("tenant-1"), eq(from), eq(to),
            eq(AuditEvent.Operation.TOKENIZE), eq("alice"), any());
    }

    @Test
    void getLogs_emptyResult_returns200WithEmptyPage() {
        Page<AuditLog> emptyPage = new PageImpl<>(List.of());
        when(auditLogRepository.findByFilters(any(), any(), any(), any(), any(), any()))
            .thenReturn(emptyPage);

        ResponseEntity<Page<AuditLog>> result = controller.getLogs(
            "tenant-1", null, null, null, null, 0, 50);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody().getContent()).isEmpty();
    }
}
