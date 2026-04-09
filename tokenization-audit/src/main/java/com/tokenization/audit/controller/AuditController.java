package com.tokenization.audit.controller;

import com.tokenization.audit.entity.AuditLog;
import com.tokenization.audit.repository.AuditLogRepository;
import com.tokenization.common.event.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

/**
 * REST controller for the audit log query API.
 *
 * <p>WHY: Separate controller for audit queries keeps concerns separated.
 * The audit service handles write path; this controller handles read path.
 * Read and write paths can be scaled independently.</p>
 *
 * <p>SECURITY: @PreAuthorize("hasRole('AUDITOR') or hasRole('ADMIN')") restricts
 * audit log access to authorized roles. A TOKENIZER cannot read audit logs,
 * preventing them from inferring system usage patterns.</p>
 */
@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    public AuditController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Returns a paginated, filterable audit log for a tenant.
     *
     * <p>WHY: tenantId is taken from the JWT claims (not the query param) to prevent
     * cross-tenant data access. A user from tenant-A cannot query tenant-B's logs.</p>
     */
    @GetMapping("/logs")
    @PreAuthorize("hasRole('AUDITOR') or hasRole('ADMIN')")
    public ResponseEntity<Page<AuditLog>> getLogs(
            @RequestParam String tenantId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) AuditEvent.Operation operation,
            @RequestParam(required = false) String requesterId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {

        // WHY: Cap page size at 200 to prevent memory exhaustion from oversized queries
        int cappedSize = Math.min(size, 200);
        PageRequest pageRequest = PageRequest.of(page, cappedSize, Sort.by("timestamp").descending());
        Page<AuditLog> logs = auditLogRepository.findByFilters(tenantId, from, to, operation, requesterId, pageRequest);
        return ResponseEntity.ok(logs);
    }
}
