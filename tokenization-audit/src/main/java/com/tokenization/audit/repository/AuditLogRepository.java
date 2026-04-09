package com.tokenization.audit.repository;

import com.tokenization.audit.entity.AuditLog;
import com.tokenization.common.event.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

/**
 * Append-only JPA repository for audit log entries.
 *
 * <p>WHY: Spring Data JPA is used for querying but the repository intentionally
 * does NOT expose save/update/delete methods at the service level.
 * The AuditService is the only consumer and it only calls save() for new records.</p>
 *
 * <p>COMPLIANCE: The findByTenantId query is always filtered by tenantId to ensure
 * compliance officers can only view their tenant's audit records (multi-tenant isolation).</p>
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    /**
     * Paginated audit log query with filtering by tenant, time range, and operation.
     *
     * <p>WHY: Pagination is mandatory for audit queries — audit logs can contain millions
     * of records. Returning all records would be a denial-of-service risk.</p>
     */
    @Query("""
        SELECT a FROM AuditLog a
        WHERE a.tenantId = :tenantId
          AND (:from IS NULL OR a.timestamp >= :from)
          AND (:to IS NULL OR a.timestamp <= :to)
          AND (:operation IS NULL OR a.operation = :operation)
          AND (:requesterId IS NULL OR a.requesterId = :requesterId)
        ORDER BY a.timestamp DESC
        """)
    Page<AuditLog> findByFilters(
        @Param("tenantId") String tenantId,
        @Param("from") Instant from,
        @Param("to") Instant to,
        @Param("operation") AuditEvent.Operation operation,
        @Param("requesterId") String requesterId,
        Pageable pageable
    );

    /** Count detokenize operations by a specific user in the last minute (for anomaly detection). */
    @Query("""
        SELECT COUNT(a) FROM AuditLog a
        WHERE a.requesterId = :requesterId
          AND a.operation = 'DETOKENIZE'
          AND a.timestamp >= :since
        """)
    long countRecentDetokenize(@Param("requesterId") String requesterId, @Param("since") Instant since);
}
