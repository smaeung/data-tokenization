package com.tokenization.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Audit Service — records all tokenization events immutably.
 *
 * <p>WHY: @EnableAsync enables non-blocking audit event processing.
 * Audit recording must never block the main tokenization path (NFR-001: P99 < 50ms).</p>
 *
 * <p>COMPLIANCE: This service satisfies PCI DSS Requirement 10 (logging and monitoring),
 * HIPAA §164.312(b) (audit controls), and SOX audit trail requirements.</p>
 */
@SpringBootApplication
@EnableAsync
public class AuditApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuditApplication.class, args);
    }
}
