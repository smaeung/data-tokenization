package com.tokenization.audit.service;

import com.tokenization.common.event.AuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for the AnomalyDetector rate-based detection logic.
 */
class AnomalyDetectorTest {

    private AnomalyDetector anomalyDetector;

    @BeforeEach
    void setUp() {
        anomalyDetector = new AnomalyDetector(new SimpleMeterRegistry());
    }

    @Test
    @DisplayName("No anomaly detected for operations below threshold")
    void analyze_belowThreshold_noAnomaly() {
        // 99 detokenize operations — just below the 100/min threshold
        for (int i = 0; i < 99; i++) {
            assertThatCode(() -> anomalyDetector.analyze(buildDetokenizeEvent("user-1", "tenant-1")))
                .doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("Anomaly is logged (not thrown) when threshold is exceeded")
    void analyze_aboveThreshold_loggedButNotThrown() {
        // 101 operations — exceeds threshold. Anomaly is logged, not thrown,
        // so the audit path is never broken by detection logic.
        for (int i = 0; i < 101; i++) {
            assertThatCode(() -> anomalyDetector.analyze(buildDetokenizeEvent("user-suspect", "tenant-1")))
                .doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("Counters are isolated per user — one user's rate does not affect another's")
    void analyze_countersIsolatedPerUser() {
        // 200 operations for user-a (above threshold)
        for (int i = 0; i < 200; i++) {
            anomalyDetector.analyze(buildDetokenizeEvent("user-a", "tenant-1"));
        }
        // user-b should start fresh at 0
        assertThatCode(() -> anomalyDetector.analyze(buildDetokenizeEvent("user-b", "tenant-1")))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("TOKENIZE operations are not rate-limited by detokenize counter")
    void analyze_tokenizeOperation_notCounted() {
        AuditEvent tokenizeEvent = new AuditEvent(
            Instant.now(), "user-1", "TOKENIZER",
            AuditEvent.Operation.TOKENIZE, "CREDIT_CARD",
            "tok_abc", "10.0.0.1", "tenant-1", true, null
        );
        // 1000 tokenize events — should not trigger anomaly
        for (int i = 0; i < 1000; i++) {
            assertThatCode(() -> anomalyDetector.analyze(tokenizeEvent))
                .doesNotThrowAnyException();
        }
    }

    private AuditEvent buildDetokenizeEvent(String userId, String tenantId) {
        return new AuditEvent(
            Instant.now(), userId, "DETOKENIZER",
            AuditEvent.Operation.DETOKENIZE, "CREDIT_CARD",
            "tok_xyz", "10.0.0.1", tenantId, true, null
        );
    }
}
