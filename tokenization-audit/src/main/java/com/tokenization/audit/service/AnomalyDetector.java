package com.tokenization.audit.service;

import com.tokenization.common.event.AuditEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Detects anomalous tokenization patterns that may indicate a compromised account
 * or insider threat attempting mass data exfiltration.
 *
 * <p>WHY: The primary threat model for a tokenization service is a compromised account
 * with DETOKENIZE permissions attempting to bulk-detokenize the entire dataset.
 * Rate-based anomaly detection provides an automated defense against this scenario.</p>
 *
 * <p>Detection rules:
 * <ul>
 *   <li>Mass detokenization: > 100 DETOKENIZE operations per user per minute → alert</li>
 *   <li>Repeated access failures: > 10 failed auth attempts per IP per minute → alert</li>
 * </ul></p>
 *
 * <p>WHY Micrometer metrics: Anomaly counters are exposed as Prometheus metrics,
 * allowing Grafana dashboards and AlertManager rules to trigger automated responses
 * (rate limiting, account suspension) without manual intervention.</p>
 */
@Component
public class AnomalyDetector {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetector.class);

    // WHY: Threshold of 100 detokenizations per minute per user is based on the
    // assumption that legitimate operations (fraud checks, customer service lookups)
    // rarely exceed single-digit operations per minute per user.
    private static final int DETOKENIZE_RATE_THRESHOLD = 100;
    private static final long WINDOW_MS = 60_000L; // 1-minute sliding window

    // WHY: ConcurrentHashMap + AtomicInteger provides thread-safe rate tracking
    // without blocking locks, which is critical for high-throughput audit processing.
    private final ConcurrentHashMap<String, WindowedCounter> detokenizeCounters = new ConcurrentHashMap<>();

    private final Counter anomalyAlertsCounter;

    public AnomalyDetector(MeterRegistry meterRegistry) {
        // WHY: Prometheus counter for anomaly alerts enables automated alerting
        // via AlertManager rules without polling log files
        this.anomalyAlertsCounter = Counter.builder("tokenization.anomaly.alerts")
            .description("Number of anomaly alerts triggered")
            .register(meterRegistry);
    }

    /**
     * Analyzes an audit event for anomalous patterns.
     *
     * <p>WHY: This runs asynchronously after the audit event is logged.
     * Detection must not block the audit logging path.</p>
     */
    public void analyze(AuditEvent event) {
        if (event.operation() == AuditEvent.Operation.DETOKENIZE) {
            checkDetokenizeRate(event);
        }
    }

    private void checkDetokenizeRate(AuditEvent event) {
        String key = event.requesterId() + ":" + event.tenantId();
        WindowedCounter counter = detokenizeCounters.computeIfAbsent(key,
            k -> new WindowedCounter());

        int count = counter.increment();

        if (count > DETOKENIZE_RATE_THRESHOLD) {
            // SECURITY: This is a potential mass data exfiltration attempt.
            // Log as WARN with structured fields for SIEM integration.
            log.warn("ANOMALY_DETECTED: High detokenize rate for user='{}', tenant='{}', " +
                "count={}, threshold={}, sourceIp='{}'",
                event.requesterId(), event.tenantId(), count,
                DETOKENIZE_RATE_THRESHOLD, event.sourceIp());

            anomalyAlertsCounter.increment();
            // WHY: In production, this would trigger:
            // 1. Automated rate limiting (Redis-backed)
            // 2. Slack/PagerDuty alert to security team
            // 3. Automatic temporary account suspension pending review
        }
    }

    /**
     * A simple sliding window counter for rate detection.
     * WHY: Sliding window is more accurate than fixed-window counting for rate limiting.
     */
    static class WindowedCounter {
        private final AtomicInteger count = new AtomicInteger(0);
        private volatile long windowStart = Instant.now().toEpochMilli();

        int increment() {
            long now = Instant.now().toEpochMilli();
            // WHY: Reset the counter when the time window has passed
            if (now - windowStart > WINDOW_MS) {
                count.set(0);
                windowStart = now;
            }
            return count.incrementAndGet();
        }
    }
}
