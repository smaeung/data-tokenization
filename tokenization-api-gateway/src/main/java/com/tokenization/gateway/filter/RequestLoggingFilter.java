package com.tokenization.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Logs request metadata for all inbound requests — WITHOUT logging request bodies.
 *
 * <p>SECURITY: Request bodies MUST NOT be logged because they may contain:
 * <ul>
 *   <li>Plaintext sensitive data in POST /api/v1/tokenize requests</li>
 *   <li>Recovered plaintext in POST /api/v1/detokenize responses</li>
 * </ul>
 * Logging these would create a compliance violation (PCI DSS Req 3.3: don't store sensitive auth data).</p>
 *
 * <p>WHY we DO log: Method, path, user identity, response status, and latency are safe
 * to log and essential for:
 * <ul>
 *   <li>Debugging operational issues</li>
 *   <li>SIEM integration for security monitoring</li>
 *   <li>Performance analysis (P99 latency tracking)</li>
 * </ul></p>
 */
@Component
public class RequestLoggingFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public int getOrder() {
        // WHY -50: Run after JWT filter (order -100) so we can log the authenticated user
        return -50;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        long startTime = System.currentTimeMillis();

        // Extract safe-to-log metadata — NO request body
        String method = request.getMethod().name();
        String path = request.getURI().getPath();
        String user = request.getHeaders().getFirst("X-Authenticated-User");
        String tenant = request.getHeaders().getFirst("X-Authenticated-Tenant");
        String clientIp = getClientIp(request);

        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            long duration = System.currentTimeMillis() - startTime;
            int status = exchange.getResponse().getStatusCode() != null
                ? exchange.getResponse().getStatusCode().value() : 0;

            // WHY structured logging: JSON-parseable logs can be ingested by
            // Elasticsearch/SIEM systems without custom parsing rules
            log.info("method={} path={} status={} durationMs={} user={} tenant={} clientIp={}",
                method, path, status, duration, user, tenant, clientIp);
        }));
    }

    private String getClientIp(ServerHttpRequest request) {
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddress() != null
            ? request.getRemoteAddress().getAddress().getHostAddress()
            : "unknown";
    }
}
