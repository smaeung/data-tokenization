package com.tokenization.gateway.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Global JWT authentication filter for all gateway routes.
 *
 * <p>WHY GlobalFilter: Applied to ALL routes automatically, preventing any request
 * from bypassing authentication. Route-specific filters could be accidentally omitted.</p>
 *
 * <p>WHY order = -100: Higher priority (lower number) ensures this filter runs
 * before Spring Security's own filters. The identity established here is trusted
 * by downstream services via the X-Authenticated-User header.</p>
 *
 * <p>SECURITY:
 * <ul>
 *   <li>JWT signature is verified against the shared secret on EVERY request</li>
 *   <li>Expiration is checked — expired tokens are rejected</li>
 *   <li>Claims are forwarded as headers so backends don't need to re-parse the JWT</li>
 *   <li>The Authorization header is REMOVED before forwarding to prevent downstream
 *       services from accidentally trusting it (they trust the injected X- headers instead)</li>
 * </ul></p>
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // Endpoints that don't require authentication
    private static final List<String> PUBLIC_PATHS = List.of(
        "/actuator/health",
        "/actuator/info",
        "/api/v1/auth/login",
        "/api/v1/auth/token"
    );

    @Value("${jwt.secret:dev-secret-change-in-production-must-be-256-bits}")
    private String jwtSecret;

    @Override
    public int getOrder() {
        // WHY -100: Run before Spring Security default filters (order 0)
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Skip authentication for public endpoints
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for path: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        try {
            Claims claims = parseJwt(token);

            String username = claims.getSubject();
            String role = claims.get("role", String.class);
            String tenantId = claims.get("tenantId", String.class);

            // WHY: Forward identity claims as headers so downstream services
            // can trust the authenticated identity without re-parsing JWT
            ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-Authenticated-User", username)
                .header("X-Authenticated-Role", role != null ? role : "")
                .header("X-Authenticated-Tenant", tenantId != null ? tenantId : "")
                // SECURITY: Remove original Authorization header so backends cannot
                // accidentally accept it — they should trust only the X- headers
                .headers(headers -> headers.remove("Authorization"))
                .build();

            log.debug("JWT validated for user='{}', role='{}', path='{}'", username, role, path);
            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT for path='{}': {}", path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        } catch (JwtException e) {
            // SECURITY: Generic error message to avoid leaking JWT validation details
            log.warn("Invalid JWT for path='{}': {}", path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private Claims parseJwt(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
