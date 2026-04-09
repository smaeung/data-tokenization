package com.tokenization.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * Integration tests for the JWT authentication filter.
 *
 * <p>WHY @SpringBootTest: We need the full Spring context including the filter chain
 * to verify JWT validation behavior end-to-end. Unit testing filters in isolation
 * is insufficient — integration matters for security tests.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "jwt.secret=test-secret-that-is-exactly-256-bits-long-for-testing",
        "spring.cloud.gateway.routes[0].id=test",
        "spring.cloud.gateway.routes[0].uri=http://localhost:8081",
        "spring.cloud.gateway.routes[0].predicates[0]=Path=/test/**"
    })
class JwtAuthenticationFilterTest {

    private static final String JWT_SECRET = "test-secret-that-is-exactly-256-bits-long-for-testing";

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @DisplayName("Health endpoint is accessible without authentication")
    void healthEndpoint_noAuth_accessible() {
        webTestClient.get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @DisplayName("Protected endpoint returns 401 without Authorization header")
    void protectedEndpoint_noToken_returns401() {
        webTestClient.post()
            .uri("/api/v1/tokenize")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Protected endpoint returns 401 with expired JWT")
    void protectedEndpoint_expiredToken_returns401() {
        String expiredToken = buildJwt("user1", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() - 10000)); // expired 10 seconds ago

        webTestClient.post()
            .uri("/api/v1/tokenize")
            .header("Authorization", "Bearer " + expiredToken)
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Protected endpoint returns 401 with tampered JWT")
    void protectedEndpoint_tamperedToken_returns401() {
        String validToken = buildJwt("user1", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() + 3600000));
        // Tamper with the token by modifying a character in the signature
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "XXXXX";

        webTestClient.post()
            .uri("/api/v1/tokenize")
            .header("Authorization", "Bearer " + tamperedToken)
            .exchange()
            .expectStatus().isUnauthorized();
    }

    private String buildJwt(String username, String role, String tenantId, Date expiration) {
        SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
            .subject(username)
            .claim("role", role)
            .claim("tenantId", tenantId)
            .expiration(expiration)
            .signWith(key)
            .compact();
    }
}
