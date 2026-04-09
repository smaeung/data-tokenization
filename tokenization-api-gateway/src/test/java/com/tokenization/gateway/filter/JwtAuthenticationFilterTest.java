package com.tokenization.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for JwtAuthenticationFilter.
 *
 * WHY unit tests (not @SpringBootTest): The gateway integration test requires
 * Redis (rate limiting) and live backend routes — tested in the integration-tests
 * profile. Here we test the security-critical JWT validation logic in isolation.
 */
class JwtAuthenticationFilterTest {

    private static final String JWT_SECRET = "test-secret-that-is-exactly-256-bits-long-for-testing";
    private SecretKey signingKey;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        signingKey = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
        filter = new JwtAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "jwtSecret", JWT_SECRET);
    }

    @Test
    @DisplayName("Filter order is -100 (highest priority)")
    void getOrder_returnsNegative100() {
        assertThat(filter.getOrder()).isEqualTo(-100);
    }

    @Test
    @DisplayName("Public path /actuator/health passes without authentication")
    void filter_publicPath_chainsWithoutAuth() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/actuator/health").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> { chainCalled.set(true); return Mono.empty(); };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("Public path /api/v1/auth/login passes without authentication")
    void filter_loginPath_chainsWithoutAuth() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/v1/auth/login").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> { chainCalled.set(true); return Mono.empty(); };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("Missing Authorization header returns 401")
    void filter_missingAuthHeader_returns401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize").build());
        GatewayFilterChain chain = ex -> Mono.error(new AssertionError("Chain should not be called"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Non-Bearer Authorization header returns 401")
    void filter_nonBearerAuthHeader_returns401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Basic dXNlcjpwYXNz")
                .build());
        GatewayFilterChain chain = ex -> Mono.error(new AssertionError("Chain should not be called"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Valid JWT passes and downstream receives identity headers")
    void filter_validJwt_chainsWithIdentityHeaders() {
        String token = buildJwt("alice", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() + 3_600_000));

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + token)
                .build());
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            assertThat(ex.getRequest().getHeaders().getFirst("X-Authenticated-User")).isEqualTo("alice");
            assertThat(ex.getRequest().getHeaders().getFirst("X-Authenticated-Role")).isEqualTo("ROLE_TOKENIZER");
            assertThat(ex.getRequest().getHeaders().getFirst("X-Authenticated-Tenant")).isEqualTo("tenant-1");
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("Valid JWT: original Authorization header is removed before forwarding")
    void filter_validJwt_removesAuthorizationHeader() {
        String token = buildJwt("alice", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() + 3_600_000));
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + token)
                .build());
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            assertThat(ex.getRequest().getHeaders().getFirst("Authorization")).isNull();
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("Expired JWT returns 401")
    void filter_expiredJwt_returns401() {
        String expired = buildJwt("alice", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() - 10_000));
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + expired)
                .build());
        GatewayFilterChain chain = ex -> Mono.error(new AssertionError("Chain should not be called"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Malformed JWT returns 401")
    void filter_malformedJwt_returns401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer not.a.valid.jwt")
                .build());
        GatewayFilterChain chain = ex -> Mono.error(new AssertionError("Chain should not be called"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("JWT with missing role claim uses empty string for X-Authenticated-Role header")
    void filter_jwtWithNullRole_usesEmptyRoleHeader() {
        String token = Jwts.builder().subject("svc")
            .claim("tenantId", "tenant-1")
            .expiration(new Date(System.currentTimeMillis() + 3_600_000))
            .signWith(signingKey).compact();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + token)
                .build());
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            assertThat(ex.getRequest().getHeaders().getFirst("X-Authenticated-Role")).isEqualTo("");
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("JWT with missing tenantId claim uses empty string for X-Authenticated-Tenant header")
    void filter_jwtWithNullTenant_usesEmptyTenantHeader() {
        String token = Jwts.builder().subject("svc")
            .claim("role", "ROLE_TOKENIZER")
            .expiration(new Date(System.currentTimeMillis() + 3_600_000))
            .signWith(signingKey).compact();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + token)
                .build());
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            assertThat(ex.getRequest().getHeaders().getFirst("X-Authenticated-Tenant")).isEqualTo("");
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(chainCalled).isTrue();
    }

    @Test
    @DisplayName("JWT signed with wrong key returns 401")
    void filter_wrongKeyJwt_returns401() {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
            "wrong-key-that-is-also-256-bits-long-for-test".getBytes(StandardCharsets.UTF_8));
        String tampered = Jwts.builder().subject("attacker")
            .claim("role", "ROLE_ADMIN")
            .expiration(new Date(System.currentTimeMillis() + 3_600_000))
            .signWith(wrongKey).compact();
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("Authorization", "Bearer " + tampered)
                .build());
        GatewayFilterChain chain = ex -> Mono.error(new AssertionError("Chain should not be called"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String buildJwt(String username, String role, String tenantId, Date expiration) {
        return Jwts.builder().subject(username)
            .claim("role", role).claim("tenantId", tenantId)
            .expiration(expiration).signWith(signingKey).compact();
    }
}
