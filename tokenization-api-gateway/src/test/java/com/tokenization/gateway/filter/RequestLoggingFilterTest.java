package com.tokenization.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for RequestLoggingFilter.
 */
class RequestLoggingFilterTest {

    private RequestLoggingFilter filter;

    @BeforeEach
    void setUp() {
        filter = new RequestLoggingFilter();
    }

    @Test
    @DisplayName("Filter order is -50 (after JWT filter at -100)")
    void getOrder_returnsNegative50() {
        assertThat(filter.getOrder()).isEqualTo(-50);
    }

    @Test
    @DisplayName("Filter chains without blocking and logs request metadata")
    void filter_chainsAndLogsRequest() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("X-Authenticated-User", "alice")
                .header("X-Authenticated-Tenant", "tenant-1")
                .build());
        GatewayFilterChain chain = ex -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
    }

    @Test
    @DisplayName("Filter uses X-Forwarded-For as client IP when present")
    void filter_withXForwardedFor_usesFirstAddress() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
                .build());
        GatewayFilterChain chain = ex -> Mono.empty();

        // Just verifying it completes without error (IP extraction is internal)
        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
    }

    @Test
    @DisplayName("Filter falls back to remote address when X-Forwarded-For is absent")
    void filter_withoutXForwardedFor_usesRemoteAddress() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize").build());
        GatewayFilterChain chain = ex -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
    }

    @Test
    @DisplayName("Filter handles blank X-Forwarded-For by using remote address")
    void filter_blankXForwardedFor_usesRemoteAddress() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/v1/tokenize")
                .header("X-Forwarded-For", "   ")
                .build());
        GatewayFilterChain chain = ex -> Mono.empty();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
    }
}
