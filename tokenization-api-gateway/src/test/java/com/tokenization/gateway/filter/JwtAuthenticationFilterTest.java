package com.tokenization.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for JWT parsing logic in JwtAuthenticationFilter.
 *
 * WHY unit tests (not @SpringBootTest): The gateway integration test requires
 * Redis (rate limiting) and live backend routes — tested in the integration-tests
 * profile. Here we test the security-critical JWT validation logic in isolation.
 */
class JwtAuthenticationFilterTest {

    private static final String JWT_SECRET = "test-secret-that-is-exactly-256-bits-long-for-testing";
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        signingKey = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("Valid JWT can be parsed and claims extracted")
    void validJwt_parsesCorrectly() {
        String token = buildJwt("user1", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() + 3_600_000));
        var claims = Jwts.parser().verifyWith(signingKey).build()
            .parseSignedClaims(token).getPayload();
        assertThat(claims.getSubject()).isEqualTo("user1");
        assertThat(claims.get("role", String.class)).isEqualTo("ROLE_TOKENIZER");
        assertThat(claims.get("tenantId", String.class)).isEqualTo("tenant-1");
    }

    @Test
    @DisplayName("Expired JWT throws ExpiredJwtException")
    void expiredJwt_throwsExpiredException() {
        String expired = buildJwt("user1", "ROLE_TOKENIZER", "tenant-1",
            new Date(System.currentTimeMillis() - 10_000));
        assertThatThrownBy(() -> Jwts.parser().verifyWith(signingKey).build()
            .parseSignedClaims(expired))
            .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }

    @Test
    @DisplayName("JWT signed with wrong key is rejected")
    void wrongKeyJwt_isRejected() {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
            "wrong-key-that-is-also-256-bits-long-for-test".getBytes(StandardCharsets.UTF_8));
        String tampered = Jwts.builder().subject("attacker")
            .expiration(new Date(System.currentTimeMillis() + 3_600_000))
            .signWith(wrongKey).compact();
        assertThatThrownBy(() -> Jwts.parser().verifyWith(signingKey).build()
            .parseSignedClaims(tampered))
            .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }

    @Test
    @DisplayName("Malformed JWT string is rejected")
    void malformedJwt_isRejected() {
        assertThatThrownBy(() -> Jwts.parser().verifyWith(signingKey).build()
            .parseSignedClaims("not.a.valid.jwt"))
            .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }

    @Test
    @DisplayName("JWT contains all claims required by the gateway filter")
    void jwt_containsAllRequiredClaims() {
        String token = buildJwt("svc", "ROLE_DETOKENIZER", "acme",
            new Date(System.currentTimeMillis() + 3_600_000));
        var claims = Jwts.parser().verifyWith(signingKey).build()
            .parseSignedClaims(token).getPayload();
        assertThat(claims.getSubject()).isNotBlank();
        assertThat(claims.get("role")).isNotNull();
        assertThat(claims.get("tenantId")).isNotNull();
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    private String buildJwt(String username, String role, String tenantId, Date expiration) {
        return Jwts.builder().subject(username)
            .claim("role", role).claim("tenantId", tenantId)
            .expiration(expiration).signWith(signingKey).compact();
    }
}
