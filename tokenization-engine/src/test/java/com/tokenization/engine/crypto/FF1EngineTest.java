package com.tokenization.engine.crypto;

import com.tokenization.common.exception.TokenizationException;
import com.tokenization.common.model.DataType;
import com.tokenization.keymanagement.LocalKeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Comprehensive unit tests for the FF1 FPE engine.
 *
 * <p>WHY: The FF1 engine is the cryptographic core. Any bug here is a security vulnerability.
 * We test exhaustively: correctness, reversibility, format preservation, domain size enforcement,
 * and alphabet validation.</p>
 */
class FF1EngineTest {

    private FF1Engine ff1Engine;
    private SecretKey testKey;
    private static final byte[] TEST_TWEAK = "tenant-001|CREDIT_CARD".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        ff1Engine = new FF1Engine();
        LocalKeyProvider keyProvider = new LocalKeyProvider();
        testKey = keyProvider.getActiveKey("test-tenant");
    }

    // ─── Format Preservation Tests ───────────────────────────────────────────

    @Test
    @DisplayName("Tokenized credit card preserves 16-digit numeric format")
    void tokenize_creditCard_preservesFormat() {
        String pan = "4532015112830366";
        String token = ff1Engine.tokenize(pan, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        assertThat(token).hasSize(16);
        assertThat(token).matches("[0-9]{16}");
        assertThat(token).isNotEqualTo(pan); // Token must differ from plaintext
    }

    @Test
    @DisplayName("Tokenized SSN preserves 9-digit numeric format")
    void tokenize_ssn_preservesFormat() {
        String ssn = "123456789";
        String token = ff1Engine.tokenize(ssn, testKey, "tenant-001|SSN".getBytes(), DataType.SSN);
        assertThat(token).hasSize(9);
        assertThat(token).matches("[0-9]{9}");
    }

    @Test
    @DisplayName("Tokenized alphanumeric ID preserves length and charset")
    void tokenize_alphanumeric_preservesFormatAndCharset() {
        String healthId = "abc1234567";
        String token = ff1Engine.tokenize(healthId, testKey, TEST_TWEAK, DataType.HEALTH_ID);
        assertThat(token).hasSize(10);
        assertThat(token).matches("[a-z0-9]{10}");
    }

    // ─── Reversibility Tests ──────────────────────────────────────────────────

    @Test
    @DisplayName("Detokenize reverses tokenize to recover original plaintext")
    void detokenize_reverseOfTokenize_recoversOriginal() {
        String original = "4532015112830366";
        String token = ff1Engine.tokenize(original, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        String recovered = ff1Engine.detokenize(token, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        assertThat(recovered).isEqualTo(original);
    }

    @ParameterizedTest
    @ValueSource(strings = {"4532015112830366", "5425233430109903", "4000000000000002", "0000000000000000"})
    @DisplayName("Round-trip tokenize→detokenize works for multiple credit card values")
    void roundTrip_multiplePans(String pan) {
        String token = ff1Engine.tokenize(pan, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        String recovered = ff1Engine.detokenize(token, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        assertThat(recovered).isEqualTo(pan);
    }

    // ─── Determinism Tests ────────────────────────────────────────────────────

    @Test
    @DisplayName("Same input + same key + same tweak always produces the same token (deterministic)")
    void tokenize_deterministic_sameInputSameToken() {
        String pan = "4532015112830366";
        String token1 = ff1Engine.tokenize(pan, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        String token2 = ff1Engine.tokenize(pan, testKey, TEST_TWEAK, DataType.CREDIT_CARD);
        // WHY: Determinism is required for analytics use cases (FR-005)
        assertThat(token1).isEqualTo(token2);
    }

    // ─── Domain Separation Tests ──────────────────────────────────────────────

    @Test
    @DisplayName("Different tweaks produce different tokens for the same input")
    void tokenize_differentTweaks_differentTokens() {
        String pan = "4532015112830366";
        byte[] tweak1 = "tenant-001|CREDIT_CARD".getBytes(StandardCharsets.UTF_8);
        byte[] tweak2 = "tenant-002|CREDIT_CARD".getBytes(StandardCharsets.UTF_8);
        String token1 = ff1Engine.tokenize(pan, testKey, tweak1, DataType.CREDIT_CARD);
        String token2 = ff1Engine.tokenize(pan, testKey, tweak2, DataType.CREDIT_CARD);
        // WHY: Cross-tenant tokens must be distinct to prevent correlation attacks
        assertThat(token1).isNotEqualTo(token2);
    }

    // ─── Domain Size Enforcement Tests ───────────────────────────────────────

    @Test
    @DisplayName("Throws DOMAIN_TOO_SMALL for input shorter than 6 digits (domain < 1,000,000)")
    void tokenize_shortInput_throwsDomainTooSmall() {
        // 5 digits: 10^5 = 100,000 < 1,000,000 (violates NIST SP 800-38G)
        assertThatThrownBy(() ->
            ff1Engine.tokenize("12345", testKey, TEST_TWEAK, DataType.CREDIT_CARD))
            .isInstanceOf(TokenizationException.class)
            .extracting(e -> ((TokenizationException) e).getErrorCode())
            .isEqualTo(TokenizationException.ErrorCode.DOMAIN_TOO_SMALL);
    }

    @Test
    @DisplayName("Does not throw for 6+ digit numeric input (domain = 10^6 = 1,000,000)")
    void tokenize_sixDigitInput_succeeds() {
        // 6 digits: 10^6 = 1,000,000 (meets minimum domain requirement)
        assertThatCode(() ->
            ff1Engine.tokenize("123456", testKey, TEST_TWEAK, DataType.CREDIT_CARD))
            .doesNotThrowAnyException();
    }

    // ─── Invalid Input Tests ──────────────────────────────────────────────────

    @Test
    @DisplayName("Throws INVALID_FORMAT for non-numeric characters in numeric data type")
    void tokenize_nonNumericInNumericType_throwsInvalidFormat() {
        assertThatThrownBy(() ->
            ff1Engine.tokenize("453201ABCD123456", testKey, TEST_TWEAK, DataType.CREDIT_CARD))
            .isInstanceOf(TokenizationException.class)
            .extracting(e -> ((TokenizationException) e).getErrorCode())
            .isEqualTo(TokenizationException.ErrorCode.INVALID_FORMAT);
    }

    // ─── buildTweak Helper Tests ──────────────────────────────────────────────

    @Test
    @DisplayName("buildTweak 2-arg produces tenantId|dataType bytes")
    void buildTweak_twoArg_producesExpectedBytes() {
        byte[] tweak = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD);
        assertThat(new String(tweak, StandardCharsets.UTF_8)).isEqualTo("tenant-1|CREDIT_CARD");
    }

    @Test
    @DisplayName("buildTweak 3-arg with null additionalContext delegates to 2-arg")
    void buildTweak_threeArg_nullContext_delegatesToTwoArg() {
        byte[] tweak2 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD);
        byte[] tweak3 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD, null);
        assertThat(tweak3).isEqualTo(tweak2);
    }

    @Test
    @DisplayName("buildTweak 3-arg with blank additionalContext delegates to 2-arg")
    void buildTweak_threeArg_blankContext_delegatesToTwoArg() {
        byte[] tweak2 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD);
        byte[] tweak3 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD, "   ");
        assertThat(tweak3).isEqualTo(tweak2);
    }

    @Test
    @DisplayName("buildTweak 3-arg with non-blank additionalContext appends context to tweak")
    void buildTweak_threeArg_withContext_appendsContext() {
        byte[] tweak = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD, "order-456");
        assertThat(new String(tweak, StandardCharsets.UTF_8))
            .isEqualTo("tenant-1|CREDIT_CARD|order-456");
    }

    @Test
    @DisplayName("Different additionalContext produces different tokens (tweak domain separation)")
    void tokenize_withDifferentAdditionalContext_differentTokens() {
        String pan = "4532015112830366";
        byte[] tweak1 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD, "ctx-A");
        byte[] tweak2 = FF1Engine.buildTweak("tenant-1", DataType.CREDIT_CARD, "ctx-B");
        String token1 = ff1Engine.tokenize(pan, testKey, tweak1, DataType.CREDIT_CARD);
        String token2 = ff1Engine.tokenize(pan, testKey, tweak2, DataType.CREDIT_CARD);
        assertThat(token1).isNotEqualTo(token2);
    }
}
