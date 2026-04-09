package com.tokenization.engine.crypto;

import com.tokenization.common.exception.TokenizationException;
import com.tokenization.common.model.DataType;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Core FF1 Format-Preserving Encryption engine using Bouncy Castle.
 *
 * <p>WHY FF1 (NIST SP 800-38G): FF1 is the only NIST-standardized Format-Preserving
 * Encryption algorithm, ensuring regulatory acceptance for PCI DSS and HIPAA tokenization.
 * It operates on arbitrary alphabets (radix-10 for numeric, radix-36 for alphanumeric)
 * and produces ciphertext of the same length and character set as the plaintext.</p>
 *
 * <p>WHY Bouncy Castle: The bcprov-jdk18on library provides a production-quality,
 * actively maintained FF1 implementation. It is used by major financial institutions
 * and has been reviewed for FIPS compliance.</p>
 *
 * <p>SECURITY: The key parameter is a 256-bit AES key retrieved from the KeyProvider.
 * The tweak parameter provides domain separation between tenants and data types —
 * the same plaintext tokenized with the same key but different tweaks produces
 * different tokens (analogous to IV/salt in symmetric encryption).</p>
 *
 * <p>COMPLIANCE: NIST SP 800-38G requires domain size (radix^minLength) >= 1,000,000.
 * This is enforced in the FormatPreserver before reaching this engine.</p>
 */
@Component
public class FF1Engine {

    private static final Logger log = LoggerFactory.getLogger(FF1Engine.class);

    /**
     * Tokenizes plaintext data using FF1 FPE.
     *
     * @param plaintext  The sensitive data to tokenize (e.g., "4532015112830366")
     * @param key        The 256-bit AES key from KeyProvider
     * @param tweak      Domain separator bytes (tenantId + dataType encoded as UTF-8)
     * @param dataType   Determines radix and alphabet used for FF1
     * @return           A format-preserving token (same length and charset as plaintext)
     */
    public String tokenize(String plaintext, SecretKey key, byte[] tweak, DataType dataType) {
        return applyFF1(plaintext, key, tweak, dataType, false);
    }

    /**
     * Detokenizes a token back to original plaintext using FF1 FPE (decryption direction).
     *
     * <p>WHY: FF1 is a bijection — it has a mathematically defined inverse operation.
     * Decryption requires the SAME key and tweak used during encryption.
     * Without the correct key, reversal is computationally infeasible.</p>
     *
     * <p>SECURITY: This method must ONLY be called after RBAC/ABAC authorization
     * has been verified by the Access Control module.</p>
     *
     * @param token      The surrogate token to reverse
     * @param key        The SAME 256-bit AES key used during tokenization
     * @param tweak      The SAME domain separator bytes used during tokenization
     * @param dataType   The data type (must match what was used during tokenization)
     * @return           The original plaintext
     */
    public String detokenize(String token, SecretKey key, byte[] tweak, DataType dataType) {
        return applyFF1(token, key, tweak, dataType, true);
    }

    /**
     * Core FF1 encrypt/decrypt operation.
     *
     * <p>WHY: FF1 works on integer arrays, not strings. We convert the input string
     * to an integer array based on the alphabet (e.g., '4' → 4 in numeric alphabet,
     * 'a' → 10 in alphanumeric alphabet), apply FF1, then convert back to a string.</p>
     *
     * @param input    The string to process
     * @param key      AES-256 key
     * @param tweak    Domain separator
     * @param dataType Determines radix and alphabet
     * @param decrypt  false = encrypt (tokenize), true = decrypt (detokenize)
     */
    private String applyFF1(String input, SecretKey key, byte[] tweak, DataType dataType, boolean decrypt) {
        try {
            DataType.Radix radix = dataType.getRadix();
            String alphabet = radix.getAlphabet();
            int radixValue = radix.getValue();

            // Convert input string to byte array based on the alphabet.
            // WHY byte[]: Bouncy Castle's FPEFF1Engine.processBlock requires byte[] —
            // each element is a numeral in range [0, radix-1] (max 35 for alphanumeric, fits in a byte).
            byte[] inputNumerals = stringToNumerals(input, alphabet);

            // COMPLIANCE: Verify domain size >= 1,000,000 (NIST SP 800-38G requirement)
            // radix^length >= 1,000,000 prevents brute-force guessing attacks
            long domainSize = (long) Math.pow(radixValue, inputNumerals.length);
            if (domainSize < 1_000_000L) {
                throw new TokenizationException(
                    TokenizationException.ErrorCode.DOMAIN_TOO_SMALL,
                    String.format("Domain size %d is below minimum 1,000,000 for radix=%d, length=%d",
                        domainSize, radixValue, inputNumerals.length)
                );
            }

            // WHY: FPEParameters wraps the key and tweak into a format Bouncy Castle understands.
            // The tweak provides domain separation: same plaintext + same key + different tweak
            // = different token. We use (tenantId + "|" + dataType) as the tweak.
            FPEParameters params = new FPEParameters(
                new KeyParameter(key.getEncoded()),
                radixValue,
                tweak
            );

            FPEFF1Engine engine = new FPEFF1Engine();
            engine.init(decrypt, params);

            // WHY: processBlock writes the result into a separate output array
            byte[] outputNumerals = inputNumerals.clone();
            engine.processBlock(inputNumerals, 0, inputNumerals.length, outputNumerals, 0);

            // Convert the output byte array back to a string using the same alphabet
            return numeralsToString(outputNumerals, alphabet);

        } catch (TokenizationException e) {
            throw e;
        } catch (Exception e) {
            log.error("FF1 operation failed for dataType={}, decrypt={}: {}",
                dataType, decrypt, e.getMessage());
            throw new TokenizationException(
                TokenizationException.ErrorCode.CRYPTO_FAILURE,
                "FF1 cryptographic operation failed: " + e.getMessage(),
                e
            );
        }
    }

    /**
     * Converts a string to a byte array for FF1 processing.
     * Each character in the input is mapped to its index in the alphabet.
     *
     * <p>WHY byte[]: Bouncy Castle FPEFF1Engine.processBlock requires byte[].
     * Radix-36 (alphanumeric) has max value 35, which fits safely in a byte.
     * For numeric data: '4' → 4, '0' → 0.
     * For alphanumeric: '0' → 0, 'a' → 10, 'z' → 35.</p>
     */
    private byte[] stringToNumerals(String input, String alphabet) {
        byte[] numerals = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            int index = alphabet.indexOf(input.charAt(i));
            if (index == -1) {
                throw new TokenizationException(
                    TokenizationException.ErrorCode.INVALID_FORMAT,
                    "Character '" + input.charAt(i) + "' is not in the expected alphabet"
                );
            }
            numerals[i] = (byte) index;
        }
        return numerals;
    }

    /**
     * Converts a byte numeral array back to a string using the alphabet.
     * This is the inverse of stringToNumerals.
     */
    private String numeralsToString(byte[] numerals, String alphabet) {
        StringBuilder sb = new StringBuilder(numerals.length);
        for (byte numeral : numerals) {
            sb.append(alphabet.charAt(numeral & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Builds the FF1 tweak bytes from tenant ID and data type.
     *
     * <p>WHY: The tweak acts as domain separator in FF1. Using (tenantId|dataType)
     * ensures that:
     * - Tokens from different tenants for the same plaintext are computationally distinct
     * - Tokens of different data types for the same plaintext are distinct (no cross-type correlation)
     * This is analogous to using a unique IV per encryption operation.</p>
     */
    public static byte[] buildTweak(String tenantId, DataType dataType) {
        return (tenantId + "|" + dataType.name()).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds the tweak with additional context (e.g., caller-provided tweak string).
     */
    public static byte[] buildTweak(String tenantId, DataType dataType, String additionalContext) {
        if (additionalContext == null || additionalContext.isBlank()) {
            return buildTweak(tenantId, dataType);
        }
        return (tenantId + "|" + dataType.name() + "|" + additionalContext)
            .getBytes(StandardCharsets.UTF_8);
    }
}
