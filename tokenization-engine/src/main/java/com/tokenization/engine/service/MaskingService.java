package com.tokenization.engine.service;

import com.tokenization.common.dto.MaskRequest;
import com.tokenization.common.dto.MaskResponse;
import com.tokenization.common.model.DataType;
import org.springframework.stereotype.Service;

/**
 * Service for dynamic data masking of tokenized values.
 *
 * <p>WHY: Masking operates on tokens (surrogate values), NOT on the original plaintext.
 * This means masking does NOT require DETOKENIZE permission — any authenticated user
 * can mask a token they hold to display a redacted view.</p>
 *
 * <p>COMPLIANCE: Dynamic masking satisfies PCI DSS data minimization requirements
 * by allowing systems to display partial values (e.g., last 4 digits of a PAN)
 * without exposing the full account number.</p>
 *
 * <p>WHY separate service: Masking has no cryptographic component. Isolating it
 * makes the code easier to test and prevents it from accidentally depending on
 * key management infrastructure.</p>
 */
@Service
public class MaskingService {

    /**
     * Applies a masking pattern to a token value.
     *
     * @param request The mask request containing token, pattern, and data type
     * @return The masked string representation
     */
    public MaskResponse mask(MaskRequest request) {
        String masked = applyMask(request.token(), request.maskPattern(), request.dataType());
        return new MaskResponse(masked, request.maskPattern().name());
    }

    /**
     * Applies the specified mask pattern to a token string.
     *
     * <p>WHY: Each data type has different display conventions:
     * - Credit cards: groups of 4 separated by dashes (4716-****-****-1234)
     * - SSN: groups of 3-2-4 separated by dashes (***-**-6789)
     * - Phone: just asterisks + last 4 (******1234)
     * - Generic: all asterisks of the same length</p>
     */
    private String applyMask(String token, DataType.MaskPattern pattern, DataType dataType) {
        return switch (pattern) {
            case LAST_4 -> maskLast4(token, dataType);
            case FIRST_4 -> maskFirst4(token, dataType);
            case FIRST_6_LAST_4 -> maskFirst6Last4(token, dataType);
            case FULL_MASK -> "*".repeat(token.length());
        };
    }

    private String maskLast4(String token, DataType dataType) {
        if (token.length() <= 4) {
            return token; // Too short to mask meaningfully
        }
        String masked = "*".repeat(token.length() - 4) + token.substring(token.length() - 4);
        return formatForDisplay(masked, dataType);
    }

    private String maskFirst4(String token, DataType dataType) {
        if (token.length() <= 4) {
            return token;
        }
        String masked = token.substring(0, 4) + "*".repeat(token.length() - 4);
        return formatForDisplay(masked, dataType);
    }

    private String maskFirst6Last4(String token, DataType dataType) {
        // WHY: First 6 + Last 4 is the industry-standard PAN display format (BIN + last 4)
        if (token.length() < 10) {
            return maskLast4(token, dataType);
        }
        String masked = token.substring(0, 6)
            + "*".repeat(token.length() - 10)
            + token.substring(token.length() - 4);
        return formatForDisplay(masked, dataType);
    }

    /**
     * Formats a masked string with data-type-specific separators for display.
     *
     * <p>WHY: Raw masked strings (e.g., "****1234") are harder to read than formatted
     * ones (e.g., "****-****-****-1234"). Display formatting is purely cosmetic and
     * does not affect the underlying token value.</p>
     */
    private String formatForDisplay(String masked, DataType dataType) {
        return switch (dataType) {
            // Credit card: groups of 4 separated by dashes
            case CREDIT_CARD -> groupBy(masked, 4, "-");
            // SSN: groups of 3-2-4
            case SSN -> groupSsn(masked);
            // Phone: groups of 3-3-4 for US format
            case PHONE -> groupPhone(masked);
            // All other types: no formatting
            default -> masked;
        };
    }

    private String groupBy(String s, int groupSize, String separator) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            if (i > 0 && i % groupSize == 0) sb.append(separator);
            sb.append(s.charAt(i));
        }
        return sb.toString();
    }

    private String groupSsn(String s) {
        // WHY: SSN format is NNN-NN-NNNN (3-2-4)
        if (s.length() != 9) return s;
        return s.substring(0, 3) + "-" + s.substring(3, 5) + "-" + s.substring(5);
    }

    private String groupPhone(String s) {
        if (s.length() != 10) return s;
        return s.substring(0, 3) + "-" + s.substring(3, 6) + "-" + s.substring(6);
    }
}
