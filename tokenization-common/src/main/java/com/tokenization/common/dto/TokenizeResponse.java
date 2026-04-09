package com.tokenization.common.dto;

import com.tokenization.common.model.DataType;
import java.time.Instant;

/**
 * Response DTO for the tokenization API (POST /api/v1/tokenize).
 *
 * <p>SECURITY: This response NEVER contains the original plaintext.
 * It contains only the surrogate token and its metadata.</p>
 *
 * <p>WHY: Returning tokenId (a stable reference handle) alongside the token itself
 * allows downstream systems to reference this tokenization event in audit logs
 * and detokenization requests without storing the plaintext.</p>
 */
public record TokenizeResponse(

    /** The format-preserving surrogate token. Same length and charset as the original data. */
    String token,

    /**
     * Stable unique identifier for this token, used in detokenization and audit references.
     * WHY: tokenId allows correlation across audit logs without exposing the token or plaintext.
     */
    String tokenId,

    /** The data type of the tokenized value. */
    DataType dataType,

    /**
     * Format descriptor of the token (e.g., "NUMERIC_16", "ALPHANUMERIC_10").
     * WHY: Allows consumers to validate token format before storing.
     */
    String format,

    /**
     * The cryptographic key version used for this tokenization.
     * WHY: Stored in token_metadata table to enable key rotation — the correct key
     * version must be used for detokenization even after rotation.
     */
    Integer keyVersion,

    /** UTC timestamp of tokenization. */
    Instant createdAt

) {}
