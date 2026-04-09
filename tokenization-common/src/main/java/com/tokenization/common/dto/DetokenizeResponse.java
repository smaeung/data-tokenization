package com.tokenization.common.dto;

import com.tokenization.common.model.DataType;

/**
 * Response DTO for detokenization (POST /api/v1/detokenize).
 *
 * <p>SECURITY: The 'data' field contains recovered plaintext — this MUST be treated
 * as sensitive data by the caller. The response is only returned to principals
 * with DETOKENIZE permission verified by the access control layer.</p>
 *
 * <p>WHY: maskedView is always returned alongside the plaintext so callers can display
 * the masked version to lower-privileged users (e.g., in a UI) without re-calling the mask API.</p>
 */
public record DetokenizeResponse(

    /**
     * The recovered original plaintext.
     * SECURITY: NEVER log this field. Treat as PII/PAN at rest and in transit.
     */
    String data,

    /** The data type of the recovered value. */
    DataType dataType,

    /**
     * A pre-computed masked view of the data (e.g., "****-****-****-1234").
     * WHY: Reduces additional API calls when the masked view is also needed.
     */
    String maskedView

) {}
