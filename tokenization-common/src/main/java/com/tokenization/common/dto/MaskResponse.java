package com.tokenization.common.dto;

/**
 * Response DTO for dynamic data masking (POST /api/v1/mask).
 */
public record MaskResponse(

    /** The masked representation of the token value (e.g., "****-****-****-1234"). */
    String masked,

    /** The mask pattern that was applied. */
    String maskPatternApplied

) {}
