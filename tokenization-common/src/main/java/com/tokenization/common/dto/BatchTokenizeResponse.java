package com.tokenization.common.dto;

import java.util.List;

/**
 * Response DTO for batch tokenization (POST /api/v1/tokenize/batch).
 *
 * <p>WHY: Individual results allow callers to handle partial failures without
 * re-submitting the entire batch. The failureCount enables quick health assessment.</p>
 */
public record BatchTokenizeResponse(

    /** Individual results in the same order as the request records. */
    List<BatchResult> results,

    /** Count of successfully tokenized records. */
    int successCount,

    /** Count of records that failed tokenization. */
    int failureCount

) {

    /**
     * Result for a single record within a batch operation.
     *
     * <p>WHY: Using a sealed class hierarchy allows the caller to pattern-match on
     * success/failure without null-checking, improving type safety.</p>
     */
    public record BatchResult(
        /** Index of the record in the original request list (0-based). */
        int index,
        /** The tokenization result if successful; null if failed. */
        TokenizeResponse result,
        /** Whether this individual record was successfully tokenized. */
        boolean success,
        /** Error message if failed; null if successful. NEVER contains plaintext data. */
        String errorMessage
    ) {}
}
