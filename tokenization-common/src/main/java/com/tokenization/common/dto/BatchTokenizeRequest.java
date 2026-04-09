package com.tokenization.common.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Request DTO for batch tokenization (POST /api/v1/tokenize/batch).
 *
 * <p>WHY: Batch processing reduces HTTP overhead for high-volume use cases.
 * Each record is processed independently — partial failures are reported without
 * failing the entire batch (FR-003).</p>
 *
 * <p>COMPLIANCE: Maximum batch size of 1,000 prevents resource exhaustion attacks
 * and aligns with rate limiting configuration.</p>
 */
public record BatchTokenizeRequest(

    /**
     * List of tokenization records. Max 1,000 per batch (FR-003).
     * WHY: Cap prevents memory exhaustion on large payloads; encourages streaming patterns for larger volumes.
     */
    @NotEmpty(message = "Batch must contain at least one record")
    @Size(max = 1000, message = "Batch size must not exceed 1,000 records")
    @Valid
    List<TokenizeRequest> records,

    /** Tenant identifier applied to all records in the batch. */
    @NotBlank(message = "Tenant ID must not be blank")
    @Pattern(regexp = "^[a-zA-Z0-9-_]{1,128}$", message = "Tenant ID contains invalid characters")
    String tenantId

) {}
