package com.tokenization.common.dto;

import com.tokenization.common.model.DataType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request DTO for dynamic data masking (POST /api/v1/mask).
 *
 * <p>WHY: Masking operates on tokens (not plaintext), so it does not require
 * DETOKENIZE permission. Any authenticated user can mask a token they possess.
 * The mask operation is purely a formatting concern — it does not touch the
 * cryptographic engine or key management system.</p>
 *
 * <p>COMPLIANCE: Dynamic masking (FR-004) allows partial data exposure to support
 * legitimate business functions (e.g., customer service confirming last 4 digits)
 * while maintaining compliance with PCI DSS data minimization requirements.</p>
 */
public record MaskRequest(

    /** The surrogate token to mask. NOT the plaintext original. */
    @NotBlank(message = "Token must not be blank")
    String token,

    /** The masking pattern to apply. */
    @NotNull(message = "Mask pattern must be specified")
    DataType.MaskPattern maskPattern,

    /** The data type determines how the mask is formatted (e.g., dashes for credit cards). */
    @NotNull(message = "Data type must be specified")
    DataType dataType

) {}
