package com.tokenization.common.dto;

import com.tokenization.common.model.DataType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for the tokenization API endpoint (POST /api/v1/tokenize).
 *
 * <p>WHY: A dedicated request DTO decouples the API contract from internal domain objects,
 * allowing the API contract to evolve independently of the tokenization engine internals.</p>
 *
 * <p>SECURITY: The 'data' field contains sensitive plaintext. It is validated but NEVER
 * logged — the RequestLoggingFilter explicitly excludes request bodies from log output.</p>
 */
public record TokenizeRequest(

    /**
     * The sensitive plaintext value to tokenize.
     * SECURITY: Never log this field. Max 256 chars prevents oversized payload attacks.
     */
    @NotBlank(message = "Data to tokenize must not be blank")
    @Size(max = 256, message = "Data length must not exceed 256 characters")
    String data,

    /**
     * The data type determining format constraints and masking defaults.
     * WHY: DataType drives FF1 radix selection and domain size validation.
     */
    @NotNull(message = "Data type must be specified")
    DataType dataType,

    /**
     * Tenant identifier for multi-tenant isolation.
     * WHY: Tenant ID is used as part of the FF1 tweak, ensuring tokens from different
     * tenants for the same input are computationally distinct (domain separation).
     */
    @NotBlank(message = "Tenant ID must not be blank")
    @Pattern(regexp = "^[a-zA-Z0-9-_]{1,128}$", message = "Tenant ID contains invalid characters")
    String tenantId,

    /**
     * Whether to strictly enforce format preservation (length + character set).
     * Defaults to true. Set to false for CUSTOM data types with variable-length input.
     */
    Boolean preserveFormat,

    /**
     * Optional additional tweak context (hex-encoded).
     * WHY: The FF1 tweak is a domain separator. Providing additional context ensures
     * tokens for the same data with different business context are computationally distinct.
     * SECURITY: This is NOT secret — it is analogous to an IV/nonce in AES-CTR.
     */
    @Size(max = 64, message = "Tweak must not exceed 64 hex characters (32 bytes)")
    String tweak

) {}
