package com.tokenization.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for detokenization (POST /api/v1/detokenize).
 *
 * <p>SECURITY: Detokenization is a privileged operation requiring DETOKENIZE permission.
 * The access control layer evaluates RBAC/ABAC policies before this reaches the FF1 engine.</p>
 *
 * <p>WHY: Accepting tokenId in addition to the token itself allows the system to look up
 * the key version and data type from token_metadata, avoiding the need to encode this
 * information in the token itself (which would reduce security).</p>
 */
public record DetokenizeRequest(

    /** The surrogate token to reverse. */
    @NotBlank(message = "Token must not be blank")
    String token,

    /** The stable token reference ID returned at tokenization time. */
    @NotBlank(message = "Token ID must not be blank")
    String tokenId,

    /** Tenant identifier — must match the tenant used during tokenization. */
    @NotBlank(message = "Tenant ID must not be blank")
    @Pattern(regexp = "^[a-zA-Z0-9-_]{1,128}$", message = "Tenant ID contains invalid characters")
    String tenantId

) {}
