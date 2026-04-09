package com.tokenization.common.exception;

/**
 * Thrown when a principal attempts an operation they are not authorized to perform.
 *
 * <p>SECURITY: This exception results in an HTTP 403 Forbidden response.
 * It is intentionally vague in the error message to avoid leaking authorization policy details
 * to potential attackers (they should not know WHY they are denied, only THAT they are denied).</p>
 */
public class AccessDeniedException extends TokenizationException {

    public AccessDeniedException(String operation) {
        super(
            ErrorCode.ACCESS_DENIED,
            // WHY: Generic message prevents attackers from inferring permission structure
            "Access denied for operation: " + operation
        );
    }
}
