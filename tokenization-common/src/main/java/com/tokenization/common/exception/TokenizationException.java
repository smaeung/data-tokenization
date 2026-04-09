package com.tokenization.common.exception;

/**
 * Base exception for all tokenization service errors.
 *
 * <p>WHY: A domain-specific exception hierarchy allows the global exception handler
 * (ControllerAdvice) to produce consistent, structured error responses without
 * leaking implementation details (stack traces, SQL errors) to API callers.</p>
 *
 * <p>SECURITY: Error messages MUST NOT contain plaintext sensitive data.
 * Token IDs may appear in error messages (they are not sensitive), but
 * plaintext PANs, SSNs, or other PII must never appear in exceptions.</p>
 */
public class TokenizationException extends RuntimeException {

    private final ErrorCode errorCode;

    public TokenizationException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public TokenizationException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * Standardized error codes for the tokenization service.
     *
     * <p>WHY: Numeric/string error codes allow clients to handle errors programmatically
     * without parsing error message strings, which improves API stability across versions.</p>
     */
    public enum ErrorCode {
        /** Input data does not match the expected format for the specified DataType. */
        INVALID_FORMAT("TOK-001"),
        /** Domain size (radix^length) is below the minimum of 1,000,000. */
        DOMAIN_TOO_SMALL("TOK-002"),
        /** The cryptographic key was not found or is not accessible. */
        KEY_NOT_FOUND("TOK-003"),
        /** FF1 encryption/decryption operation failed. */
        CRYPTO_FAILURE("TOK-004"),
        /** The requested operation is not permitted for the caller's role. */
        ACCESS_DENIED("TOK-005"),
        /** Token metadata was not found in the token_metadata table. */
        TOKEN_NOT_FOUND("TOK-006"),
        /** Multi-tenant isolation violation — tenant mismatch detected. */
        TENANT_MISMATCH("TOK-007"),
        /** Batch size exceeds the maximum allowed (1,000). */
        BATCH_TOO_LARGE("TOK-008");

        private final String code;

        ErrorCode(String code) { this.code = code; }

        public String getCode() { return code; }
    }
}
