package com.tokenization.common.exception;

/**
 * Thrown when a requested cryptographic key cannot be found in the key management system.
 *
 * <p>WHY: Separating key-not-found from general crypto failure allows the monitoring system
 * to alert on missing keys specifically, which may indicate a key rotation issue or
 * unauthorized key deletion.</p>
 *
 * <p>SECURITY: The error message includes keyId (a non-sensitive identifier) but
 * never the key material itself.</p>
 */
public class KeyNotFoundException extends TokenizationException {

    public KeyNotFoundException(String keyId, String tenantId) {
        super(
            ErrorCode.KEY_NOT_FOUND,
            String.format("Key '%s' not found for tenant '%s'", keyId, tenantId)
        );
    }
}
