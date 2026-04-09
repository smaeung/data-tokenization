package com.tokenization.keymanagement;

import java.time.Instant;

/**
 * Metadata record describing a cryptographic key version.
 *
 * <p>WHY: Key metadata is safe to expose to administrators for audit and lifecycle
 * management purposes. It contains NO key material — only descriptive information.</p>
 *
 * <p>SECURITY: This record is intentionally free of key bytes. Key material
 * is NEVER serialized, logged, or included in API responses.</p>
 */
public record KeyMetadata(

    /** Unique identifier for this key (e.g., "tenant-001-key-v3"). */
    String keyId,

    /** Numeric version of this key (monotonically increasing). */
    int version,

    /** The algorithm this key is intended for (always "AES" in our implementation). */
    String algorithm,

    /** Key size in bits (always 256 in our implementation). */
    int keySizeBits,

    /** UTC timestamp when this key version was created. */
    Instant createdAt,

    /** Current status of this key version. */
    KeyStatus status,

    /** The tenant this key belongs to. */
    String tenantId

) {

    /**
     * Lifecycle status of a key version.
     *
     * <p>WHY: Tracking key status enables the admin portal to show which keys are
     * active, which are archived (old but still needed for detokenization), and
     * which have been deliberately revoked (emergency response to compromise).</p>
     */
    public enum KeyStatus {
        /** The current active key version used for new tokenization operations. */
        ACTIVE,
        /** An older key version retained for detokenizing pre-rotation tokens. */
        ARCHIVED,
        /** Permanently disabled — tokens using this version cannot be detokenized. */
        REVOKED
    }
}
