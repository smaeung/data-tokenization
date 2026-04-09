package com.tokenization.keymanagement;

import java.util.List;
import javax.crypto.SecretKey;

/**
 * Core abstraction for all cryptographic key management operations.
 *
 * <p>WHY: The KeyProvider interface is the critical architectural boundary between
 * the tokenization engine and the underlying key store. This abstraction enables:
 * <ul>
 *   <li>Production: HashiCorp Vault Transit Engine (FIPS 140-3 compatible)</li>
 *   <li>Development: Local AES key from environment variable</li>
 *   <li>Testing: In-memory mock key provider</li>
 * </ul>
 * The tokenization engine only depends on this interface, never on a concrete implementation.</p>
 *
 * <p>SECURITY: Implementations must ensure that:
 * <ul>
 *   <li>Key material is never written to disk unencrypted</li>
 *   <li>Key material is cleared from memory after use (zeroing byte arrays)</li>
 *   <li>All key access is audited</li>
 * </ul></p>
 *
 * <p>COMPLIANCE: FIPS 140-3 Level 3 requires that key material never leave the
 * HSM boundary in plaintext. The VaultKeyProvider implementation satisfies this
 * by using Vault's Transit engine (server-side crypto) where possible.</p>
 */
public interface KeyProvider {

    /**
     * Retrieves the active (current) cryptographic key for a tenant.
     *
     * <p>WHY: Keys are tenant-scoped to enforce cryptographic domain separation.
     * A key compromise in one tenant cannot affect others.</p>
     *
     * @param tenantId the tenant identifier
     * @return the active AES-256 key for FF1 operations
     * @throws com.tokenization.common.exception.KeyNotFoundException if no active key exists
     */
    SecretKey getActiveKey(String tenantId);

    /**
     * Retrieves a specific key version for a tenant (used during key rotation).
     *
     * <p>WHY: After key rotation, tokens tokenized with older key versions must still
     * be detokenizable. This method retrieves the key version stored in token_metadata.</p>
     *
     * @param tenantId the tenant identifier
     * @param keyVersion the specific key version to retrieve
     * @return the AES-256 key for the specified version
     */
    SecretKey getKey(String tenantId, int keyVersion);

    /**
     * Returns the current active key version for a tenant.
     *
     * <p>WHY: The current version number is stored in token_metadata at tokenization time
     * to allow the correct key to be retrieved during detokenization.</p>
     */
    int getCurrentKeyVersion(String tenantId);

    /**
     * Rotates the cryptographic key for a tenant, creating a new key version.
     *
     * <p>WHY: Regular key rotation is required by PCI DSS (at least annually) and
     * limits the blast radius of a key compromise. Old versions remain available
     * for detokenizing tokens created before rotation.</p>
     *
     * @param tenantId the tenant identifier
     * @return metadata about the newly created key version
     */
    KeyMetadata rotateKey(String tenantId);

    /**
     * Lists all key versions (active and archived) for a tenant.
     *
     * <p>WHY: Administrators need to audit key lifecycle and verify rotation history
     * for compliance purposes.</p>
     */
    List<KeyMetadata> listKeys(String tenantId);
}
