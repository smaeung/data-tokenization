package com.tokenization.keymanagement;

import com.tokenization.common.exception.KeyNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for LocalKeyProvider.
 *
 * <p>WHY: We test the LocalKeyProvider exhaustively because it is the implementation
 * used in all integration tests. Even though it is dev-only, it must behave correctly
 * to ensure integration tests provide meaningful coverage of key management scenarios.</p>
 */
class LocalKeyProviderTest {

    private LocalKeyProvider provider;

    @BeforeEach
    void setUp() {
        provider = new LocalKeyProvider();
    }

    @Test
    @DisplayName("getActiveKey returns a valid 256-bit AES key for a new tenant")
    void getActiveKey_newTenant_returnsAesKey() {
        SecretKey key = provider.getActiveKey("tenant-001");
        assertThat(key).isNotNull();
        assertThat(key.getAlgorithm()).isEqualTo("AES");
        // WHY: AES-256 key must be exactly 32 bytes (256 bits)
        assertThat(key.getEncoded()).hasSize(32);
    }

    @Test
    @DisplayName("getActiveKey returns the same key on repeated calls for the same tenant")
    void getActiveKey_sameTenant_returnsSameKey() {
        SecretKey key1 = provider.getActiveKey("tenant-001");
        SecretKey key2 = provider.getActiveKey("tenant-001");
        assertThat(key1.getEncoded()).isEqualTo(key2.getEncoded());
    }

    @Test
    @DisplayName("getActiveKey returns different keys for different tenants")
    void getActiveKey_differentTenants_returnsDifferentKeys() {
        SecretKey key1 = provider.getActiveKey("tenant-001");
        SecretKey key2 = provider.getActiveKey("tenant-002");
        // WHY: Cryptographic domain separation is critical — different tenants MUST have different keys
        assertThat(key1.getEncoded()).isNotEqualTo(key2.getEncoded());
    }

    @Test
    @DisplayName("rotateKey increments version and generates a new key")
    void rotateKey_incrementsVersion() {
        provider.getActiveKey("tenant-001"); // initialize
        int versionBefore = provider.getCurrentKeyVersion("tenant-001");
        SecretKey keyBefore = provider.getActiveKey("tenant-001");

        KeyMetadata metadata = provider.rotateKey("tenant-001");

        assertThat(metadata.version()).isEqualTo(versionBefore + 1);
        assertThat(provider.getCurrentKeyVersion("tenant-001")).isEqualTo(versionBefore + 1);

        // WHY: The new active key must differ from the old key
        SecretKey keyAfter = provider.getActiveKey("tenant-001");
        assertThat(keyBefore.getEncoded()).isNotEqualTo(keyAfter.getEncoded());
    }

    @Test
    @DisplayName("getKey retrieves old key version after rotation")
    void getKey_oldVersion_returnsArchivedKey() {
        provider.getActiveKey("tenant-001"); // initialize v1
        SecretKey v1Key = provider.getActiveKey("tenant-001");

        provider.rotateKey("tenant-001"); // creates v2

        // WHY: Old key versions must remain accessible for detokenization of pre-rotation tokens
        SecretKey retrievedV1 = provider.getKey("tenant-001", 1);
        assertThat(retrievedV1.getEncoded()).isEqualTo(v1Key.getEncoded());
    }

    @Test
    @DisplayName("getKey throws KeyNotFoundException for unknown tenant")
    void getKey_unknownTenant_throwsKeyNotFoundException() {
        assertThatThrownBy(() -> provider.getKey("unknown-tenant", 1))
            .isInstanceOf(KeyNotFoundException.class);
    }

    @Test
    @DisplayName("listKeys returns all versions including archived")
    void listKeys_returnsAllVersions() {
        provider.getActiveKey("tenant-001"); // v1
        provider.rotateKey("tenant-001"); // v2
        provider.rotateKey("tenant-001"); // v3

        var keys = provider.listKeys("tenant-001");
        assertThat(keys).hasSize(3);
        assertThat(keys).anyMatch(k -> k.status() == KeyMetadata.KeyStatus.ACTIVE && k.version() == 3);
        assertThat(keys).anyMatch(k -> k.status() == KeyMetadata.KeyStatus.ARCHIVED && k.version() == 1);
    }
}
