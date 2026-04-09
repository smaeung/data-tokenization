package com.tokenization.keymanagement;

import com.tokenization.common.exception.KeyNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Development-only, in-memory key provider using randomly generated AES-256 keys.
 *
 * <p>WHY: The LocalKeyProvider exists ONLY to allow developers to run the service
 * without a HashiCorp Vault instance. It is activated via the "local-keys" Spring profile.
 * It MUST NEVER be used in production environments.</p>
 *
 * <p>SECURITY: Keys generated here are ephemeral (lost on restart) and stored in JVM heap.
 * This violates FIPS 140-3 requirements and PCI DSS key storage requirements.
 * The @ConditionalOnProperty annotation ensures this bean is ONLY created when
 * tokenization.key-provider=local is explicitly configured.</p>
 */
@Component
@ConditionalOnProperty(name = "tokenization.key-provider", havingValue = "local")
public class LocalKeyProvider implements KeyProvider {

    private static final Logger log = LoggerFactory.getLogger(LocalKeyProvider.class);

    // WHY: ConcurrentHashMap ensures thread-safe access to keys in high-concurrency scenarios
    private final Map<String, Map<Integer, byte[]>> keyStore = new ConcurrentHashMap<>();
    private final Map<String, Integer> currentVersions = new ConcurrentHashMap<>();

    // WHY: SecureRandom with DRBG provides cryptographically secure random bytes.
    // Never use java.util.Random for cryptographic key generation.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public LocalKeyProvider() {
        // SECURITY: Log a prominent warning so developers know they are NOT in secure mode
        log.warn("==========================================================");
        log.warn("!!! LOCAL KEY PROVIDER ACTIVE — NOT FOR PRODUCTION USE !!!");
        log.warn("Keys are ephemeral, stored in JVM heap, NOT FIPS 140-3 compliant.");
        log.warn("Set tokenization.key-provider=vault for production environments.");
        log.warn("==========================================================");
    }

    @Override
    public SecretKey getActiveKey(String tenantId) {
        // Initialize a key for this tenant if none exists
        keyStore.computeIfAbsent(tenantId, t -> new ConcurrentHashMap<>());
        currentVersions.computeIfAbsent(tenantId, t -> {
            generateNewKeyVersion(t, 1);
            return 1;
        });
        int version = currentVersions.get(tenantId);
        return buildSecretKey(keyStore.get(tenantId).get(version));
    }

    @Override
    public SecretKey getKey(String tenantId, int keyVersion) {
        Map<Integer, byte[]> tenantKeys = keyStore.get(tenantId);
        if (tenantKeys == null || !tenantKeys.containsKey(keyVersion)) {
            throw new KeyNotFoundException("version-" + keyVersion, tenantId);
        }
        return buildSecretKey(tenantKeys.get(keyVersion));
    }

    @Override
    public int getCurrentKeyVersion(String tenantId) {
        return currentVersions.getOrDefault(tenantId, 0);
    }

    @Override
    public KeyMetadata rotateKey(String tenantId) {
        int newVersion = currentVersions.getOrDefault(tenantId, 0) + 1;
        generateNewKeyVersion(tenantId, newVersion);
        currentVersions.put(tenantId, newVersion);
        log.info("Key rotated for tenant '{}'. New version: {}", tenantId, newVersion);
        return new KeyMetadata(
            tenantId + "-key-v" + newVersion,
            newVersion,
            "AES",
            256,
            Instant.now(),
            KeyMetadata.KeyStatus.ACTIVE,
            tenantId
        );
    }

    @Override
    public List<KeyMetadata> listKeys(String tenantId) {
        Map<Integer, byte[]> tenantKeys = keyStore.getOrDefault(tenantId, Map.of());
        int currentVersion = currentVersions.getOrDefault(tenantId, 0);
        return tenantKeys.keySet().stream()
            .map(version -> new KeyMetadata(
                tenantId + "-key-v" + version,
                version,
                "AES",
                256,
                Instant.now(),
                version == currentVersion ? KeyMetadata.KeyStatus.ACTIVE : KeyMetadata.KeyStatus.ARCHIVED,
                tenantId
            ))
            .toList();
    }

    private void generateNewKeyVersion(String tenantId, int version) {
        // WHY: AES-256 requires exactly 32 bytes (256 bits) of key material
        byte[] keyBytes = new byte[32];
        SECURE_RANDOM.nextBytes(keyBytes);
        keyStore.computeIfAbsent(tenantId, t -> new ConcurrentHashMap<>()).put(version, keyBytes);
    }

    private SecretKey buildSecretKey(byte[] keyBytes) {
        // WHY: SecretKeySpec wraps raw key bytes into a JCE-compatible SecretKey object
        // The algorithm must be "AES" to be accepted by Bouncy Castle FF1 engine
        return new SecretKeySpec(keyBytes, "AES");
    }
}
