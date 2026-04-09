package com.tokenization.engine.service;

import com.tokenization.common.dto.*;
import com.tokenization.common.event.AuditEvent;
import com.tokenization.common.exception.TokenizationException;
import com.tokenization.common.model.DataType;
import com.tokenization.engine.crypto.FF1Engine;
import com.tokenization.engine.entity.TokenMetadata;
import com.tokenization.engine.repository.TokenMetadataRepository;
import com.tokenization.keymanagement.KeyProvider;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Orchestrates the full tokenization and detokenization lifecycle.
 *
 * <p>WHY: This service is the central coordinator — it calls KeyProvider (key retrieval),
 * FF1Engine (cryptographic operation), TokenMetadataRepository (metadata persistence),
 * and ApplicationEventPublisher (audit events). By centralizing orchestration here,
 * each dependency is kept focused on a single responsibility.</p>
 *
 * <p>SECURITY: This service assumes the caller has already been authenticated and
 * authorized by the Access Control module. It does NOT re-check authorization —
 * that would create inconsistent enforcement. The security boundary is at the API Gateway.</p>
 *
 * <p>COMPLIANCE: Every tokenization and detokenization operation publishes an AuditEvent
 * that is asynchronously persisted by the Audit module. This satisfies PCI DSS Req 10.2.</p>
 */
@Service
public class TokenizationService {

    private static final Logger log = LoggerFactory.getLogger(TokenizationService.class);

    private final FF1Engine ff1Engine;
    private final KeyProvider keyProvider;
    private final TokenMetadataRepository tokenMetadataRepository;
    private final MaskingService maskingService;
    private final ApplicationEventPublisher eventPublisher;

    // WHY: Micrometer metrics for Prometheus monitoring dashboards
    private final Counter tokenizeCounter;
    private final Counter detokenizeCounter;
    private final Timer tokenizeTimer;

    public TokenizationService(FF1Engine ff1Engine, KeyProvider keyProvider,
                                TokenMetadataRepository tokenMetadataRepository,
                                MaskingService maskingService,
                                ApplicationEventPublisher eventPublisher,
                                MeterRegistry meterRegistry) {
        this.ff1Engine = ff1Engine;
        this.keyProvider = keyProvider;
        this.tokenMetadataRepository = tokenMetadataRepository;
        this.maskingService = maskingService;
        this.eventPublisher = eventPublisher;
        this.tokenizeCounter = Counter.builder("tokenization.operations")
            .tag("operation", "tokenize").register(meterRegistry);
        this.detokenizeCounter = Counter.builder("tokenization.operations")
            .tag("operation", "detokenize").register(meterRegistry);
        this.tokenizeTimer = Timer.builder("tokenization.duration")
            .tag("operation", "tokenize").register(meterRegistry);
    }

    /**
     * Tokenizes a single sensitive value.
     *
     * <p>WHY @Transactional: Token metadata persistence and audit event publishing
     * must be atomic. If metadata fails to save, we should not return a token
     * that has no metadata record (it could never be detokenized).</p>
     */
    @Transactional
    public TokenizeResponse tokenize(TokenizeRequest request, String requesterId, String requesterRole, String sourceIp) {
        return tokenizeTimer.record(() -> {
            try {
                // Step 1: Retrieve the active cryptographic key for this tenant
                SecretKey key = keyProvider.getActiveKey(request.tenantId());
                int keyVersion = keyProvider.getCurrentKeyVersion(request.tenantId());

                // Step 2: Build the FF1 tweak (domain separator: tenantId|dataType)
                // WHY: The tweak ensures tokens from different tenants/data-types are distinct
                byte[] tweak = FF1Engine.buildTweak(request.tenantId(), request.dataType(), request.tweak());

                // Step 3: Apply FF1 encryption
                String token = ff1Engine.tokenize(request.data(), key, tweak, request.dataType());

                // Step 4: Generate a stable token reference ID
                // WHY: tokenId is a UUID that acts as a stable handle for this token event,
                // used in audit logs and detokenization requests without encoding any sensitive data
                String tokenId = "tok_" + UUID.randomUUID().toString().replace("-", "");

                // Step 5: Persist token metadata (NOT the plaintext — vaultless by design)
                String format = request.dataType().getRadix().name() + "_" + request.data().length();
                saveTokenMetadata(tokenId, request.dataType(), format, keyVersion, request.tenantId());

                // Step 6: Publish audit event asynchronously
                // WHY: Fire-and-forget — audit logging must not block the tokenization response
                publishAuditEvent(requesterId, requesterRole, AuditEvent.Operation.TOKENIZE,
                    request.dataType().name(), tokenId, sourceIp, request.tenantId(), true, null);

                tokenizeCounter.increment();
                return new TokenizeResponse(token, tokenId, request.dataType(), format, keyVersion, Instant.now());

            } catch (Exception e) {
                publishAuditEvent(requesterId, requesterRole, AuditEvent.Operation.TOKENIZE,
                    request.dataType().name(), null, sourceIp, request.tenantId(), false, e.getMessage());
                throw e;
            }
        });
    }

    /**
     * Reverses a token back to the original plaintext using FF1 decryption.
     *
     * <p>SECURITY: This is a privileged operation. The caller MUST have DETOKENIZE permission.
     * The access control verification happens in the controller layer (@PreAuthorize).</p>
     */
    @Transactional(readOnly = true)
    public DetokenizeResponse detokenize(DetokenizeRequest request, String requesterId, String requesterRole, String sourceIp) {
        try {
            // Step 1: Retrieve token metadata to get the key version and data type
            // WHY: We stored the key version at tokenization time so we can retrieve
            // the correct key version even after key rotation
            TokenMetadata metadata = tokenMetadataRepository.findById(request.tokenId())
                .orElseThrow(() -> new TokenizationException(
                    TokenizationException.ErrorCode.TOKEN_NOT_FOUND,
                    "Token metadata not found for tokenId: " + request.tokenId()));

            // SECURITY: Enforce tenant isolation — reject if token belongs to different tenant
            if (!metadata.getTenantId().equals(request.tenantId())) {
                throw new TokenizationException(
                    TokenizationException.ErrorCode.TENANT_MISMATCH,
                    "Tenant mismatch for tokenId: " + request.tokenId());
            }

            // Step 2: Retrieve the specific key version used at tokenization time
            SecretKey key = keyProvider.getKey(request.tenantId(), metadata.getKeyVersion());

            // Step 3: Rebuild the SAME tweak used during tokenization
            byte[] tweak = FF1Engine.buildTweak(request.tenantId(), metadata.getDataType());

            // Step 4: Apply FF1 decryption (inverse of tokenization)
            String plaintext = ff1Engine.detokenize(request.token(), key, tweak, metadata.getDataType());

            // Step 5: Generate masked view for the response
            DataType.MaskPattern maskPattern = metadata.getDataType().getDefaultMaskPattern();
            String maskedView = maskingService.mask(
                new MaskRequest(request.token(), maskPattern, metadata.getDataType())
            ).masked();

            publishAuditEvent(requesterId, requesterRole, AuditEvent.Operation.DETOKENIZE,
                metadata.getDataType().name(), request.tokenId(), sourceIp, request.tenantId(), true, null);

            detokenizeCounter.increment();
            return new DetokenizeResponse(plaintext, metadata.getDataType(), maskedView);

        } catch (TokenizationException e) {
            publishAuditEvent(requesterId, requesterRole, AuditEvent.Operation.DETOKENIZE,
                "UNKNOWN", request.tokenId(), sourceIp, request.tenantId(), false, e.getMessage());
            throw e;
        }
    }

    /**
     * Tokenizes a batch of sensitive values (up to 1,000 per request).
     *
     * <p>WHY: Processing each record independently (not in a single transaction)
     * ensures partial failures don't roll back successful records.</p>
     */
    public BatchTokenizeResponse tokenizeBatch(BatchTokenizeRequest request, String requesterId, String requesterRole, String sourceIp) {
        List<BatchTokenizeResponse.BatchResult> results = new ArrayList<>();
        int successCount = 0;
        int failureCount = 0;

        for (int i = 0; i < request.records().size(); i++) {
            TokenizeRequest record = request.records().get(i);
            // Ensure tenantId from batch request is used
            TokenizeRequest withTenant = new TokenizeRequest(
                record.data(), record.dataType(), request.tenantId(),
                record.preserveFormat(), record.tweak()
            );
            try {
                TokenizeResponse result = tokenize(withTenant, requesterId, requesterRole, sourceIp);
                results.add(new BatchTokenizeResponse.BatchResult(i, result, true, null));
                successCount++;
            } catch (Exception e) {
                // WHY: Partial failures are isolated — one bad record doesn't fail the batch
                results.add(new BatchTokenizeResponse.BatchResult(i, null, false, e.getMessage()));
                failureCount++;
            }
        }
        return new BatchTokenizeResponse(results, successCount, failureCount);
    }

    private void saveTokenMetadata(String tokenId, DataType dataType, String format, int keyVersion, String tenantId) {
        TokenMetadata metadata = new TokenMetadata();
        metadata.setTokenId(tokenId);
        metadata.setDataType(dataType);
        metadata.setFormat(format);
        metadata.setKeyVersion(keyVersion);
        metadata.setTenantId(tenantId);
        metadata.setCreatedAt(Instant.now());
        tokenMetadataRepository.save(metadata);
    }

    private void publishAuditEvent(String requesterId, String requesterRole, AuditEvent.Operation operation,
                                    String dataType, String tokenId, String sourceIp, String tenantId,
                                    boolean success, String failureReason) {
        AuditEvent event = new AuditEvent(
            Instant.now(), requesterId, requesterRole, operation, dataType,
            tokenId, sourceIp, tenantId, success, failureReason
        );
        // WHY: Spring's ApplicationEventPublisher decouples the engine from the audit module.
        // The audit module picks up the event asynchronously in its own thread pool.
        eventPublisher.publishEvent(event);
    }
}
