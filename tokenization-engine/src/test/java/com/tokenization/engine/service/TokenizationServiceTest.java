package com.tokenization.engine.service;

import com.tokenization.common.dto.*;
import com.tokenization.common.event.AuditEvent;
import com.tokenization.common.exception.TokenizationException;
import com.tokenization.common.model.DataType;
import com.tokenization.engine.crypto.FF1Engine;
import com.tokenization.engine.entity.TokenMetadata;
import com.tokenization.engine.repository.TokenMetadataRepository;
import com.tokenization.keymanagement.KeyProvider;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenizationServiceTest {

    @Mock FF1Engine ff1Engine;
    @Mock KeyProvider keyProvider;
    @Mock TokenMetadataRepository tokenMetadataRepository;
    @Mock MaskingService maskingService;
    @Mock ApplicationEventPublisher eventPublisher;

    TokenizationService service;
    SecretKey testKey;

    @BeforeEach
    void setUp() throws Exception {
        service = new TokenizationService(
            ff1Engine, keyProvider, tokenMetadataRepository,
            maskingService, eventPublisher, new SimpleMeterRegistry()
        );
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        testKey = kg.generateKey();
    }

    // --- tokenize() ---

    @Test
    void tokenize_returnsTokenWithCorrectDataType() {
        when(keyProvider.getActiveKey("tenant-1")).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion("tenant-1")).thenReturn(1);
        when(ff1Engine.tokenize(any(), any(), any(), any())).thenReturn("4111111111111111");

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        TokenizeResponse resp = service.tokenize(req, "user1", "ROLE_TOKENIZER", "127.0.0.1");

        assertThat(resp.token()).isEqualTo("4111111111111111");
        assertThat(resp.dataType()).isEqualTo(DataType.CREDIT_CARD);
        assertThat(resp.keyVersion()).isEqualTo(1);
        assertThat(resp.tokenId()).startsWith("tok_");
    }

    @Test
    void tokenize_savesTokenMetadata() {
        when(keyProvider.getActiveKey(any())).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion(any())).thenReturn(2);
        when(ff1Engine.tokenize(any(), any(), any(), any())).thenReturn("9999999999999999");

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        service.tokenize(req, "user1", "ROLE_TOKENIZER", "10.0.0.1");

        ArgumentCaptor<TokenMetadata> captor = ArgumentCaptor.forClass(TokenMetadata.class);
        verify(tokenMetadataRepository).save(captor.capture());

        TokenMetadata saved = captor.getValue();
        assertThat(saved.getTenantId()).isEqualTo("tenant-1");
        assertThat(saved.getDataType()).isEqualTo(DataType.CREDIT_CARD);
        assertThat(saved.getKeyVersion()).isEqualTo(2);
        assertThat(saved.getTokenId()).startsWith("tok_");
    }

    @Test
    void tokenize_publishesAuditEvent() {
        when(keyProvider.getActiveKey(any())).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion(any())).thenReturn(1);
        when(ff1Engine.tokenize(any(), any(), any(), any())).thenReturn("4111111111111111");

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        service.tokenize(req, "alice", "ROLE_TOKENIZER", "192.168.1.1");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher, atLeastOnce()).publishEvent(captor.capture());

        AuditEvent event = captor.getValue();
        assertThat(event.operation()).isEqualTo(AuditEvent.Operation.TOKENIZE);
        assertThat(event.requesterId()).isEqualTo("alice");
        assertThat(event.success()).isTrue();
    }

    @Test
    void tokenize_onFailure_publishesFailureAuditEvent() {
        when(keyProvider.getActiveKey(any())).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion(any())).thenReturn(1);
        when(ff1Engine.tokenize(any(), any(), any(), any()))
            .thenThrow(new RuntimeException("FF1 error"));

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        assertThatThrownBy(() -> service.tokenize(req, "alice", "ROLE_TOKENIZER", "1.2.3.4"))
            .isInstanceOf(RuntimeException.class);

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().success()).isFalse();
    }

    // --- detokenize() ---

    @Test
    void detokenize_returnsOriginalPlaintext() throws Exception {
        TokenMetadata meta = buildMetadata("tok_abc", DataType.CREDIT_CARD, 1, "tenant-1");
        when(tokenMetadataRepository.findById("tok_abc")).thenReturn(Optional.of(meta));
        when(keyProvider.getKey("tenant-1", 1)).thenReturn(testKey);
        when(ff1Engine.detokenize(any(), any(), any(), any())).thenReturn("4532015112830366");
        when(maskingService.mask(any())).thenReturn(new MaskResponse("************0366", "LAST_4"));

        DetokenizeRequest req = new DetokenizeRequest("4111111111111111", "tok_abc", "tenant-1");
        DetokenizeResponse resp = service.detokenize(req, "user1", "ROLE_DETOKENIZER", "127.0.0.1");

        assertThat(resp.data()).isEqualTo("4532015112830366");
        assertThat(resp.dataType()).isEqualTo(DataType.CREDIT_CARD);
    }

    @Test
    void detokenize_throwsWhenTokenNotFound() {
        when(tokenMetadataRepository.findById("tok_missing")).thenReturn(Optional.empty());

        DetokenizeRequest req = new DetokenizeRequest("9999999999999999", "tok_missing", "tenant-1");
        assertThatThrownBy(() -> service.detokenize(req, "user1", "ROLE_DETOKENIZER", "127.0.0.1"))
            .isInstanceOf(TokenizationException.class)
            .hasMessageContaining("Token metadata not found");
    }

    @Test
    void detokenize_throwsOnTenantMismatch() {
        TokenMetadata meta = buildMetadata("tok_abc", DataType.CREDIT_CARD, 1, "tenant-OTHER");
        when(tokenMetadataRepository.findById("tok_abc")).thenReturn(Optional.of(meta));

        DetokenizeRequest req = new DetokenizeRequest("4111111111111111", "tok_abc", "tenant-1");
        assertThatThrownBy(() -> service.detokenize(req, "user1", "ROLE_DETOKENIZER", "127.0.0.1"))
            .isInstanceOf(TokenizationException.class)
            .hasMessageContaining("Tenant mismatch");
    }

    @Test
    void detokenize_publishesAuditEvent() {
        TokenMetadata meta = buildMetadata("tok_abc", DataType.CREDIT_CARD, 1, "tenant-1");
        when(tokenMetadataRepository.findById("tok_abc")).thenReturn(Optional.of(meta));
        when(keyProvider.getKey(any(), anyInt())).thenReturn(testKey);
        when(ff1Engine.detokenize(any(), any(), any(), any())).thenReturn("4532015112830366");
        when(maskingService.mask(any())).thenReturn(new MaskResponse("************0366", "LAST_4"));

        DetokenizeRequest req = new DetokenizeRequest("4111111111111111", "tok_abc", "tenant-1");
        service.detokenize(req, "bob", "ROLE_DETOKENIZER", "10.0.0.1");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher, atLeastOnce()).publishEvent(captor.capture());
        assertThat(captor.getValue().operation()).isEqualTo(AuditEvent.Operation.DETOKENIZE);
        assertThat(captor.getValue().requesterId()).isEqualTo("bob");
    }

    // --- tokenizeBatch() ---

    @Test
    void tokenizeBatch_returnsSuccessCountForAllRecords() {
        when(keyProvider.getActiveKey(any())).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion(any())).thenReturn(1);
        when(ff1Engine.tokenize(any(), any(), any(), any())).thenReturn("4111111111111111");

        List<TokenizeRequest> records = List.of(
            new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, null, true, null),
            new TokenizeRequest("4532015112830367", DataType.CREDIT_CARD, null, true, null)
        );
        BatchTokenizeRequest req = new BatchTokenizeRequest(records, "tenant-1");
        BatchTokenizeResponse resp = service.tokenizeBatch(req, "user1", "ROLE_TOKENIZER", "127.0.0.1");

        assertThat(resp.successCount()).isEqualTo(2);
        assertThat(resp.failureCount()).isEqualTo(0);
    }

    @Test
    void tokenizeBatch_isolatesFailures_partialSuccessReturned() {
        when(keyProvider.getActiveKey(any())).thenReturn(testKey);
        when(keyProvider.getCurrentKeyVersion(any())).thenReturn(1);
        when(ff1Engine.tokenize(any(), any(), any(), any()))
            .thenReturn("4111111111111111")
            .thenThrow(new RuntimeException("bad record"));

        List<TokenizeRequest> records = List.of(
            new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, null, true, null),
            new TokenizeRequest("BAD", DataType.CREDIT_CARD, null, true, null)
        );
        BatchTokenizeRequest req = new BatchTokenizeRequest(records, "tenant-1");
        BatchTokenizeResponse resp = service.tokenizeBatch(req, "user1", "ROLE_TOKENIZER", "127.0.0.1");

        assertThat(resp.successCount()).isEqualTo(1);
        assertThat(resp.failureCount()).isEqualTo(1);
        assertThat(resp.results().get(0).success()).isTrue();
        assertThat(resp.results().get(1).success()).isFalse();
    }

    @Test
    void tokenizeBatch_emptyBatch_returnsZeroCounts() {
        BatchTokenizeRequest req = new BatchTokenizeRequest(List.of(), "tenant-1");
        BatchTokenizeResponse resp = service.tokenizeBatch(req, "user1", "ROLE_TOKENIZER", "127.0.0.1");

        assertThat(resp.successCount()).isEqualTo(0);
        assertThat(resp.failureCount()).isEqualTo(0);
        assertThat(resp.results()).isEmpty();
    }

    @Test
    void detokenize_publishesFailureAuditEventOnTokenizationException() {
        TokenMetadata meta = buildMetadata("tok_abc", DataType.CREDIT_CARD, 1, "tenant-1");
        when(tokenMetadataRepository.findById("tok_abc")).thenReturn(Optional.of(meta));
        when(keyProvider.getKey(any(), anyInt())).thenReturn(testKey);
        when(ff1Engine.detokenize(any(), any(), any(), any()))
            .thenThrow(new com.tokenization.common.exception.TokenizationException(
                com.tokenization.common.exception.TokenizationException.ErrorCode.CRYPTO_FAILURE,
                "FF1 error"));

        DetokenizeRequest req = new DetokenizeRequest("4111111111111111", "tok_abc", "tenant-1");
        assertThatThrownBy(() -> service.detokenize(req, "bob", "ROLE_DETOKENIZER", "127.0.0.1"))
            .isInstanceOf(com.tokenization.common.exception.TokenizationException.class);

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher, atLeastOnce()).publishEvent(captor.capture());
        AuditEvent failEvent = captor.getAllValues().stream()
            .filter(e -> !e.success()).findFirst().orElseThrow();
        assertThat(failEvent.success()).isFalse();
        assertThat(failEvent.requesterId()).isEqualTo("bob");
    }

    private TokenMetadata buildMetadata(String tokenId, DataType dataType, int keyVersion, String tenantId) {
        TokenMetadata meta = new TokenMetadata();
        meta.setTokenId(tokenId);
        meta.setDataType(dataType);
        meta.setFormat("NUMERIC_16");
        meta.setKeyVersion(keyVersion);
        meta.setTenantId(tenantId);
        meta.setCreatedAt(Instant.now());
        return meta;
    }
}
