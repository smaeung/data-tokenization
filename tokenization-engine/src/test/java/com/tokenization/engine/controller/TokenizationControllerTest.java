package com.tokenization.engine.controller;

import com.tokenization.common.dto.*;
import com.tokenization.common.model.DataType;
import com.tokenization.engine.service.MaskingService;
import com.tokenization.engine.service.TokenizationService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenizationControllerTest {

    @Mock TokenizationService tokenizationService;
    @Mock MaskingService maskingService;

    TokenizationController controller;

    UserDetails tokenizer;
    UserDetails detokenizer;
    HttpServletRequest mockRequest;

    @BeforeEach
    void setUp() {
        controller = new TokenizationController(tokenizationService, maskingService);
        tokenizer = new User("alice", "", List.of(new SimpleGrantedAuthority("ROLE_TOKENIZER")));
        detokenizer = new User("bob", "", List.of(new SimpleGrantedAuthority("ROLE_DETOKENIZER")));
        mockRequest = mock(HttpServletRequest.class);
    }

    // --- tokenize ---

    @Test
    void tokenize_returns201Created() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn(null);
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        TokenizeResponse resp = new TokenizeResponse("4111111111111111", "tok_abc",
            DataType.CREDIT_CARD, "NUMERIC_16", 1, Instant.now());
        when(tokenizationService.tokenize(any(), eq("alice"), any(), any())).thenReturn(resp);

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        ResponseEntity<TokenizeResponse> result = controller.tokenize(req, tokenizer, mockRequest);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(result.getBody()).isEqualTo(resp);
    }

    @Test
    void tokenize_usesXForwardedForAsSourceIp() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5, 10.0.0.1");
        TokenizeResponse resp = new TokenizeResponse("4111111111111111", "tok_abc",
            DataType.CREDIT_CARD, "NUMERIC_16", 1, Instant.now());
        when(tokenizationService.tokenize(any(), any(), any(), eq("203.0.113.5"))).thenReturn(resp);

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        controller.tokenize(req, tokenizer, mockRequest);

        verify(tokenizationService).tokenize(any(), any(), any(), eq("203.0.113.5"));
    }

    @Test
    void tokenize_fallsBackToRemoteAddrWhenNoXForwardedFor() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn(null);
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        TokenizeResponse resp = new TokenizeResponse("4111111111111111", "tok_abc",
            DataType.CREDIT_CARD, "NUMERIC_16", 1, Instant.now());
        when(tokenizationService.tokenize(any(), any(), any(), eq("127.0.0.1"))).thenReturn(resp);

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        controller.tokenize(req, tokenizer, mockRequest);

        verify(tokenizationService).tokenize(any(), any(), any(), eq("127.0.0.1"));
    }

    // --- detokenize ---

    @Test
    void detokenize_returns200Ok() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn(null);
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        DetokenizeResponse resp = new DetokenizeResponse("4532015112830366", DataType.CREDIT_CARD, "****1234");
        when(tokenizationService.detokenize(any(), eq("bob"), any(), any())).thenReturn(resp);

        DetokenizeRequest req = new DetokenizeRequest("4111111111111111", "tok_abc", "tenant-1");
        ResponseEntity<DetokenizeResponse> result = controller.detokenize(req, detokenizer, mockRequest);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isEqualTo(resp);
    }

    // --- batch ---

    @Test
    void tokenizeBatch_returns201Created() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn(null);
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        BatchTokenizeResponse resp = new BatchTokenizeResponse(List.of(), 0, 0);
        when(tokenizationService.tokenizeBatch(any(), any(), any(), any())).thenReturn(resp);

        BatchTokenizeRequest req = new BatchTokenizeRequest(List.of(), "tenant-1");
        ResponseEntity<BatchTokenizeResponse> result = controller.tokenizeBatch(req, tokenizer, mockRequest);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void tokenize_blankXForwardedForFallsBackToRemoteAddr() {
        when(mockRequest.getHeader("X-Forwarded-For")).thenReturn("   ");
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        TokenizeResponse resp = new TokenizeResponse("4111111111111111", "tok_abc",
            DataType.CREDIT_CARD, "NUMERIC_16", 1, Instant.now());
        when(tokenizationService.tokenize(any(), any(), any(), eq("127.0.0.1"))).thenReturn(resp);

        TokenizeRequest req = new TokenizeRequest("4532015112830366", DataType.CREDIT_CARD, "tenant-1", true, null);
        controller.tokenize(req, tokenizer, mockRequest);

        verify(tokenizationService).tokenize(any(), any(), any(), eq("127.0.0.1"));
    }

    // --- mask ---

    @Test
    void mask_returns200WithMaskedValue() {
        MaskResponse resp = new MaskResponse("****1234", "LAST_4");
        when(maskingService.mask(any())).thenReturn(resp);

        MaskRequest req = new MaskRequest("4111111111111111", DataType.MaskPattern.LAST_4, DataType.CREDIT_CARD);
        ResponseEntity<MaskResponse> result = controller.mask(req);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isEqualTo(resp);
    }
}
