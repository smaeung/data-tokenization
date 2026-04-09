package com.tokenization.access.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OpaClientTest {

    @Mock RestTemplate restTemplate;

    OpaClient opaClient;

    @BeforeEach
    void setUp() {
        opaClient = new OpaClient(restTemplate);
        ReflectionTestUtils.setField(opaClient, "opaUrl", "http://localhost:8181");
    }

    @Test
    void evaluate_returnsTrueWhenOpaAllows() {
        mockOpaResponse(Map.of("result", true));

        boolean allowed = opaClient.evaluate("alice", "ROLE_TOKENIZER", "tokenize", "CREDIT_CARD", "tenant-1");

        assertThat(allowed).isTrue();
    }

    @Test
    void evaluate_returnsFalseWhenOpaDenies() {
        mockOpaResponse(Map.of("result", false));

        boolean allowed = opaClient.evaluate("alice", "ROLE_READ_ONLY", "detokenize", "CREDIT_CARD", "tenant-1");

        assertThat(allowed).isFalse();
    }

    @Test
    void evaluate_returnsFalseWhenResultKeyMissing() {
        mockOpaResponse(Map.of());

        boolean allowed = opaClient.evaluate("alice", "ROLE_TOKENIZER", "tokenize", "CREDIT_CARD", "tenant-1");

        assertThat(allowed).isFalse();
    }

    @Test
    void evaluate_throwsOnRestTemplateException() {
        when(restTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
            .thenThrow(new RuntimeException("Connection refused"));

        assertThatThrownBy(() ->
            opaClient.evaluate("alice", "ROLE_TOKENIZER", "tokenize", "CREDIT_CARD", "tenant-1")
        ).isInstanceOf(RuntimeException.class)
         .hasMessageContaining("OPA evaluation error");
    }

    @Test
    void evaluate_sendsCorrectInputStructure() {
        mockOpaResponse(Map.of("result", true));

        opaClient.evaluate("bob", "ROLE_DETOKENIZER", "detokenize", "SSN", "tenant-2");

        ArgumentCaptor<HttpEntity> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(
            eq("http://localhost:8181/v1/data/tokenization/allow"),
            eq(HttpMethod.POST),
            captor.capture(),
            eq(Map.class)
        );

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) captor.getValue().getBody();
        assertThat(body).containsKey("input");

        @SuppressWarnings("unchecked")
        Map<String, Object> input = (Map<String, Object>) body.get("input");
        assertThat(input.get("user")).isEqualTo("bob");
        assertThat(input.get("role")).isEqualTo("ROLE_DETOKENIZER");
        assertThat(input.get("operation")).isEqualTo("detokenize");
        assertThat(input.get("dataType")).isEqualTo("SSN");
        assertThat(input.get("tenantId")).isEqualTo("tenant-2");
    }

    @Test
    void evaluate_returnsFalseOnNon2xxResponse() {
        ResponseEntity<Map> response = ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        when(restTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
            .thenReturn(response);

        boolean allowed = opaClient.evaluate("alice", "ROLE_TOKENIZER", "tokenize", "CREDIT_CARD", "tenant-1");

        assertThat(allowed).isFalse();
    }

    @SuppressWarnings("unchecked")
    private void mockOpaResponse(Map<String, Object> responseBody) {
        ResponseEntity<Map> response = ResponseEntity.ok(responseBody);
        when(restTemplate.exchange(anyString(), any(), any(), eq(Map.class)))
            .thenReturn(response);
    }
}
