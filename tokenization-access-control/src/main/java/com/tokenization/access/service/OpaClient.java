package com.tokenization.access.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * HTTP client for Open Policy Agent (OPA) ABAC policy evaluation.
 *
 * <p>WHY OPA: Open Policy Agent provides an externalized, auditable, version-controlled
 * policy engine. Policies (Rego) are stored in docs/opa/tokenization.rego and can be
 * updated without redeploying the application. This satisfies compliance requirements
 * for separation of duties between policy authors and application developers.</p>
 *
 * <p>ARCHITECTURE: OPA runs as a sidecar container at http://opa:8181.
 * The /v1/data/tokenization/allow endpoint evaluates the Rego policy
 * with the provided input context and returns {result: true/false}.</p>
 *
 * <p>SECURITY: OPA communication is on an internal network only (not exposed externally).
 * In production, mTLS between the application and OPA sidecar provides transport security.</p>
 */
@Component
public class OpaClient {

    private static final Logger log = LoggerFactory.getLogger(OpaClient.class);

    @Value("${opa.url:http://localhost:8181}")
    private String opaUrl;

    private final RestTemplate restTemplate;

    public OpaClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Evaluates the OPA policy for the given operation context.
     *
     * <p>WHY the input structure: OPA Rego policies receive a JSON "input" object.
     * We include username, role, operation, data type, and tenant ID so the policy
     * can make context-aware decisions (e.g., "DETOKENIZER may access CREDIT_CARD but not PHI").</p>
     *
     * @return true if the operation is allowed, false if denied
     */
    public boolean evaluate(String username, String role, String operation,
                             String dataType, String tenantId) {
        try {
            Map<String, Object> input = Map.of(
                "input", Map.of(
                    "user", username,
                    "role", role,
                    "operation", operation,
                    "dataType", dataType,
                    "tenantId", tenantId
                )
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(input, headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                opaUrl + "/v1/data/tokenization/allow",
                HttpMethod.POST,
                entity,
                Map.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Object result = response.getBody().get("result");
                return Boolean.TRUE.equals(result);
            }
            // WHY: Treat non-2xx as denial (fail-closed)
            log.warn("OPA returned non-2xx status: {}. Denying.", response.getStatusCode());
            return false;

        } catch (Exception e) {
            // WHY: Log and return false — the circuit breaker in AccessControlService
            // will handle repeated failures by opening the circuit
            log.error("OPA evaluation failed: {}", e.getMessage());
            throw new RuntimeException("OPA evaluation error: " + e.getMessage(), e);
        }
    }
}
