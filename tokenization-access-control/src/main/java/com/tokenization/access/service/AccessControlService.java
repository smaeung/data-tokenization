package com.tokenization.access.service;

import com.tokenization.common.exception.AccessDeniedException;
import com.tokenization.common.model.DataType;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Central service for evaluating access control decisions.
 *
 * <p>WHY: This service implements a two-layer authorization model:
 * <ol>
 *   <li>RBAC (Role-Based): Does the user have the required role? (fast, local check)</li>
 *   <li>ABAC (Attribute-Based): Does the context allow the operation? (calls OPA)</li>
 * </ol>
 * RBAC is checked first as a fast gate. Only if RBAC passes does the service
 * make the more expensive OPA call for ABAC evaluation.</p>
 *
 * <p>COMPLIANCE: All authorization decisions are evaluated by OPA, whose policies
 * are version-controlled in docs/opa/tokenization.rego. This provides an auditable,
 * externalized record of authorization policy separate from application code.</p>
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final OpaClient opaClient;

    public AccessControlService(OpaClient opaClient) {
        this.opaClient = opaClient;
    }

    /**
     * Evaluates whether a principal can tokenize a specific data type.
     *
     * @param username  The principal's username
     * @param role      The principal's role
     * @param dataType  The data type to be tokenized
     * @param tenantId  The tenant context
     * @throws AccessDeniedException if the operation is not permitted
     */
    public void assertCanTokenize(String username, String role, DataType dataType, String tenantId) {
        // WHY: RBAC gate — fast local check before calling OPA
        if (!hasTokenizeRole(role)) {
            log.warn("RBAC_DENY: user='{}', role='{}', operation=TOKENIZE, dataType='{}'",
                username, role, dataType);
            throw new AccessDeniedException("TOKENIZE:" + dataType);
        }
        // WHY: ABAC gate — OPA evaluates context-aware policies (time, IP, tenant attributes)
        evaluateWithOpa(username, role, "tokenize", dataType.name(), tenantId);
    }

    /**
     * Evaluates whether a principal can detokenize a specific data type.
     *
     * <p>SECURITY: Detokenization is the most sensitive operation.
     * Both the role (RBAC) and the data type sensitivity (ABAC) are checked.
     * For example, a DETOKENIZER may be allowed to detokenize CREDIT_CARD but not PHI.</p>
     */
    public void assertCanDetokenize(String username, String role, DataType dataType, String tenantId) {
        if (!hasDetokenizeRole(role)) {
            log.warn("RBAC_DENY: user='{}', role='{}', operation=DETOKENIZE, dataType='{}'",
                username, role, dataType);
            throw new AccessDeniedException("DETOKENIZE:" + dataType);
        }
        evaluateWithOpa(username, role, "detokenize", dataType.name(), tenantId);
    }

    /**
     * Evaluates whether a principal can view audit logs.
     */
    public void assertCanViewAudit(String username, String role, String tenantId) {
        if (!hasAuditRole(role)) {
            throw new AccessDeniedException("VIEW_AUDIT");
        }
        evaluateWithOpa(username, role, "view_audit", "AUDIT_LOG", tenantId);
    }

    /**
     * Evaluates whether a principal can perform key management operations.
     */
    public void assertCanManageKeys(String username, String role, String tenantId) {
        if (!isAdmin(role)) {
            throw new AccessDeniedException("MANAGE_KEYS");
        }
        evaluateWithOpa(username, role, "manage_keys", "KEY", tenantId);
    }

    /**
     * Calls OPA for ABAC policy evaluation with circuit breaker protection.
     *
     * <p>WHY @CircuitBreaker: If OPA is unavailable, we DENY by default (fail-closed).
     * This is the correct security posture — "deny unless explicitly allowed" is safer
     * than "allow unless explicitly denied" when the policy engine is unreachable.</p>
     */
    @CircuitBreaker(name = "opa", fallbackMethod = "opaUnavailableFallback")
    private void evaluateWithOpa(String username, String role, String operation,
                                   String dataType, String tenantId) {
        boolean allowed = opaClient.evaluate(username, role, operation, dataType, tenantId);
        if (!allowed) {
            log.warn("OPA_DENY: user='{}', role='{}', operation='{}', dataType='{}', tenant='{}'",
                username, role, operation, dataType, tenantId);
            throw new AccessDeniedException(operation + ":" + dataType);
        }
    }

    /**
     * Circuit breaker fallback — DENY when OPA is unreachable.
     *
     * <p>WHY fail-closed: Security systems must default to DENY on failure.
     * An attacker could trigger OPA unavailability to bypass authorization.
     * Failing closed prevents this attack vector.</p>
     */
    private void opaUnavailableFallback(String username, String role, String operation,
                                         String dataType, String tenantId, Exception ex) {
        log.error("OPA circuit breaker open — denying operation='{}' for user='{}'. Cause: {}",
            operation, username, ex.getMessage());
        throw new AccessDeniedException(operation + ":OPA_UNAVAILABLE");
    }

    private boolean hasTokenizeRole(String role) {
        return "ROLE_TOKENIZER".equals(role) || "ROLE_ADMIN".equals(role);
    }

    private boolean hasDetokenizeRole(String role) {
        return "ROLE_DETOKENIZER".equals(role) || "ROLE_ADMIN".equals(role);
    }

    private boolean hasAuditRole(String role) {
        return "ROLE_AUDITOR".equals(role) || "ROLE_ADMIN".equals(role);
    }

    private boolean isAdmin(String role) {
        return "ROLE_ADMIN".equals(role);
    }
}
