package com.tokenization.access.service;

import com.tokenization.common.exception.AccessDeniedException;
import com.tokenization.common.model.DataType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AccessControlService RBAC enforcement.
 *
 * <p>WHY: We mock OpaClient to test the RBAC layer independently.
 * OPA integration is tested separately in integration tests.</p>
 */
class AccessControlServiceTest {

    @Mock
    private OpaClient opaClient;

    private AccessControlService accessControlService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Default: OPA allows everything (we're testing RBAC layer here)
        when(opaClient.evaluate(any(), any(), any(), any(), any())).thenReturn(true);
        accessControlService = new AccessControlService(opaClient);
    }

    // ─── Tokenize permission tests ────────────────────────────────────────────

    @Test
    @DisplayName("TOKENIZER role can tokenize CREDIT_CARD")
    void assertCanTokenize_tokenizerRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanTokenize("user1", "ROLE_TOKENIZER", DataType.CREDIT_CARD, "tenant-1"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("ADMIN role can tokenize any data type")
    void assertCanTokenize_adminRole_allowed() {
        for (DataType type : DataType.values()) {
            assertThatCode(() ->
                accessControlService.assertCanTokenize("admin", "ROLE_ADMIN", type, "tenant-1"))
                .doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("READ_ONLY role cannot tokenize")
    void assertCanTokenize_readOnlyRole_denied() {
        assertThatThrownBy(() ->
            accessControlService.assertCanTokenize("user1", "ROLE_READ_ONLY", DataType.CREDIT_CARD, "tenant-1"))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("AUDITOR role cannot tokenize")
    void assertCanTokenize_auditorRole_denied() {
        assertThatThrownBy(() ->
            accessControlService.assertCanTokenize("auditor1", "ROLE_AUDITOR", DataType.CREDIT_CARD, "tenant-1"))
            .isInstanceOf(AccessDeniedException.class);
    }

    // ─── Detokenize permission tests ──────────────────────────────────────────

    @Test
    @DisplayName("DETOKENIZER role can detokenize")
    void assertCanDetokenize_detokenizerRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanDetokenize("user1", "ROLE_DETOKENIZER", DataType.CREDIT_CARD, "tenant-1"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("TOKENIZER role cannot detokenize")
    void assertCanDetokenize_tokenizerRole_denied() {
        assertThatThrownBy(() ->
            accessControlService.assertCanDetokenize("user1", "ROLE_TOKENIZER", DataType.CREDIT_CARD, "tenant-1"))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("OPA DENY overrides RBAC ALLOW")
    void assertCanTokenize_opaDeniesDespiteRbacAllow() {
        // RBAC allows TOKENIZER, but OPA denies (e.g., outside business hours policy)
        when(opaClient.evaluate(any(), any(), any(), any(), any())).thenReturn(false);
        assertThatThrownBy(() ->
            accessControlService.assertCanTokenize("user1", "ROLE_TOKENIZER", DataType.CREDIT_CARD, "tenant-1"))
            .isInstanceOf(AccessDeniedException.class);
    }

    // ─── Audit log access tests ───────────────────────────────────────────────

    @Test
    @DisplayName("AUDITOR role can view audit logs")
    void assertCanViewAudit_auditorRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanViewAudit("auditor1", "ROLE_AUDITOR", "tenant-1"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("TOKENIZER role cannot view audit logs")
    void assertCanViewAudit_tokenizerRole_denied() {
        assertThatThrownBy(() ->
            accessControlService.assertCanViewAudit("user1", "ROLE_TOKENIZER", "tenant-1"))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("ADMIN role can detokenize any data type")
    void assertCanDetokenize_adminRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanDetokenize("admin", "ROLE_ADMIN", DataType.CREDIT_CARD, "tenant-1"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("ADMIN role can view audit logs")
    void assertCanViewAudit_adminRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanViewAudit("admin", "ROLE_ADMIN", "tenant-1"))
            .doesNotThrowAnyException();
    }

    // ─── Key management tests ─────────────────────────────────────────────────

    @Test
    @DisplayName("ADMIN role can manage keys")
    void assertCanManageKeys_adminRole_allowed() {
        assertThatCode(() ->
            accessControlService.assertCanManageKeys("admin", "ROLE_ADMIN", "tenant-1"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Only ADMIN can manage keys")
    void assertCanManageKeys_nonAdmin_denied() {
        for (String role : new String[]{"ROLE_TOKENIZER", "ROLE_DETOKENIZER", "ROLE_AUDITOR", "ROLE_READ_ONLY"}) {
            assertThatThrownBy(() ->
                accessControlService.assertCanManageKeys("user1", role, "tenant-1"))
                .isInstanceOf(AccessDeniedException.class);
        }
    }
}
