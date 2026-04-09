package com.tokenization.ui.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for cryptographic key lifecycle management.
 *
 * <p>WHY admin-only: Key rotation and status monitoring are highly privileged
 * operations. Unauthorized key rotation could make all existing tokens permanently
 * undetokenizable if not handled correctly.</p>
 *
 * <p>COMPLIANCE: Key management operations are audit-logged by the key management
 * module, satisfying PCI DSS Req 3.6 (key management procedures).</p>
 */
@Controller
@RequestMapping("/keys")
@PreAuthorize("hasRole('ADMIN')")
public class KeyManagementController {

    @GetMapping
    public String keyStatus(Model model) {
        model.addAttribute("pageTitle", "Key Management");
        return "keys";
    }
}
