package com.tokenization.ui.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controller for the audit log viewer page.
 *
 * <p>WHY @PreAuthorize("hasRole('AUDITOR') or hasRole('ADMIN')"): Audit logs
 * contain operation metadata including token IDs and user activity patterns.
 * Restricting access prevents unauthorized users from inferring usage patterns.</p>
 */
@Controller
@RequestMapping("/audit")
public class AuditLogController {

    @GetMapping
    @PreAuthorize("hasRole('AUDITOR') or hasRole('ADMIN')")
    public String auditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(required = false) String operation,
            @RequestParam(required = false) String requesterId,
            Model model) {
        model.addAttribute("pageTitle", "Audit Logs");
        model.addAttribute("page", page);
        model.addAttribute("selectedOperation", operation);
        model.addAttribute("selectedRequesterId", requesterId);
        return "audit";
    }
}
