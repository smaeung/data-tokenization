package com.tokenization.ui.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Dashboard controller showing system health and key statistics.
 *
 * <p>WHY statistics instead of raw data: The dashboard shows COUNTS and STATUS
 * information only — never token values, never plaintext data. This ensures
 * that even the admin UI cannot be used to exfiltrate sensitive data.</p>
 */
@Controller
public class DashboardController {

    @GetMapping({"/", "/dashboard"})
    @PreAuthorize("isAuthenticated()")
    public String dashboard(Model model) {
        // WHY placeholder data: In production, these metrics come from
        // Micrometer counters exposed via the Actuator metrics endpoint
        model.addAttribute("pageTitle", "Dashboard");
        model.addAttribute("tokensIssuedToday", 0);
        model.addAttribute("activeKeys", 0);
        model.addAttribute("recentAnomalies", 0);
        model.addAttribute("systemStatus", "OPERATIONAL");
        return "dashboard";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
}
