package com.tokenization.ui.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for user and role management.
 *
 * <p>WHY admin-only: User management allows role assignment which directly
 * controls who can tokenize/detokenize. Only ADMIN can change this.</p>
 */
@Controller
@RequestMapping("/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserManagementController {

    @GetMapping
    public String listUsers(Model model) {
        model.addAttribute("pageTitle", "User Management");
        return "users";
    }
}
