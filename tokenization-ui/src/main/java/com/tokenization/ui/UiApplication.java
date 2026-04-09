package com.tokenization.ui;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Admin UI Portal — Thymeleaf server-side rendered admin dashboard.
 *
 * <p>WHY server-side rendering: Reduces XSS attack surface compared to SPAs.
 * Thymeleaf's server-side templating with Spring Security integration
 * provides built-in CSRF protection and role-based view rendering.</p>
 */
@SpringBootApplication
public class UiApplication {
    public static void main(String[] args) {
        SpringApplication.run(UiApplication.class, args);
    }
}
