package com.tokenization.access;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Access Control Service — enforces RBAC and ABAC for all tokenization operations.
 *
 * <p>WHY: Separating access control into its own module provides:
 * <ul>
 *   <li>Independent scaling of the policy engine</li>
 *   <li>Policy changes without redeploying the tokenization engine</li>
 *   <li>Clear audit boundary: all authorization decisions are logged here</li>
 * </ul></p>
 *
 * <p>SECURITY: This service implements Zero Trust principles — every request is
 * evaluated against current policy regardless of source or prior authorization.</p>
 */
@SpringBootApplication
public class AccessControlApplication {
    public static void main(String[] args) {
        SpringApplication.run(AccessControlApplication.class, args);
    }
}
