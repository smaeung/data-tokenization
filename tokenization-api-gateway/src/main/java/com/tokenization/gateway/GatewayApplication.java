package com.tokenization.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API Gateway — the single entry point for all external traffic.
 *
 * <p>WHY centralized gateway: The API Gateway enforces authentication, rate limiting,
 * and routing before any request reaches the backend microservices. This provides:
 * <ul>
 *   <li>Single enforcement point for JWT validation — backends trust forwarded identity</li>
 *   <li>Rate limiting protection against DDoS and credential stuffing</li>
 *   <li>Defense against shadow APIs (unlisted/forgotten endpoints)</li>
 *   <li>Centralized logging of all inbound traffic metadata (no body logging)</li>
 * </ul></p>
 *
 * <p>SECURITY: The gateway is the only service exposed to the internet.
 * All backend services communicate only on the internal Docker network.</p>
 */
@SpringBootApplication
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
