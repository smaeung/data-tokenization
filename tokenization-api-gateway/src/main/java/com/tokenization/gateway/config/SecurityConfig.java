package com.tokenization.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Reactive Spring Security configuration for the API Gateway.
 *
 * <p>WHY @EnableWebFluxSecurity: The gateway uses Spring WebFlux (reactive).
 * Standard @EnableWebSecurity is for Servlet-based apps — using the wrong one
 * would silently disable security on a reactive application.</p>
 *
 * <p>WHY disable httpBasic/formLogin: The gateway uses JWT only. Enabling other
 * authentication mechanisms would create unexpected auth bypass vectors.</p>
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            // WHY: CSRF not needed for stateless JWT API (CSRF exploits session cookies)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            // WHY: Disable httpBasic — gateway uses JWT only, not username/password over HTTP
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            // WHY: Disable formLogin — no HTML login form in the gateway layer
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/actuator/health", "/actuator/info").permitAll()
                .pathMatchers("/api/v1/auth/**").permitAll()
                // WHY: JwtAuthenticationFilter handles all other auth — this just denies unauthenticated at the Spring layer
                .anyExchange().permitAll()
            )
            .build();
    }
}
