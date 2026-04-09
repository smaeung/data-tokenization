package com.tokenization.access.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

/**
 * Spring Security configuration for the access control module.
 *
 * <p>WHY stateless (STATELESS session): JWT-based authentication is stateless.
 * No session state means horizontal scaling works without session affinity or
 * shared session storage. Eliminates session fixation attack vector.</p>
 *
 * <p>WHY BCrypt cost factor 12: The OWASP recommendation for BCrypt is a cost
 * factor that takes at least 1 second to compute. Factor 12 achieves this on
 * modern hardware while remaining feasible for login operations.</p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // WHY: Disable CSRF for stateless JWT API — CSRF only applies to session-based auth
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Health checks are public (needed for load balancer health probes)
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // WHY BCrypt strength=12: Balances security (slow enough to resist brute force)
        // with usability (fast enough for interactive login within ~1 second).
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public RestTemplate restTemplate() {
        // WHY: RestTemplate for OPA client. In production, configure with
        // custom SSL context for mTLS between the service and OPA sidecar.
        return new RestTemplate();
    }
}
