package com.tokenization.ui.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for the Thymeleaf admin UI.
 *
 * <p>WHY form-based login (not JWT) for UI: The UI is a browser-based application.
 * Browser CSRF protection works with session cookies + CSRF tokens, which is the
 * default Spring Security setup. JWT would require storing tokens in localStorage
 * (XSS risk) or cookies (requires custom CSRF handling).</p>
 *
 * <p>SECURITY: CSRF protection is ENABLED (unlike the API modules).
 * Thymeleaf automatically injects CSRF tokens into all forms.</p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // WHY: CSRF enabled for form-based UI (Thymeleaf auto-injects CSRF tokens)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/js/**", "/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                // WHY: Clear authentication cookie on logout to prevent session reuse
                .deleteCookies("JSESSIONID")
            )
            .build();
    }
}
