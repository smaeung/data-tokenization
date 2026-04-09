package com.tokenization.engine.controller;

import com.tokenization.common.dto.*;
import com.tokenization.engine.service.MaskingService;
import com.tokenization.engine.service.TokenizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for tokenization, detokenization, masking, and batch operations.
 *
 * <p>WHY: The controller is thin — it delegates immediately to TokenizationService.
 * Its responsibility is HTTP request/response mapping, authentication context
 * extraction, and routing authorization (@PreAuthorize). No business logic here.</p>
 *
 * <p>SECURITY: Every endpoint requires authentication. Detokenization additionally
 * requires the DETOKENIZER or ADMIN role. This dual-layer enforcement (gateway + controller)
 * follows defense-in-depth principles.</p>
 *
 * <p>SECURITY: Request bodies are NEVER logged — the RequestLoggingFilter explicitly
 * excludes body content. This ensures sensitive plaintext (in tokenize requests) and
 * recovered values (in detokenize responses) never appear in logs.</p>
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Tokenization", description = "FF1 Format-Preserving Encryption operations")
@SecurityRequirement(name = "bearerAuth")
public class TokenizationController {

    private final TokenizationService tokenizationService;
    private final MaskingService maskingService;

    public TokenizationController(TokenizationService tokenizationService, MaskingService maskingService) {
        this.tokenizationService = tokenizationService;
        this.maskingService = maskingService;
    }

    /**
     * Tokenizes a single sensitive value.
     *
     * <p>WHY HTTP 201 Created: A new token resource is being created.
     * Using 201 instead of 200 allows clients to detect idempotency issues.</p>
     */
    @PostMapping("/tokenize")
    @PreAuthorize("hasRole('TOKENIZER') or hasRole('ADMIN')")
    @Operation(summary = "Tokenize a sensitive value using FF1 FPE")
    public ResponseEntity<TokenizeResponse> tokenize(
            @Valid @RequestBody TokenizeRequest request,
            @AuthenticationPrincipal UserDetails user,
            HttpServletRequest httpRequest) {

        String sourceIp = extractSourceIp(httpRequest);
        String role = user.getAuthorities().stream().findFirst()
            .map(a -> a.getAuthority()).orElse("UNKNOWN");

        TokenizeResponse response = tokenizationService.tokenize(request, user.getUsername(), role, sourceIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Reverses a token back to the original plaintext.
     *
     * <p>SECURITY: @PreAuthorize restricts to DETOKENIZER and ADMIN roles.
     * This is the most sensitive operation in the system.</p>
     */
    @PostMapping("/detokenize")
    @PreAuthorize("hasRole('DETOKENIZER') or hasRole('ADMIN')")
    @Operation(summary = "Detokenize a token to recover the original value (privileged)")
    public ResponseEntity<DetokenizeResponse> detokenize(
            @Valid @RequestBody DetokenizeRequest request,
            @AuthenticationPrincipal UserDetails user,
            HttpServletRequest httpRequest) {

        String sourceIp = extractSourceIp(httpRequest);
        String role = user.getAuthorities().stream().findFirst()
            .map(a -> a.getAuthority()).orElse("UNKNOWN");

        DetokenizeResponse response = tokenizationService.detokenize(request, user.getUsername(), role, sourceIp);
        return ResponseEntity.ok(response);
    }

    /**
     * Tokenizes a batch of sensitive values (up to 1,000).
     */
    @PostMapping("/tokenize/batch")
    @PreAuthorize("hasRole('TOKENIZER') or hasRole('ADMIN')")
    @Operation(summary = "Batch tokenize up to 1,000 sensitive values")
    public ResponseEntity<BatchTokenizeResponse> tokenizeBatch(
            @Valid @RequestBody BatchTokenizeRequest request,
            @AuthenticationPrincipal UserDetails user,
            HttpServletRequest httpRequest) {

        String sourceIp = extractSourceIp(httpRequest);
        String role = user.getAuthorities().stream().findFirst()
            .map(a -> a.getAuthority()).orElse("UNKNOWN");

        BatchTokenizeResponse response = tokenizationService.tokenizeBatch(request, user.getUsername(), role, sourceIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Dynamically masks a token value without requiring DETOKENIZE permission.
     */
    @PostMapping("/mask")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Apply dynamic masking to a token (no DETOKENIZE permission required)")
    public ResponseEntity<MaskResponse> mask(@Valid @RequestBody MaskRequest request) {
        return ResponseEntity.ok(maskingService.mask(request));
    }

    /**
     * Extracts the real source IP, respecting X-Forwarded-For from the API Gateway.
     *
     * <p>WHY: The service runs behind a gateway/load balancer. The X-Forwarded-For
     * header carries the original client IP for accurate audit logging.</p>
     *
     * <p>SECURITY: We take only the FIRST IP in X-Forwarded-For to prevent
     * IP spoofing via crafted headers (attackers may append fake IPs).</p>
     */
    private String extractSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // WHY: Take only the leftmost IP — it is the original client, set by the outermost proxy
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
