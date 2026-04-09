package com.tokenization.engine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * Tokenization Engine — the cryptographic core of the tokenization service.
 *
 * <p>WHY: This service owns all FF1 FPE operations (tokenize, detokenize, mask).
 * It is intentionally NOT the access control gate — that responsibility belongs to
 * the API Gateway and Access Control modules. The engine trusts that callers have
 * already been authorized and focuses solely on correct cryptographic execution.</p>
 */
@SpringBootApplication
@ComponentScan(basePackages = {"com.tokenization.engine", "com.tokenization.keymanagement"})
public class EngineApplication {
    public static void main(String[] args) {
        SpringApplication.run(EngineApplication.class, args);
    }
}
