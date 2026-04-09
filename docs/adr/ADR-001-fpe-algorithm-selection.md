# ADR-001: Format-Preserving Encryption Algorithm Selection (FF1)

## Status
Accepted

## Date
2026-04-08

## Context
The tokenization service must replace sensitive data (credit card numbers, SSNs, phone numbers) with surrogate values that preserve the exact format and length of the original data. This requirement rules out standard encryption modes (AES-CBC, AES-GCM) which produce outputs of different length and structure than the input.

Two main approaches exist:
1. **Random tokenization with vault**: Generate a random token, store the mapping in a secure database
2. **Format-Preserving Encryption (FPE)**: Use a cryptographic algorithm designed to produce ciphertext in the same format as the plaintext

## Decision
We chose **FF1 (NIST SP 800-38G)** Format-Preserving Encryption as the tokenization algorithm.

## Rationale
- FF1 is the NIST-standardized FPE algorithm, ensuring regulatory acceptance for PCI DSS and HIPAA
- FF1 is deterministic: same input + key → same output, enabling analytics without decryption
- FF1 operates on arbitrary radix (base), supporting numeric (radix-10), alphanumeric (radix-36), and custom character sets
- FF1 requires no central lookup database, enabling vaultless tokenization
- Bouncy Castle (bcprov-jdk18on) provides a production-grade, FIPS-compatible FF1 implementation for Java
- Domain size enforcement (radix^length ≥ 1,000,000) prevents brute-force recovery attacks

## Consequences
- **Positive**: No vault database required, eliminating the central "honeypot" of sensitive data
- **Positive**: Linear horizontal scaling (CPU-bound, not I/O-bound)
- **Positive**: Regulatory acceptance under NIST standards
- **Negative**: Security entirely depends on key confidentiality — key compromise allows token reversal
- **Negative**: FPE is slower than random generation for very short inputs (< 6 characters)
- **Mitigation**: Keys stored in HSM (HashiCorp Vault), never in application memory beyond the operation lifetime
