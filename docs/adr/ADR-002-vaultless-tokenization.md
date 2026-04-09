# ADR-002: Vaultless Tokenization Architecture

## Status
Accepted

## Date
2026-04-08

## Context
Tokenization architectures fall into two categories:
1. **Vaulted**: Generates random tokens, stores plaintext→token mapping in an encrypted database vault
2. **Vaultless**: Uses deterministic cryptographic algorithms (FPE) to generate tokens without storing mappings

## Decision
We chose **vaultless tokenization** using FF1 FPE.

## Rationale
- **No central honeypot**: A vaulted database containing all plaintext values is an extremely high-value attack target. Vaultless architecture eliminates this risk surface.
- **Distributed reconstruction authority**: Reversing a token requires simultaneously possessing the correct key, passing RBAC/ABAC policy checks, and having network access — no single compromise point enables mass data exfiltration
- **Operational simplicity**: No vault database to back up, replicate, or manage; infrastructure overhead is significantly reduced
- **Global scale**: CPU-bound operations scale linearly with compute; no I/O bottleneck from database reads
- **Near-instantaneous performance**: No database round-trip per tokenization operation

## Consequences
- **Positive**: Eliminates central data breach risk
- **Positive**: Simpler operational model
- **Positive**: Better performance and scalability
- **Negative**: "Moderate" vs "full" PCI DSS scope reduction (vaulted models can achieve slightly broader scope reduction in some interpretations)
- **Negative**: Key compromise is existential — entire security model depends on HSM integrity
- **Mitigation**: FIPS 140-3 Level 3 HSM (HashiCorp Vault with hardware backend) for all key operations
