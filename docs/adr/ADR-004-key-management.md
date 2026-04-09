# ADR-004: HashiCorp Vault for Key Management

## Status
Accepted

## Date
2026-04-08

## Context
The entire security model of vaultless tokenization depends on the confidentiality of cryptographic keys. Keys must be:
- Generated in a tamper-resistant environment
- Never exposed in plaintext to application code
- Rotatable without data loss
- Auditably accessed

## Decision
We chose **HashiCorp Vault** with a pluggable `KeyProvider` abstraction layer.

## Rationale
- HashiCorp Vault's Transit Secrets Engine performs cryptographic operations server-side — the plaintext key never leaves Vault
- Vault supports FIPS 140-2/140-3 compliant backends (HSM integration via PKCS#11)
- The `KeyProvider` interface allows swapping implementations (Vault in production, local AES in dev)
- Vault provides built-in key versioning, enabling key rotation while preserving old key access for re-tokenization
- Spring Vault (spring-vault-core) provides native Spring Boot integration

## Consequences
- **Positive**: Keys never in application memory beyond individual operation scope
- **Positive**: FIPS 140-3 compatible with HSM backend
- **Positive**: Pluggable interface allows local development without Vault dependency
- **Negative**: Vault is a critical infrastructure dependency; outage impacts tokenization
- **Mitigation**: Vault HA mode with automatic unsealing; circuit breaker prevents cascade failure
