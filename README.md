# Data Tokenization Service

Production-grade vaultless data tokenization API built with Spring Boot 3.x and GraalVM Native Image. Implements NIST SP 800-38G FF1 Format-Preserving Encryption (FPE) for PCI DSS and HIPAA compliance.

## Architecture Overview

```
[Client] ──JWT──► [API Gateway :8080]
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
    [Engine :8081] [Audit :8084] [UI :8085]
         │
    [Key Mgmt]  ──► [HashiCorp Vault]
    [Access Ctrl] ──► [OPA :8181]
         │
    [PostgreSQL :5432] [Redis :6379]
```

## Key Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Tokenization algorithm | FF1 FPE (NIST SP 800-38G) | NIST-approved, deterministic, format-preserving |
| Architecture | Vaultless | Eliminates central data honeypot |
| Policy engine | Open Policy Agent (OPA) | Externalized, auditable ABAC policies |
| Key management | HashiCorp Vault | FIPS 140-3 compatible, server-side crypto |
| Runtime | GraalVM Native Image | <100ms cold start, 50-80% less memory |
| Audit | Append-only PostgreSQL | Tamper-resistant compliance trail |

See `docs/adr/` for full Architecture Decision Records.

## Module Structure

| Module | Port | Purpose |
|--------|------|---------|
| `tokenization-api-gateway` | 8080 | JWT auth, rate limiting, routing |
| `tokenization-engine` | 8081 | FF1 FPE tokenize/detokenize |
| `tokenization-access-control` | 8083 | RBAC/ABAC + OPA policy engine |
| `tokenization-audit` | 8084 | Immutable audit log + anomaly detection |
| `tokenization-ui` | 8085 | Thymeleaf admin portal |
| `tokenization-key-management` | — | Key provider abstraction (library) |
| `tokenization-common` | — | Shared DTOs and exceptions (library) |

## Quick Start

### Prerequisites
- Java 21, Maven 3.9+
- Docker + Docker Compose (for full-stack mode)

---

### Option A — Dev mode (no Docker, local keys)

`LocalKeyProvider` generates in-memory AES-256 keys. No Vault, no PostgreSQL needed.

**1. Build all modules:**
```bash
mvn clean install -DskipTests -Dtokenization.key-provider=local
```

**2. Run a service** (pick one, or open separate terminals for each):
```bash
# Core tokenization engine (port 8081)
mvn spring-boot:run -pl tokenization-engine -am \
  -Dspring-boot.run.profiles=dev \
  -Dspring-boot.run.jvmArguments="-Dtokenization.key-provider=local"

# Access control / OPA (port 8083)
mvn spring-boot:run -pl tokenization-access-control -am \
  -Dspring-boot.run.profiles=dev \
  -Dspring-boot.run.jvmArguments="-Dtokenization.key-provider=local"

# Audit service (port 8084)
mvn spring-boot:run -pl tokenization-audit -am \
  -Dspring-boot.run.profiles=dev \
  -Dspring-boot.run.jvmArguments="-Dtokenization.key-provider=local"

# API Gateway (port 8080) — routes to the services above
mvn spring-boot:run -pl tokenization-api-gateway -am \
  -Dspring-boot.run.profiles=dev

# Admin UI (port 8085)
mvn spring-boot:run -pl tokenization-ui -am \
  -Dspring-boot.run.profiles=dev
```

> **Note:** Send all API requests to the gateway on port **8080** — it handles JWT auth and routes to the correct service.

---

### Option B — Full stack (with Docker)

**1. Start infrastructure** (PostgreSQL, Redis, Vault, OPA, Prometheus, Jaeger):
```bash
docker-compose up -d
```

**2. Build:**
```bash
mvn clean install -DskipTests
```

**3. Run services** (separate terminals):
```bash
mvn spring-boot:run -pl tokenization-engine -am -Dspring-boot.run.profiles=docker
mvn spring-boot:run -pl tokenization-access-control -am -Dspring-boot.run.profiles=docker
mvn spring-boot:run -pl tokenization-audit -am -Dspring-boot.run.profiles=docker
mvn spring-boot:run -pl tokenization-api-gateway -am -Dspring-boot.run.profiles=docker
mvn spring-boot:run -pl tokenization-ui -am -Dspring-boot.run.profiles=docker
```

---

### Option C — GraalVM Native Image

Builds a self-contained native binary with <100ms startup time.

```bash
# Build native image for the engine module (requires GraalVM 21+)
mvn -Pnative package -pl tokenization-engine -am \
  -DskipTests -Dtokenization.key-provider=local

# Run the native binary
./tokenization-engine/target/tokenization-engine \
  --tokenization.key-provider=local
```

## API Reference

### Tokenize
```bash
curl -X POST http://localhost:8080/api/v1/tokenize \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":"4532015112830366","dataType":"CREDIT_CARD","tenantId":"tenant-001"}'
```

### Detokenize (requires DETOKENIZER role)
```bash
curl -X POST http://localhost:8080/api/v1/detokenize \
  -H "Authorization: Bearer $DETOKENIZER_JWT" \
  -H "Content-Type: application/json" \
  -d '{"token":"4716234512839012","tokenId":"tok_abc123","tenantId":"tenant-001"}'
```

### Batch Tokenize
```bash
curl -X POST http://localhost:8080/api/v1/tokenize/batch \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"records":[{"data":"4532015112830366","dataType":"CREDIT_CARD"}],"tenantId":"tenant-001"}'
```

## Roles and Permissions

| Role | Tokenize | Detokenize PAN | Detokenize PHI | View Audit | Manage Keys |
|------|----------|----------------|----------------|------------|-------------|
| ADMIN | Yes | Yes | Yes | Yes | Yes |
| TOKENIZER | Yes | No | No | No | No |
| DETOKENIZER | No | Yes | No | No | No |
| AUDITOR | No | No | No | Yes | No |
| READ_ONLY | No | No | No | No | No |

## Security Design

- **Zero plaintext in logs**: Request bodies are never logged; audit records contain token IDs only
- **Vaultless**: No mapping database — the only way to reverse a token is with the correct key + RBAC authorization
- **FIPS 140-3**: Keys stored in HashiCorp Vault (HSM-backed in production)
- **FF1 domain enforcement**: Minimum domain size 1,000,000 (NIST SP 800-38G requirement)
- **Fail-closed**: OPA circuit breaker DENIES on unavailability
- **Anomaly detection**: Alerts on > 100 detokenizations per user per minute

## Testing

```bash
# Unit tests only
mvn test -Dtokenization.key-provider=local

# Unit + integration tests (requires Docker for Testcontainers PostgreSQL)
mvn verify -P integration-tests -Dtokenization.key-provider=local

# With JaCoCo coverage report
mvn verify -Dtokenization.key-provider=local
# Report at: target/site/jacoco/index.html
```

> **Why `-Dtokenization.key-provider=local`?** `LocalKeyProvider` is `@ConditionalOnProperty(havingValue="local")`. Without this flag the Spring context tries to wire `VaultKeyProvider`, which requires a live Vault instance.

## Compliance

| Regulation | How Satisfied |
|------------|--------------|
| PCI DSS Req 3 | PANs replaced with FF1 tokens in all downstream systems |
| PCI DSS Req 10 | Immutable append-only audit log for all data access |
| HIPAA §164.312(b) | Audit controls with tamper-resistant storage |
| GDPR Art. 5.1(c) | Data minimization — RBAC prevents unauthorized access |
| NIST SP 800-38G | FF1 algorithm with domain size >= 1,000,000 |
