# Non-Functional Requirements — Data Tokenization Service

## NFR-001: Performance
- P99 tokenization latency SHALL be < 50ms under normal load
- P99 detokenization latency SHALL be < 50ms under normal load
- System SHALL support ≥ 10,000 tokenization operations per second with horizontal scaling

## NFR-002: Reliability
- System SHALL achieve 99.99% uptime SLA
- Circuit breakers (Resilience4j) SHALL prevent cascade failures between microservices
- All microservices SHALL implement health check endpoints at `/actuator/health`

## NFR-003: Security
- Cryptographic keys SHALL be stored in FIPS 140-3 Level 3 compatible Hardware Security Modules
- All data in transit SHALL be encrypted with TLS 1.3 minimum
- All data at rest SHALL be encrypted with AES-256
- Plaintext sensitive data SHALL NEVER appear in application logs
- OWASP Top 10 mitigations SHALL be applied to all HTTP endpoints
- mTLS SHALL be enforced for internal service-to-service communication

## NFR-004: Compliance
- The service architecture SHALL reduce PCI DSS compliance scope by removing PANs from downstream systems
- The service SHALL be compatible with HIPAA PHI handling requirements
- Audit logging SHALL satisfy SOX and GDPR audit trail requirements

## NFR-005: Scalability
- The system SHALL scale horizontally via container orchestration (Kubernetes-compatible)
- Tokenization engine SHALL be CPU-bound (not I/O-bound), enabling linear horizontal scaling
- Database connections SHALL use connection pooling (HikariCP)

## NFR-006: Observability
- All services SHALL emit structured JSON logs (no plaintext sensitive data)
- All services SHALL expose Prometheus metrics via `/actuator/prometheus`
- Distributed tracing SHALL be supported via OpenTelemetry
- Anomaly detection SHALL alert when a single user detokenizes > 100 records per minute

## NFR-007: GraalVM Native Image
- All Spring Boot modules SHALL be compatible with GraalVM Native Image compilation
- Native images SHALL achieve cold start times < 100ms
- Reflection hints and serialization configurations SHALL be provided where required
- Build SHALL produce both JVM JAR and native image artifacts

## NFR-008: Cryptographic Standards
- Tokenization SHALL use NIST SP 800-38G FF1 algorithm (Format-Preserving Encryption)
- Key size SHALL be 256-bit AES minimum
- Tweak inputs SHALL incorporate tenant ID and data type to ensure domain separation
- Random number generation SHALL use SecureRandom (DRBG-based)
