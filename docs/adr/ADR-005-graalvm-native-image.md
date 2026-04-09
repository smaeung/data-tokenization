# ADR-005: GraalVM Native Image for Production Deployment

## Status
Accepted

## Date
2026-04-08

## Context
Traditional JVM-based Spring Boot applications have:
- Slow cold start times (5–20 seconds) unsuitable for serverless/auto-scaling scenarios
- High memory footprint per instance
- Dependency on JDK runtime in containers

GraalVM Native Image ahead-of-time (AOT) compilation addresses these issues.

## Decision
All Spring Boot modules SHALL be compiled as **GraalVM Native Images** for production deployment.

## Rationale
- Cold start time < 100ms enables true auto-scaling and serverless deployment
- Reduced memory footprint (50–80% lower vs JVM) reduces infrastructure cost
- Spring Boot 3.x has first-class GraalVM Native Image support via spring-boot-buildpacks and native-maven-plugin
- Smaller container images improve security posture (smaller attack surface)
- No JVM required in production containers (distroless base images)

## Implementation
- `native-maven-plugin` added to each module's pom.xml
- `@RegisterReflectionForBinding` and `RuntimeHintsRegistrar` used where reflection is needed
- GraalVM reachability metadata provided for Bouncy Castle and Spring Vault
- Build profile: `-P native` for native compilation, default profile for JVM JAR
- Docker multi-stage build: GraalVM builder → distroless runtime image

## Consequences
- **Positive**: Sub-100ms cold start, lower memory, smaller containers
- **Positive**: No JVM in production (smaller attack surface)
- **Negative**: Longer build times (AOT compilation is slow)
- **Negative**: Dynamic features (reflection, proxies) require explicit configuration
- **Mitigation**: CI uses JVM builds for fast test feedback; native builds only on release pipeline
