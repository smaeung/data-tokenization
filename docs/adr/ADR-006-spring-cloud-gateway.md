# ADR-006: Spring Cloud Gateway as API Gateway

## Status
Accepted

## Date
2026-04-08

## Context
The system requires a centralized API gateway for:
- JWT and API key authentication
- Rate limiting
- Request routing to backend microservices
- Request/response transformation and logging

Options evaluated: Kong, AWS API Gateway, NGINX, Spring Cloud Gateway.

## Decision
We chose **Spring Cloud Gateway** (reactive, Spring Boot 3.x native).

## Rationale
- Native Spring ecosystem integration — same Spring Security, Spring Actuator, Micrometer stack
- Reactive (WebFlux) foundation handles high concurrency with low thread overhead
- Built-in filter chain architecture simplifies JWT validation, rate limiting, and logging filter implementation
- GraalVM Native Image compatible
- No additional infrastructure license costs

## Consequences
- **Positive**: Unified Spring ecosystem, shared security configuration
- **Positive**: Reactive performance, GraalVM-compatible
- **Negative**: Less feature-rich than Kong or AWS API Gateway out-of-the-box
- **Mitigation**: Custom filters implement all required capabilities within the filter chain
