# ADR-003: Open Policy Agent (OPA) for ABAC Policy Engine

## Status
Accepted

## Date
2026-04-08

## Context
The system requires fine-grained access control beyond simple RBAC. For example:
- A DETOKENIZER role may be allowed to detokenize credit cards but not PHI
- A user may have detokenize permission only during business hours
- Certain tenants may have stricter access controls than others

This requires Attribute-Based Access Control (ABAC). Options evaluated:
1. **Spring Security @PreAuthorize expressions**: Tightly coupled to application code
2. **Apache Casbin**: Embedded policy engine, policies defined in model files
3. **Open Policy Agent (OPA)**: Externalized policy engine with Rego policy language

## Decision
We chose **Open Policy Agent (OPA)** deployed as a sidecar.

## Rationale
- OPA policies (Rego) are externalized, auditable, and version-controlled separately from application code
- OPA supports context-aware decisions: time of day, source IP, tenant attributes, data classification
- OPA integrates naturally with Kubernetes and service mesh environments
- OPA decisions are logged separately, providing a compliance-friendly audit trail of policy evaluations
- Policy changes do not require application redeployment

## Consequences
- **Positive**: Externalized, auditable, independently deployable policy engine
- **Positive**: Rich context-aware access decisions
- **Negative**: Additional infrastructure component (OPA sidecar per service)
- **Negative**: Rego language has a learning curve
- **Mitigation**: Local OPA evaluation via REST API (HTTP to sidecar at port 8181); fallback to local RBAC if OPA is unavailable
