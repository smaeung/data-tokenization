## Summary
<!-- Describe what this PR changes and why -->

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security fix
- [ ] Refactoring
- [ ] Documentation

## Security Checklist
- [ ] No sensitive data (PAN, SSN, keys) in logs
- [ ] No new SQL queries with string concatenation (use parameterized queries)
- [ ] RBAC/ABAC checked for any new endpoints
- [ ] Audit events published for any new data operations
- [ ] Dependencies scanned (OWASP check passes)

## Test Coverage
- [ ] Unit tests added/updated
- [ ] Integration tests pass (`mvn verify -P integration-tests`)
- [ ] JaCoCo coverage >= 80% for modified modules

## Compliance
- [ ] No plaintext PII in code, comments, or test fixtures
- [ ] Audit trail verified in integration tests
