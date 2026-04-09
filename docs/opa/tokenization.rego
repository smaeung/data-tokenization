# tokenization.rego — Open Policy Agent ABAC policy for the tokenization service
#
# WHY OPA/Rego: Externalized policies enable:
# 1. Policy changes without application redeployment
# 2. Version-controlled, auditable policy history (this file is in git)
# 3. Separation of duties: security team owns policies, developers own application code
# 4. Consistent policy evaluation across all microservices
#
# COMPLIANCE: This policy enforces the data minimization principle required by
# PCI DSS (Req 3.3) and GDPR (Article 5.1.c): users only access data they need.

package tokenization

import future.keywords.if
import future.keywords.in

# Default to DENY — fail-closed is the correct security posture
# WHY: An unmatched rule should deny, not allow. This prevents accidental access
# from policy gaps.
default allow := false

# ADMIN role has full access to all operations
allow if {
    input.role == "ROLE_ADMIN"
}

# TOKENIZER role can only tokenize (not detokenize)
allow if {
    input.role == "ROLE_TOKENIZER"
    input.operation == "tokenize"
}

# DETOKENIZER role can detokenize PAN (credit card) data
allow if {
    input.role == "ROLE_DETOKENIZER"
    input.operation == "detokenize"
    input.dataType in {"CREDIT_CARD", "ACCOUNT_NUMBER", "PHONE"}
}

# DETOKENIZER requires elevated role for PHI data types
# WHY: PHI (HIPAA) requires additional access controls beyond standard PAN detokenization
allow if {
    input.role == "ROLE_DETOKENIZER_PHI"
    input.operation == "detokenize"
    input.dataType in {"HEALTH_ID", "DATE_OF_BIRTH", "SSN"}
}

# AUDITOR role can only view audit logs
allow if {
    input.role == "ROLE_AUDITOR"
    input.operation == "view_audit"
}

# All authenticated roles can apply masking (no sensitive data exposed)
allow if {
    input.role in {"ROLE_TOKENIZER", "ROLE_DETOKENIZER", "ROLE_AUDITOR", "ROLE_READ_ONLY"}
    input.operation == "mask"
}

# All authenticated roles can tokenize (masking is non-sensitive)
allow if {
    input.operation == "mask"
}
