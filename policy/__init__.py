"""Policy-as-code parsing layer for ShieldEye ComplianceScan.

Provides Pydantic-validated policy document schemas, YAML loading,
and minimal OPA/Rego stub validation for CIS, PCI-DSS, SOC2, and GDPR controls.

Reuses scan template naming conventions (e.g. quick_gdpr, security_headers, cookie_privacy).
"""

from policy.validator import PolicyDocument, load_policy_yaml, validate_rego_stub

__all__ = ["PolicyDocument", "load_policy_yaml", "validate_rego_stub"]
