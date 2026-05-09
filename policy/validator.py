from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Literal

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, model_validator

logger = logging.getLogger("shieldeye.policy")


class PolicyDocument(BaseModel):  # type: ignore[misc]
    """Pydantic v2 schema for a compliance policy document.

    Reuses scan template naming conventions (e.g. quick_gdpr, security_headers, cookie_privacy).
    """

    control_id: str
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"]
    description: str
    check: str
    remediation: str
    severity: Literal["critical", "high", "medium", "low"]
    timeout: int = 600  # Why 600s? Balances policy eval completeness vs UX

    @model_validator(mode="after")  # type: ignore[misc]
    def validate_control_id(self) -> "PolicyDocument":
        pattern = rf"^{re.escape(self.standard)}-\d+\.\d+(\.\d+)?$"
        if not re.match(pattern, self.control_id):
            raise ValueError(
                f"control_id '{self.control_id}' does not match expected pattern "
                f"{self.standard}-X.Y[.Z]. hint: use format CIS-4.1.3 for control IDs"
            )
        return self


def load_policy_yaml(path: str) -> PolicyDocument:
    file_path = Path(path)
    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Policy file not found: {path}. "
            "hint: ensure the YAML policy file exists and the path is correct"
        ) from None

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected YAML mapping at root, got {type(data).__name__}. "
            "hint: ensure the file contains a top-level key/value policy document"
        )

    return PolicyDocument(**data)


def validate_rego_stub(content: str) -> bool:
    has_package = "package" in content
    has_rule_or_default = "rule" in content or "default" in content
    has_allow = "allow" in content

    is_valid = has_package and has_rule_or_default and has_allow

    if not is_valid:
        missing = []
        if not has_package:
            missing.append("'package'")
        if not has_rule_or_default:
            missing.append("'rule' or 'default'")
        if not has_allow:
            missing.append("'allow'")
        logger.warning(
            "Rego stub appears incomplete: missing %s. "
            "hint: ensure 'package shieldeye.policy' is declared in Rego file",
            ", ".join(missing),
        )

    return is_valid


# Impact: Provides a secure, typed policy-as-code foundation with minimal OPA/Rego compatibility,
# enabling YAML-driven compliance controls for CIS, PCI-DSS, SOC2, and GDPR without adding
# heavy parser dependencies.
