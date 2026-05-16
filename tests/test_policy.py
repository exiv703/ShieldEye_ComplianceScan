from __future__ import annotations

from pathlib import Path

import pytest
from policy.validator import PolicyDocument, load_policy_yaml, validate_rego_stub


def test_policy_document_valid_cis() -> None:
    doc = PolicyDocument(
        control_id="CIS-4.1.3",
        standard="CIS",
        description="x",
        check="y",
        remediation="z",
        severity="high",
    )
    assert doc.control_id == "CIS-4.1.3"


def test_policy_document_valid_pci() -> None:
    doc = PolicyDocument(
        control_id="PCI-DSS-3.2.1",
        standard="PCI-DSS",
        description="x",
        check="y",
        remediation="z",
        severity="high",
    )
    assert doc.control_id == "PCI-DSS-3.2.1"


def test_policy_document_invalid_control_id() -> None:
    with pytest.raises(ValueError, match="does not match expected pattern"):
        PolicyDocument(
            control_id="bad",
            standard="CIS",
            description="x",
            check="y",
            remediation="z",
            severity="high",
        )


def test_load_policy_yaml_valid(tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text(
        "control_id: CIS-1.1.1\nstandard: CIS\ndescription: d\ncheck: c\nremediation: r\nseverity: medium\n"
    )
    doc = load_policy_yaml(str(f))
    assert doc.control_id == "CIS-1.1.1"


def test_load_policy_yaml_missing() -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        load_policy_yaml("/tmp/nonexistent.yaml")


def test_load_policy_yaml_invalid_root(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("- not a dict")
    with pytest.raises(ValueError, match="Expected YAML mapping"):
        load_policy_yaml(str(f))


def test_validate_rego_stub_valid() -> None:
    assert validate_rego_stub("package main\nrule x {}\nallow") is True


def test_validate_rego_stub_invalid() -> None:
    assert validate_rego_stub("foo") is False
