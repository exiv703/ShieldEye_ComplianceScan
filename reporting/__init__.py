"""ShieldEye ComplianceScan reporting layer.

Generates human-readable remediation guides and machine-readable compliance
reports (JSON/SARIF) from policy mappings and benchmark execution results.
"""

from reporting.generator import (
    ComplianceReport,
    export_json_report,
    export_sarif_report,
    generate_remediation_snippet,
)

__all__ = [
    "ComplianceReport",
    "generate_remediation_snippet",
    "export_json_report",
    "export_sarif_report",
]
