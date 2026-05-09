from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from backend.utils.logging_config import get_logger
from benchmark.engine import ControlMapping, get_control_mapping
from benchmark.orchestrator import BenchmarkResult
from integrations.surfacescan_client import SurfaceFinding

logger = get_logger("reporting.generator")

# Reuse secret redaction patterns from benchmark/orchestrator.py
_SECRET_REDACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S+"
    ),
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
]


def _scrub_output(text: str) -> str:
    """Redact likely secrets from command output before persistence."""
    for pattern in _SECRET_REDACTION_PATTERNS:
        text = pattern.sub("***REDACTED***", text)
    return text


_SHIELD_EYE_VERSION = "0.1.0"
_GENERATOR_VERSION = "1.0.0"


class ComplianceReport(BaseModel):  # type: ignore[misc]
    """Pydantic v2 schema unifying orchestrator results and integration findings."""

    report_id: str
    target: str
    timestamp: datetime
    controls_tested: list[str]
    results: list[BenchmarkResult]
    correlated_findings: list[SurfaceFinding] = Field(default_factory=list)
    summary: dict[str, int]
    remediation_snippets: dict[str, str]


def _is_complex_command(command: str) -> bool:
    """Determine if a remediation command is complex enough to warrant a hint."""
    return any(op in command for op in ("&&", "||", "|", ";", "\n"))


def generate_remediation_snippet(
    mapping: ControlMapping, context: dict[str, str]
) -> str:
    """Render a copy-paste ready remediation command from a mapping template.

    Replaces ``{variable}`` placeholders in *remediation_template* with values
    from *context*, prepends a safety comment when elevated privileges are
    required, and adds an operational hint for complex commands.
    """
    # Why copy-paste ready? Operators need actionable fixes, not just 'FAIL'
    scrubbed_context = {k: _scrub_output(v) for k, v in context.items()}

    raw_command = mapping.remediation_template
    for key, value in scrubbed_context.items():
        raw_command = raw_command.replace(f"{{{key}}}", value)

    lines: list[str] = []
    if _is_complex_command(raw_command):
        hint = (
            f"# Why this command? Applies the security fix for {mapping.control_id} "
            f"({mapping.standard} {mapping.section})"
        )
        lines.append(hint)

    if "sudo" in raw_command:
        lines.append("# Requires elevated privileges")

    lines.append(raw_command)
    return "\n".join(lines)


def _atomic_write_json(data: dict[str, Any], output_path: str) -> None:
    """Write JSON data atomically using a temporary file + rename."""
    output_path_resolved = Path(output_path).resolve()
    dir_name = output_path_resolved.parent
    dir_name.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        dir=str(dir_name),
        delete=False,
        suffix=".tmp",
    ) as f:
        json.dump(data, f, indent=2)
        temp_path = f.name
    os.replace(temp_path, str(output_path_resolved))


def export_json_report(report: ComplianceReport, output_path: str) -> None:
    """Export a ComplianceReport to a JSON file with audit metadata.

    Serializes the report, injects audit metadata, and writes atomically.
    Secrets are redacted from any user-provided context before inclusion.
    """
    # Pydantic v2: model_dump(mode="json") provides a JSON-serializable dict.
    # Secret redaction is handled upstream via _scrub_output.
    data = report.model_dump(mode="json")

    feature_flags_snapshot = {
        "ENABLE_REMEDIATION_SNIPPETS": os.getenv(
            "ENABLE_REMEDIATION_SNIPPETS", "true"
        ).lower()
        == "true",
    }

    data["audit_metadata"] = {
        "generator_version": _GENERATOR_VERSION,
        "shield_eye_version": _SHIELD_EYE_VERSION,
        "feature_flags_snapshot": feature_flags_snapshot,
    }

    logger.info(
        "Generated %d remediation snippets for target %s",
        len(report.remediation_snippets),
        report.target,
    )

    try:
        _atomic_write_json(data, output_path)
        logger.info("JSON report exported to %s", output_path)
    except OSError:
        logger.warning(
            "Failed to export report to %s. hint: check file permissions or disk space",
            output_path,
        )
        raise


def _status_to_sarif_level(status: str, severity: str | None) -> str:
    """Map BenchmarkResult status to SARIF v2.1.0 result level."""
    if status == "passed":
        return "none"
    if status == "skipped":
        return "note"
    if status in ("failed", "error"):
        if severity in ("critical", "high"):
            return "error"
        return "warning"
    return "warning"


def export_sarif_report(report: ComplianceReport, output_path: str) -> None:
    """Export a ComplianceReport to a minimal SARIF v2.1.0 JSON file.

    Dict-based JSON assembly — no template rendering required.
    If jinja2 is not available, this path is already used.
    """
    # Why SARIF? Enables import into GRC platforms like ServiceNow, Drata
    results: list[dict[str, Any]] = []
    for benchmark_result in report.results:
        severity: str | None = None
        mapping = get_control_mapping(benchmark_result.control_id)
        if mapping is not None:
            severity = mapping.severity

        level = _status_to_sarif_level(benchmark_result.status, severity)
        if level == "none":
            continue  # SARIF typically omits passed checks

        snippet = report.remediation_snippets.get(benchmark_result.control_id, "")
        help_text = ""
        if snippet:
            help_text = f"Remediation:\n{snippet}"

        sarif_result: dict[str, Any] = {
            "ruleId": benchmark_result.control_id,
            "level": level,
            "message": {
                "text": f"Control {benchmark_result.control_id}: {benchmark_result.status}"
            },
        }
        if help_text:
            sarif_result["help"] = {"text": help_text}

        results.append(sarif_result)

    sarif_doc: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShieldEye ComplianceScan",
                        "version": _SHIELD_EYE_VERSION,
                    }
                },
                "results": results,
            }
        ],
    }

    try:
        _atomic_write_json(sarif_doc, output_path)
    except OSError:
        logger.warning(
            "Failed to export report to %s. hint: check file permissions or disk space",
            output_path,
        )
        raise


# Impact: Provides a unified reporting layer that bridges benchmark execution results
# into actionable, copy-paste ready remediation guides and machine-readable SARIF/JSON
# outputs for GRC automation, with secret redaction, atomic writes, and operational hints.
