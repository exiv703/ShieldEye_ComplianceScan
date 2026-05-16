from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from benchmark.engine import get_control_mapping
from benchmark.orchestrator import BenchmarkResult
from integrations.surfacescan_client import SurfaceFinding
from reporting.generator import (
    ComplianceReport,
    export_json_report,
    export_sarif_report,
    generate_remediation_snippet,
)


def test_generate_remediation_snippet() -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "auditd"})
    assert "auditd" in s and "# Requires elevated privileges" in s


def test_compliance_report_schema() -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="passed",
        output="ok",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h",
    )
    sf = SurfaceFinding(
        finding_id="f1",
        target_url="https://t.com",
        category="ssl",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3"],
        results=[br],
        correlated_findings=[sf],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 1},
        remediation_snippets={"CIS-4.1.3": s},
    )
    assert r.report_id == "r1"


def test_export_json_report(tmp_path: Path) -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="passed",
        output="ok",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h",
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3"],
        results=[br],
        correlated_findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 1},
        remediation_snippets={"CIS-4.1.3": s},
    )
    p = tmp_path / "report.json"
    export_json_report(r, str(p))
    d = json.loads(p.read_text())
    assert d["report_id"] == "r1" and "audit_metadata" in d


def test_export_json_report_oserror(tmp_path: Path) -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="passed",
        output="ok",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h",
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3"],
        results=[br],
        correlated_findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 1},
        remediation_snippets={"CIS-4.1.3": s},
    )
    with patch("reporting.generator.os.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            export_json_report(r, "/nonexistent/path/report.json")


def test_export_sarif_report(tmp_path: Path) -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="failed",
        output="err",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h",
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3"],
        results=[br],
        correlated_findings=[],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "passed": 0},
        remediation_snippets={"CIS-4.1.3": s},
    )
    p = tmp_path / "report.sarif"
    export_sarif_report(r, str(p))
    d = json.loads(p.read_text())
    assert d["version"] == "2.1.0" and len(d["runs"][0]["results"]) == 1


def test_export_sarif_report_omits_passed(tmp_path: Path) -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    passed_br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="passed",
        output="ok",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h1",
    )
    failed_br = BenchmarkResult(
        control_id="GDPR-32.1.1",
        target="https://t.com",
        status="failed",
        output="err",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h2",
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3", "GDPR-32.1.1"],
        results=[passed_br, failed_br],
        correlated_findings=[],
        summary={"critical": 0, "high": 1, "medium": 0, "low": 0, "passed": 1},
        remediation_snippets={"CIS-4.1.3": s, "GDPR-32.1.1": s},
    )
    p = tmp_path / "report.sarif"
    export_sarif_report(r, str(p))
    d = json.loads(p.read_text())
    assert len(d["runs"][0]["results"]) == 1


def test_export_sarif_report_oserror(tmp_path: Path) -> None:
    m = get_control_mapping("CIS-4.1.3")
    s = generate_remediation_snippet(m, {"package": "x"})
    br = BenchmarkResult(
        control_id="CIS-4.1.3",
        target="https://t.com",
        status="failed",
        output="err",
        duration_ms=10,
        timestamp=datetime.now(timezone.utc),
        idempotency_hash="h",
    )
    r = ComplianceReport(
        report_id="r1",
        target="https://t.com",
        timestamp=datetime.now(timezone.utc),
        controls_tested=["CIS-4.1.3"],
        results=[br],
        correlated_findings=[],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "passed": 0},
        remediation_snippets={"CIS-4.1.3": s},
    )
    with patch("reporting.generator.os.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            export_sarif_report(r, str(tmp_path / "report.sarif"))


def test_generate_remediation_snippet_complex_hint() -> None:
    m = get_control_mapping("CIS-5.2.1")
    s = generate_remediation_snippet(m, {})
    assert "# Fix for" in s
