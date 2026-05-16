from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from integrations.core_client import CoreClient, CoreScanResult
from integrations.surfacescan_client import SurfaceFinding, SurfaceScanClient


def test_core_validate_blocks_localhost() -> None:
    with pytest.raises(ValueError, match="Localhost"):
        CoreClient._validate_base_url("http://localhost", allow_internal=False)


def test_core_validate_blocks_private_ip() -> None:
    with pytest.raises(ValueError, match="private"):
        CoreClient._validate_base_url("http://192.168.1.1", allow_internal=False)


def test_core_validate_allows_public() -> None:
    assert (
        CoreClient._validate_base_url("example.com", allow_internal=False)
        == "https://example.com"
    )


def test_correlate_ssl_to_cis() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f = SurfaceFinding(
        finding_id="f1",
        target_url="https://t.com",
        category="ssl",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    assert c.correlate_to_control(f, "CIS-4.1.3") is True


def test_correlate_privacy_to_gdpr() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f = SurfaceFinding(
        finding_id="f2",
        target_url="https://t.com",
        category="privacy",
        severity="medium",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    assert c.correlate_to_control(f, "GDPR-32.1.1") is True


def test_correlate_mismatch() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f = SurfaceFinding(
        finding_id="f3",
        target_url="https://t.com",
        category="ssl",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    assert c.correlate_to_control(f, "GDPR-32.1.1") is False


def test_core_get_scan_results_mocked() -> None:
    client = CoreClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "scan_id": "s1",
        "target_url": "https://t.com",
        "findings": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    }
    with patch.object(client.session, "get", return_value=resp):
        r = client.get_scan_results("s1")
        assert r is not None and r.scan_id == "s1"


def test_core_get_scan_results_404() -> None:
    client = CoreClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 404
    with patch.object(client.session, "get", return_value=resp):
        assert client.get_scan_results("s1") is None


def test_core_get_scan_results_timeout() -> None:
    import requests  # type: ignore[import-untyped]

    client = CoreClient("https://api.example.com", api_key="k")
    with patch.object(client.session, "get", side_effect=requests.Timeout):
        assert client.get_scan_results("s1") is None


def test_core_get_scan_results_invalid_json() -> None:
    client = CoreClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError
    with patch.object(client.session, "get", return_value=resp):
        assert client.get_scan_results("s1") is None


def test_core_list_recent_scans() -> None:
    client = CoreClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = [
        {
            "scan_id": "s1",
            "target_url": "https://t.com",
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {},
            "status": "completed",
        }
    ]
    with patch.object(client.session, "get", return_value=resp):
        scans = client.list_recent_scans(limit=10)
        assert len(scans) == 1 and scans[0].scan_id == "s1"


def test_surface_get_findings_mocked() -> None:
    client = SurfaceScanClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = [
        {
            "finding_id": "f1",
            "target_url": "https://t.com",
            "category": "ssl",
            "severity": "high",
            "description": "d",
            "remediation_hint": "h",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ]
    with patch.object(client.session, "get", return_value=resp):
        findings = client.get_findings("https://t.com")
        assert len(findings) == 1 and findings[0].finding_id == "f1"


def test_surface_get_findings_404() -> None:
    client = SurfaceScanClient("https://api.example.com", api_key="k")
    resp = MagicMock()
    resp.status_code = 404
    with patch.object(client.session, "get", return_value=resp):
        assert client.get_findings("https://t.com") == []


def test_surface_get_findings_timeout() -> None:
    import requests

    client = SurfaceScanClient("https://api.example.com", api_key="k")
    with patch.object(client.session, "get", side_effect=requests.Timeout):
        assert client.get_findings("https://t.com") == []


def test_surface_correlate_findings_to_control() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f1 = SurfaceFinding(
        finding_id="f1",
        target_url="https://t.com",
        category="ssl",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    f2 = SurfaceFinding(
        finding_id="f2",
        target_url="https://t.com",
        category="privacy",
        severity="medium",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    correlated = c.correlate_findings_to_control([f1, f2], "CIS-4.1.3")
    assert len(correlated) == 1 and correlated[0].finding_id == "f1"


def test_surface_correlate_headers_to_cis() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f = SurfaceFinding(
        finding_id="f1",
        target_url="https://t.com",
        category="headers",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    assert c.correlate_to_control(f, "CIS-5.2.1") is True


def test_surface_correlate_tracking_to_gdpr() -> None:
    c = SurfaceScanClient("https://local", allow_internal=True)
    f = SurfaceFinding(
        finding_id="f1",
        target_url="https://t.com",
        category="tracking",
        severity="high",
        description="d",
        remediation_hint="h",
        timestamp=datetime.now(timezone.utc),
    )
    assert c.correlate_to_control(f, "GDPR-32.1.1") is True
