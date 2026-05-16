from __future__ import annotations

import logging
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from benchmark.engine import get_control_mapping, render_remediation
from benchmark.orchestrator import (
    BenchmarkResult,
    _compute_idempotency_hash,
    _is_transient_error,
    is_execution_idempotent,
)


def test_get_control_mapping_cis() -> None:
    m = get_control_mapping("CIS-4.1.3")
    assert m is not None and m.standard == "CIS"


def test_get_control_mapping_gdpr() -> None:
    m = get_control_mapping("GDPR-32.1.1")
    assert m is not None and m.standard == "GDPR"


def test_get_control_mapping_unknown(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        assert get_control_mapping("UNKNOWN-1.1.1") is None
    assert "No mapping found" in caplog.text


def test_render_remediation_substitutes() -> None:
    m = get_control_mapping("GDPR-32.2.1")
    assert (
        render_remediation(m, {"domain": "ex.com"})
        == "# Add HSTS header in web server configuration for ex.com"
    )


def test_render_remediation_sudo() -> None:
    m = get_control_mapping("CIS-4.1.3")
    result = render_remediation(m, {"package": "nginx"})
    assert result == "# Requires elevated privileges\nsudo systemctl enable --now nginx"


def test_is_transient_error() -> None:
    assert _is_transient_error(TimeoutError("timeout")) is True
    assert _is_transient_error(ValueError("bad")) is False


def test_compute_idempotency_hash() -> None:
    h = _compute_idempotency_hash("CIS-1.1.1", "https://t.com", 60)
    assert isinstance(h, str) and len(h) == 64


def test_is_execution_idempotent() -> None:
    with (
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase") as db,
    ):
        cfg.return_value.database.db_path = ":memory:"
        db.return_value._get_connection.return_value.__enter__.return_value.cursor.return_value.fetchone.return_value = (
            None
        )
        assert is_execution_idempotent("CIS-1.1.1", "https://t.com") is False


def test_scrub_output() -> None:
    from benchmark.orchestrator import _scrub_output

    assert _scrub_output("password=secret123") == "***REDACTED***"


def test_is_execution_idempotent_cached() -> None:
    with (
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase") as db,
    ):
        cfg.return_value.database.db_path = ":memory:"
        db.return_value._get_connection.return_value.__enter__.return_value.cursor.return_value.fetchone.return_value = {
            "value": "passed"
        }
        assert is_execution_idempotent("CIS-1.1.1", "https://t.com") is True


def test_get_cached_result_none() -> None:
    with (
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase") as db,
    ):
        cfg.return_value.database.db_path = ":memory:"
        db.return_value._get_connection.return_value.__enter__.return_value.cursor.return_value.fetchone.return_value = (
            None
        )
        from benchmark.orchestrator import _get_cached_result

        assert _get_cached_result("hash123") is None


def test_get_cached_result_valid() -> None:
    with (
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase") as db,
    ):
        cfg.return_value.database.db_path = ":memory:"
        br = BenchmarkResult(
            control_id="CIS-1.1.1",
            target="https://t.com",
            status="passed",
            output="ok",
            duration_ms=10,
            timestamp=datetime.now(timezone.utc),
            idempotency_hash="h",
        )
        db.return_value._get_connection.return_value.__enter__.return_value.cursor.return_value.fetchone.return_value = {
            "value": br.model_dump_json()
        }
        from benchmark.orchestrator import _get_cached_result

        result = _get_cached_result("hash123")
        assert result is not None and result.control_id == "CIS-1.1.1"


def test_store_benchmark_result() -> None:
    with (
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase") as db,
    ):
        cfg.return_value.database.db_path = ":memory:"
        conn = db.return_value._get_connection.return_value.__enter__.return_value
        from benchmark.orchestrator import _store_benchmark_result

        br = BenchmarkResult(
            control_id="CIS-1.1.1",
            target="https://t.com",
            status="passed",
            output="ok",
            duration_ms=10,
            timestamp=datetime.now(timezone.utc),
            idempotency_hash="h",
        )
        _store_benchmark_result(br)
        assert conn.cursor.return_value.execute.call_count == 2


def test_execute_benchmark_passed() -> None:
    import asyncio
    from unittest.mock import AsyncMock
    from benchmark.orchestrator import execute_benchmark

    m = get_control_mapping("CIS-4.1.3")
    with (
        patch("benchmark.orchestrator.is_execution_idempotent", return_value=False),
        patch(
            "benchmark.orchestrator._run_check_with_timeout", new_callable=AsyncMock
        ) as mock_run,
        patch("benchmark.orchestrator._store_benchmark_result"),
        patch("benchmark.orchestrator.get_metrics_collector"),
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase"),
    ):
        cfg.return_value.database.db_path = ":memory:"
        mock_run.return_value = (0, "active", "")
        result = asyncio.run(execute_benchmark(m, "https://t.com"))
        assert result.status == "passed"


def test_execute_benchmark_timeout() -> None:
    import asyncio
    from unittest.mock import AsyncMock
    from benchmark.orchestrator import execute_benchmark

    m = get_control_mapping("CIS-4.1.3")
    with (
        patch("benchmark.orchestrator.is_execution_idempotent", return_value=False),
        patch(
            "benchmark.orchestrator._run_check_with_timeout", new_callable=AsyncMock
        ) as mock_run,
        patch("benchmark.orchestrator._store_benchmark_result"),
        patch("benchmark.orchestrator.get_metrics_collector"),
        patch("benchmark.orchestrator.get_config") as cfg,
        patch("benchmark.orchestrator.ScanDatabase"),
    ):
        cfg.return_value.database.db_path = ":memory:"
        mock_run.side_effect = asyncio.TimeoutError()
        result = asyncio.run(execute_benchmark(m, "https://t.com"))
        assert result.status == "error"
