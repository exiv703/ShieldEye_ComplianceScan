from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..core.scanner import Scanner
from ..reporting.reporter import Reporter
from ..core.analysis import analyze_results, AnalysisResult
from ..utils.config import get_config


logger = logging.getLogger("shieldeye.backend")


def run_scan(
    start_url: str,
    standards: Optional[List[str]] = None,
    mode: str = "Quick/Safe",
    *,
    max_pages: Optional[int] = None,
    max_depth: Optional[int] = None,
    timeout: int = 10,
    verify_ssl: Optional[bool] = None,
    user_agent: Optional[str] = None,
    logger_instance: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """Public backend entrypoint for running a scan."""

    if standards is None:
        standards = []

    if verify_ssl is None:
        verify_ssl = get_config().scanner.verify_ssl

    scan_logger = logger_instance or logger
    scan_logger.debug(
        "Starting scan",
        extra={
            "url": start_url,
            "mode": mode,
            "standards": standards,
            "max_pages": max_pages,
            "max_depth": max_depth,
            "timeout": timeout,
            "verify_ssl": verify_ssl,
        },
    )

    scanner = Scanner(
        start_url=start_url,
        standards=standards,
        mode=mode,
        max_pages=max_pages,
        max_depth=max_depth,
        timeout=timeout,
        verify_ssl=verify_ssl,
        user_agent=user_agent,
        logger_instance=scan_logger,
    )

    results = scanner.run_scan()
    return results


def generate_pdf_report(
    url: str,
    scan_results: Dict[str, Any],
    scan_duration: float,
    output_path: str,
) -> tuple[bool, Optional[str]]:
    """Generate PDF report and return (success, message)."""

    reporter = Reporter(url, scan_results, scan_duration)
    success, message = reporter.generate_pdf(output_path)
    if success:
        logger.info("Report generated", extra={"output_path": output_path})
    else:
        logger.warning(
            "Report generation failed",
            extra={"output_path": output_path, "reason": message},
        )
    return success, message


def analyze_scan_results(scan_results: Dict[str, Any]) -> AnalysisResult:
    return analyze_results(scan_results)
