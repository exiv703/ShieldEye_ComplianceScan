from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import List

from ..core.backend import run_scan, generate_pdf_report
from ..core.analysis import analyze_results

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ShieldEye ComplianceScan - command line interface",
    )

    parser.add_argument(
        "url",
        help="Target URL to scan (e.g. https://example.com)",
    )

    parser.add_argument(
        "--standard",
        "-s",
        action="append",
        choices=["GDPR", "PCI-DSS", "ISO 27001"],
        help=(
            "Compliance standard to audit. "
            "Can be specified multiple times, e.g. -s GDPR -s 'PCI-DSS'."
        ),
    )

    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="quick",
        help="Scan mode: 'quick' (default) or 'full' (more pages, deeper crawl)",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Override maximum number of pages to scan.",
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Override maximum crawl depth.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for HTTP requests (default: 10)",
    )

    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates during HTTP requests.",
    )

    parser.add_argument(
        "--output-json",
        metavar="PATH",
        help="Write raw scan results as JSON to the given file.",
    )

    parser.add_argument(
        "--pdf",
        metavar="PATH",
        help="Generate a PDF report and save it to the given path.",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level).",
    )

    return parser.parse_args(argv)

def main(argv: List[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    args = _parse_args(argv)

    _configure_logging(args.verbose)
    logger = logging.getLogger("shieldeye.cli")

    mode_str = "Aggressive/Full" if args.mode == "full" else "Quick/Safe"
    standards = args.standard or []

    logger.info(
        "Starting scan",
        extra={
            "url": args.url,
            "mode": mode_str,
            "standards": standards,
            "max_pages": args.max_pages,
            "max_depth": args.max_depth,
            "timeout": args.timeout,
            "verify_ssl": args.verify_ssl,
        },
    )

    start_ts = time.time()
    try:
        results = run_scan(
            start_url=args.url,
            standards=standards,
            mode=mode_str,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
        )
    except Exception as exc:
        logger.exception("Scan failed with an unexpected error")
        print(f"ERROR: scan failed: {exc}", file=sys.stderr)
        return 1

    duration = time.time() - start_ts
    pages = results.get("pages", {})
    scanned_pages = [p for p in pages.keys() if p != "domain_findings"]

    print(f"Scan completed in {duration:.2f} seconds.")
    print(f"Pages scanned: {len(scanned_pages)}")

    analysis_result = analyze_results(results)
    summary = analysis_result.summary_counts
    print(
        "Findings summary - "
        f"critical: {summary.get('critical', 0)}, "
        f"high: {summary.get('high', 0)}, "
        f"medium: {summary.get('medium', 0)}, "
        f"low: {summary.get('low', 0)}, "
        f"score: {analysis_result.score}/100"
    )

    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "url": args.url,
                        "mode": mode_str,
                        "standards": standards,
                        "duration": duration,
                        "results": results,
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
            print(f"JSON results written to {args.output_json}")
        except OSError as exc:
            logger.error("Failed to write JSON output", exc_info=True)
            print(f"WARNING: could not write JSON output: {exc}", file=sys.stderr)

    if args.pdf:
        success, message = generate_pdf_report(args.url, results, duration, args.pdf)
        if success:
            print(f"PDF report written to {args.pdf}")
        else:
            print(f"WARNING: could not generate PDF report: {message}", file=sys.stderr)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
