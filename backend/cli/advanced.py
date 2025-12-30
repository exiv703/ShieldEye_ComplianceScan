from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from ..core.backend import run_scan, generate_pdf_report
from ..core.analysis import analyze_results
from ..storage.database import ScanDatabase
from ..integrations.comparison import ScanComparator
from ..utils.config import get_config, AppConfig
from ..utils.logging_config import setup_logging, get_logger
from ..utils.monitoring import get_health_checker
from ..integrations.scheduler import get_scheduler, ScheduleFrequency
from ..integrations.webhooks import get_webhook_manager, WebhookEvent

logger = get_logger("cli")

def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ShieldEye ComplianceScan - Production CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan https://example.com
  
  %(prog)s scan https://example.com -s GDPR -s PCI-DSS --mode full
  
  %(prog)s scan https://example.com --save-db
  
  %(prog)s compare SCAN_ID_1 SCAN_ID_2
  
  %(prog)s health
  
  %(prog)s history --limit 10
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("url", help="Target URL to scan")
    scan_parser.add_argument(
        "--standard", "-s",
        action="append",
        choices=["GDPR", "PCI-DSS", "ISO 27001"],
        help="Compliance standard to audit"
    )
    scan_parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="quick",
        help="Scan mode"
    )
    scan_parser.add_argument("--max-pages", type=int, help="Maximum pages to scan")
    scan_parser.add_argument("--max-depth", type=int, help="Maximum crawl depth")
    scan_parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    scan_parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    scan_parser.add_argument("--output-json", metavar="PATH", help="Save results as JSON")
    scan_parser.add_argument("--pdf", metavar="PATH", help="Generate PDF report")
    scan_parser.add_argument("--save-db", action="store_true", help="Save to database")
    scan_parser.add_argument("--no-rate-limit", action="store_true", help="Disable rate limiting")
    
    compare_parser = subparsers.add_parser("compare", help="Compare two scans")
    compare_parser.add_argument("baseline_id", help="Baseline scan ID")
    compare_parser.add_argument("current_id", help="Current scan ID")
    compare_parser.add_argument("--output", help="Save comparison report to file")
    
    history_parser = subparsers.add_parser("history", help="View scan history")
    history_parser.add_argument("--limit", type=int, default=20, help="Number of scans to show")
    history_parser.add_argument("--url", help="Filter by URL")
    history_parser.add_argument("--status", help="Filter by status")
    
    subparsers.add_parser("health", help="Check system health")
    
    stats_parser = subparsers.add_parser("stats", help="Show database statistics")
    
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--db-path", help="Database path")
    
    return parser.parse_args(argv)

def cmd_scan(args: argparse.Namespace, config: AppConfig) -> int:
    mode_str = "Aggressive/Full" if args.mode == "full" else "Quick/Safe"
    standards = args.standard or []
    
    logger.info(f"Starting scan for {args.url}")
    
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
        logger.exception("Scan failed")
        print(f"ERROR: Scan failed: {exc}", file=sys.stderr)
        return 1
    
    duration = time.time() - start_ts
    scan_id = results.get("scan_id", "unknown")
    
    analysis = analyze_results(results)
    summary = analysis.summary_counts
    
    print(f"\nScan completed in {duration:.2f} seconds")
    print(f"Scan ID: {scan_id}")
    print(f"Score: {analysis.score}/100")
    print(f"Findings: critical={summary['critical']}, high={summary['high']}, "
          f"medium={summary['medium']}, low={summary['low']}")
    
    if args.save_db:
        db_path = Path(args.db_path) if args.db_path else config.database.db_path
        db = ScanDatabase(db_path)
        
        db.create_scan(scan_id, args.url, mode_str, standards)
        db.update_scan(
            scan_id,
            status="completed",
            duration=duration,
            score=analysis.score,
            counts=summary,
            pages_scanned=len(results.get("pages", {})),
            results=results
        )
        
        for finding in analysis.findings:
            if finding.severity != "pass":
                db.add_finding(
                    scan_id,
                    finding.severity,
                    finding.message,
                    finding.category,
                    finding.location,
                    finding.standards
                )
        
        print(f"Saved to database: {db_path}")
    
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON saved to: {args.output_json}")
    
    if args.pdf:
        success, message = generate_pdf_report(args.url, results, duration, args.pdf)
        if success:
            print(f"PDF report saved to: {args.pdf}")
        else:
            print(f"WARNING: PDF generation failed: {message}", file=sys.stderr)
    
    return 0

def cmd_compare(args: argparse.Namespace, config: AppConfig) -> int:
    db_path = Path(args.db_path) if args.db_path else config.database.db_path
    db = ScanDatabase(db_path)
    
    baseline_scan = db.get_scan(args.baseline_id)
    current_scan = db.get_scan(args.current_id)
    
    if not baseline_scan:
        print(f"ERROR: Baseline scan not found: {args.baseline_id}", file=sys.stderr)
        return 1
    
    if not current_scan:
        print(f"ERROR: Current scan not found: {args.current_id}", file=sys.stderr)
        return 1
    
    baseline_results = json.loads(baseline_scan["results_json"])
    current_results = json.loads(current_scan["results_json"])
    
    baseline_analysis = analyze_results(baseline_results)
    current_analysis = analyze_results(current_results)
    
    comparator = ScanComparator()
    comparison = comparator.compare_scans(
        baseline_results,
        current_results,
        baseline_analysis,
        current_analysis
    )
    
    report = comparator.generate_comparison_report(comparison)
    print(report)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\nComparison saved to: {args.output}")
    
    return 0

def cmd_history(args: argparse.Namespace, config: AppConfig) -> int:
    db_path = Path(args.db_path) if args.db_path else config.database.db_path
    db = ScanDatabase(db_path)
    
    scans = db.get_scans(
        limit=args.limit,
        url=args.url,
        status=args.status
    )
    
    if not scans:
        print("No scans found")
        return 0
    
    print(f"\n{'Scan ID':<40} {'URL':<30} {'Status':<12} {'Score':<6} {'Date'}")
    print("=" * 120)
    
    for scan in scans:
        scan_id = scan["scan_id"][:36]
        url = scan["url"][:28] + ".." if len(scan["url"]) > 30 else scan["url"]
        status = scan["status"]
        score = scan["score"] if scan["score"] is not None else "N/A"
        date = scan["start_time"][:19]
        
        print(f"{scan_id:<40} {url:<30} {status:<12} {score:<6} {date}")
    
    return 0

def cmd_health(args: argparse.Namespace, config: AppConfig) -> int:
    checker = get_health_checker()
    health = checker.perform_health_check()
    
    print("\n" + "=" * 70)
    print("SYSTEM HEALTH CHECK")
    print("=" * 70)
    print(f"\nStatus: {health.status.upper()}")
    print(f"Overall Health: {'✓ HEALTHY' if health.healthy else '✗ UNHEALTHY'}")
    
    print("\nChecks:")
    for check_name, passed in health.checks.items():
        status = "✓" if passed else "✗"
        print(f"  {status} {check_name}")
    
    print("\nMetrics:")
    for metric_name, value in health.metrics.items():
        if isinstance(value, float):
            print(f"  {metric_name}: {value:.2f}")
        else:
            print(f"  {metric_name}: {value}")
    
    return 0 if health.healthy else 1

def cmd_stats(args: argparse.Namespace, config: AppConfig) -> int:
    db_path = Path(args.db_path) if args.db_path else config.database.db_path
    db = ScanDatabase(db_path)
    
    stats = db.get_statistics()
    
    print("\n" + "=" * 70)
    print("DATABASE STATISTICS")
    print("=" * 70)
    print(f"\nTotal Scans: {stats['total_scans']}")
    print(f"Completed: {stats['completed_scans']}")
    print(f"Failed: {stats['failed_scans']}")
    print(f"Average Score: {stats['average_score']:.1f}/100")
    print(f"Total Critical Findings: {stats['total_critical_findings']}")
    print(f"Total High Findings: {stats['total_high_findings']}")
    
    return 0

def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    
    args = _parse_args(argv)
    
    if not args.command:
        print("ERROR: No command specified. Use --help for usage.", file=sys.stderr)
        return 1
    
    config = get_config()
    
    log_level = "DEBUG" if args.verbose else config.logging.level
    setup_logging(
        level=getattr(__import__("logging"), log_level),
        log_file=str(config.logging.log_dir / "shieldeye.log") if config.logging.log_dir else None,
        structured=config.logging.structured
    )
    
    if args.command == "scan":
        return cmd_scan(args, config)
    elif args.command == "compare":
        return cmd_compare(args, config)
    elif args.command == "history":
        return cmd_history(args, config)
    elif args.command == "health":
        return cmd_health(args, config)
    elif args.command == "stats":
        return cmd_stats(args, config)
    else:
        print(f"ERROR: Unknown command: {args.command}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
