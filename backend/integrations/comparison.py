from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime, timezone

from ..core.analysis import FindingDetail, AnalysisResult
from ..utils.logging_config import get_logger

logger = get_logger("comparison")

@dataclass
class FindingDiff:
    
    change_type: str
    severity: str
    message: str
    category: Optional[str] = None
    location: Optional[str] = None
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None

@dataclass
class ScanComparison:
    
    baseline_scan_id: str
    current_scan_id: str
    baseline_url: str
    current_url: str
    baseline_date: str
    current_date: str
    
    new_findings: List[FindingDetail] = field(default_factory=list)
    resolved_findings: List[FindingDetail] = field(default_factory=list)
    unchanged_findings: List[FindingDetail] = field(default_factory=list)
    
    score_change: int = 0
    baseline_score: int = 0
    current_score: int = 0
    
    severity_changes: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    improved: bool = False
    degraded: bool = False
    
    summary: str = ""

class ScanComparator:
    
    def __init__(self):
        pass
    
    def compare_scans(
        self,
        baseline_results: Dict[str, Any],
        current_results: Dict[str, Any],
        baseline_analysis: AnalysisResult,
        current_analysis: AnalysisResult,
    ) -> ScanComparison:

        baseline_findings_set = {
            self._finding_key(f) for f in baseline_analysis.findings
            if f.severity != "pass"
        }
        current_findings_set = {
            self._finding_key(f) for f in current_analysis.findings
            if f.severity != "pass"
        }
        
        new_findings = [
            f for f in current_analysis.findings
            if self._finding_key(f) not in baseline_findings_set and f.severity != "pass"
        ]
        
        resolved_findings = [
            f for f in baseline_analysis.findings
            if self._finding_key(f) not in current_findings_set and f.severity != "pass"
        ]
        
        unchanged_findings = [
            f for f in current_analysis.findings
            if self._finding_key(f) in baseline_findings_set and f.severity != "pass"
        ]
        
        score_change = current_analysis.score - baseline_analysis.score
        
        severity_changes = self._calculate_severity_changes(
            baseline_analysis.summary_counts,
            current_analysis.summary_counts
        )
        
        if score_change > 5:
            improved = True
            degraded = False
        elif score_change < -5:
            improved = False
            degraded = True
        elif score_change > 0:
            improved = True
            degraded = False
        elif score_change < 0:
            improved = False
            degraded = True
        else:
            if len(resolved_findings) > len(new_findings):
                improved = True
                degraded = False
            elif len(new_findings) > len(resolved_findings):
                improved = False
                degraded = True
            else:
                improved = False
                degraded = False
        
        summary = self._generate_summary(
            len(new_findings),
            len(resolved_findings),
            score_change,
            improved,
            degraded
        )
        
        comparison = ScanComparison(
            baseline_scan_id=baseline_results.get("scan_id", "unknown"),
            current_scan_id=current_results.get("scan_id", "unknown"),
            baseline_url=baseline_results.get("start_url", ""),
            current_url=current_results.get("start_url", ""),
            baseline_date=baseline_results.get("timestamp", datetime.now(timezone.utc).isoformat()),
            current_date=current_results.get("timestamp", datetime.now(timezone.utc).isoformat()),
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
            score_change=score_change,
            baseline_score=baseline_analysis.score,
            current_score=current_analysis.score,
            severity_changes=severity_changes,
            improved=improved,
            degraded=degraded,
            summary=summary,
        )
        
        logger.info(
            f"Scan comparison completed: {len(new_findings)} new, "
            f"{len(resolved_findings)} resolved, score change: {score_change:+d}"
        )
        
        return comparison
    
    def _finding_key(self, finding: FindingDetail) -> str:
        return f"{finding.severity}:{finding.category}:{finding.message}"
    
    def _calculate_severity_changes(
        self,
        baseline_counts: Dict[str, int],
        current_counts: Dict[str, int]
    ) -> Dict[str, Dict[str, int]]:
        changes = {}
        
        for severity in ["critical", "high", "medium", "low"]:
            baseline = baseline_counts.get(severity, 0)
            current = current_counts.get(severity, 0)
            change = current - baseline
            
            changes[severity] = {
                "baseline": baseline,
                "current": current,
                "change": change,
            }
        
        return changes
    
    def _generate_summary(
        self,
        new_count: int,
        resolved_count: int,
        score_change: int,
        improved: bool,
        degraded: bool
    ) -> str:
        if improved and not degraded:
            status = "improved"
        elif degraded and not improved:
            status = "degraded"
        elif new_count == 0 and resolved_count == 0:
            status = "unchanged"
        else:
            status = "mixed"
        
        summary = f"Security posture has {status}. "
        
        if new_count > 0:
            summary += f"{new_count} new issue(s) found. "
        
        if resolved_count > 0:
            summary += f"{resolved_count} issue(s) resolved. "
        
        if score_change != 0:
            direction = "increased" if score_change > 0 else "decreased"
            summary += f"Score {direction} by {abs(score_change)} points."
        
        return summary.strip()
    
    def generate_comparison_report(self, comparison: ScanComparison) -> str:
        report = []
        report.append("=" * 70)
        report.append("SCAN COMPARISON REPORT")
        report.append("=" * 70)
        report.append("")
        
        report.append(f"Baseline Scan: {comparison.baseline_scan_id}")
        report.append(f"  URL: {comparison.baseline_url}")
        report.append(f"  Date: {comparison.baseline_date}")
        report.append(f"  Score: {comparison.baseline_score}/100")
        report.append("")
        
        report.append(f"Current Scan: {comparison.current_scan_id}")
        report.append(f"  URL: {comparison.current_url}")
        report.append(f"  Date: {comparison.current_date}")
        report.append(f"  Score: {comparison.current_score}/100")
        report.append("")
        
        report.append(f"Score Change: {comparison.score_change:+d} points")
        report.append("")
        
        report.append("SUMMARY")
        report.append("-" * 70)
        report.append(comparison.summary)
        report.append("")
        
        if comparison.new_findings:
            report.append("NEW ISSUES")
            report.append("-" * 70)
            for finding in comparison.new_findings:
                report.append(f"  [{finding.severity.upper()}] {finding.message}")
                if finding.location:
                    report.append(f"    Location: {finding.location}")
            report.append("")
        
        if comparison.resolved_findings:
            report.append("RESOLVED ISSUES")
            report.append("-" * 70)
            for finding in comparison.resolved_findings:
                report.append(f"  [{finding.severity.upper()}] {finding.message}")
                if finding.location:
                    report.append(f"    Location: {finding.location}")
            report.append("")
        
        report.append("SEVERITY CHANGES")
        report.append("-" * 70)
        for severity, data in comparison.severity_changes.items():
            change = data["change"]
            sign = "+" if change > 0 else ""
            report.append(
                f"  {severity.capitalize()}: {data['baseline']} → {data['current']} "
                f"({sign}{change})"
            )
        report.append("")
        
        report.append("=" * 70)
        
        return "\n".join(report)

def compare_scan_results(
    baseline_results: Dict[str, Any],
    current_results: Dict[str, Any],
    baseline_analysis: AnalysisResult,
    current_analysis: AnalysisResult,
) -> ScanComparison:
    comparator = ScanComparator()
    return comparator.compare_scans(
        baseline_results,
        current_results,
        baseline_analysis,
        current_analysis
    )
