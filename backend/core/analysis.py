from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

FindingTuple = Tuple[str, str]

logger = logging.getLogger("shieldeye.analysis")

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "pass": 4,
}

@dataclass
class FindingDetail:

    severity: str
    message: str
    category: str | None = None
    standards: List[str] | None = None
    location: str | None = None
    code: str | None = None

@dataclass
class AnalysisResult:
    findings: List[FindingDetail]
    summary_counts: Dict[str, int]
    score: int

def _normalize_finding(raw: Any) -> FindingTuple | None:

    if not isinstance(raw, tuple) or len(raw) < 2:
        return None
    severity, message = raw[0], raw[1]
    return str(severity), str(message)

def _infer_standards_for_category(category: str, all_standards: List[str]) -> List[str]:

    category_lower = category.lower()
    mapped: List[str] = []

    if category_lower == "privacy" and "GDPR" in all_standards:
        mapped.append("GDPR")
    if category_lower == "pci" and "PCI-DSS" in all_standards:
        mapped.append("PCI-DSS")
    if category_lower == "iso" and "ISO 27001" in all_standards:
        mapped.append("ISO 27001")

    if not mapped and all_standards:
        mapped = list(all_standards)

    return mapped

def _collect_all_findings(results: Dict[str, Any]) -> List[FindingDetail]:
    pages_results = results.get("pages", {}) or {}
    domain_findings = pages_results.get("domain_findings", {}) or {}
    all_standards: List[str] = results.get("standards", []) or []
    start_url: str | None = results.get("start_url")

    collected: List[FindingDetail] = []

    for category_name, category_items in domain_findings.items():
        if not category_items:
            continue
        for raw in category_items:
            normalized = _normalize_finding(raw)
            if normalized is None:
                continue
            severity, message = normalized
            collected.append(
                FindingDetail(
                    severity=severity,
                    message=message,
                    category=category_name,
                    standards=_infer_standards_for_category(category_name, all_standards),
                    location=start_url,
                )
            )

    for url, page_data in pages_results.items():
        if url == "domain_findings":
            continue
        if not isinstance(page_data, dict):
            continue
        for category_name, category in page_data.items():
            if not isinstance(category, dict):
                continue
            items = category.get("findings", []) or []
            for raw in items:
                normalized = _normalize_finding(raw)
                if normalized is None:
                    continue
                severity, message = normalized
                collected.append(
                    FindingDetail(
                        severity=severity,
                        message=message,
                        category=category_name,
                        standards=_infer_standards_for_category(category_name, all_standards),
                        location=url,
                    )
                )

    return collected

def _deduplicate_findings(findings: List[FindingDetail]) -> List[FindingDetail]:

    seen_messages = set()
    unique: List[FindingDetail] = []
    for finding in findings:
        if finding.message in seen_messages:
            continue
        seen_messages.add(finding.message)
        unique.append(finding)
    return unique

def _sort_findings(findings: List[FindingDetail]) -> List[FindingDetail]:
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 99),
    )

def _calculate_summary_counts(findings: List[FindingDetail]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev_key = finding.severity.lower()
        if sev_key in summary and sev_key != "pass":
            summary[sev_key] += 1
    return summary

def _calculate_score(
    summary_counts: Dict[str, int], 
    severity_weights: Dict[str, int] | None = None,
    pages_scanned: int = 1
) -> int:

    weights = severity_weights or {
        "critical": 20,
        "high": 10,
        "medium": 5,
        "low": 2,
    }

    penalty = 0
    for sev, count in summary_counts.items():
        weight = weights.get(sev, 0)
        penalty += count * weight
    
    import math
    normalization_factor = max(1.0, math.sqrt(max(1, pages_scanned)))
    normalized_penalty = penalty / normalization_factor
    
    score = 100 - normalized_penalty
    return max(0, min(100, int(score)))

def analyze_results(
    results: Dict[str, Any], severity_weights: Dict[str, int] | None = None
) -> AnalysisResult:

    all_findings = _collect_all_findings(results)
    if not all_findings:
        logger.info("No findings present in results")

    unique_findings = _deduplicate_findings(all_findings)
    sorted_findings = _sort_findings(unique_findings)
    summary_counts = _calculate_summary_counts(sorted_findings)
    
    metrics = results.get("metrics") or {}
    pages_scanned = metrics.get("pages_scanned", 1) if isinstance(metrics, dict) else 1
    score = _calculate_score(summary_counts, severity_weights, pages_scanned)

    return AnalysisResult(
        findings=sorted_findings,
        summary_counts=summary_counts,
        score=score,
    )
