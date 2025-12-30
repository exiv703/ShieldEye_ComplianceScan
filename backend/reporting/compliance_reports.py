from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from ..core.analysis import AnalysisResult, FindingDetail

logger = logging.getLogger("shieldeye.compliance")

@dataclass
class ComplianceSection:
    title: str
    status: str
    score: int
    requirements: List[Dict[str, Any]]
    findings: List[FindingDetail]
    recommendations: List[str]

@dataclass
class ExecutiveSummary:
    overall_status: str
    risk_level: str
    key_findings: List[str]
    critical_issues: int
    compliance_score: int
    recommendations: List[str]
    business_impact: str

class ComplianceReportGenerator:
    
    GDPR_REQUIREMENTS = {
        "data_protection": {
            "title": "Data Protection & Privacy",
            "checks": ["privacy_policy", "cookie_consent", "data_processing"],
            "weight": 0.3
        },
        "security_measures": {
            "title": "Technical Security Measures",
            "checks": ["ssl", "encryption", "secure_transmission"],
            "weight": 0.25
        },
        "user_rights": {
            "title": "User Rights & Consent",
            "checks": ["cookie_consent", "opt_out", "data_access"],
            "weight": 0.25
        },
        "transparency": {
            "title": "Transparency & Accountability",
            "checks": ["privacy_policy", "data_controller", "dpo_contact"],
            "weight": 0.2
        }
    }
    
    PCI_DSS_REQUIREMENTS = {
        "network_security": {
            "title": "Build and Maintain Secure Network",
            "checks": ["firewall", "encryption", "secure_protocols"],
            "weight": 0.2
        },
        "cardholder_data": {
            "title": "Protect Cardholder Data",
            "checks": ["encryption", "data_masking", "secure_storage"],
            "weight": 0.25
        },
        "vulnerability_management": {
            "title": "Maintain Vulnerability Management Program",
            "checks": ["security_updates", "antivirus", "secure_systems"],
            "weight": 0.2
        },
        "access_control": {
            "title": "Implement Strong Access Control",
            "checks": ["authentication", "authorization", "access_logs"],
            "weight": 0.2
        },
        "monitoring": {
            "title": "Monitor and Test Networks",
            "checks": ["logging", "monitoring", "testing"],
            "weight": 0.15
        }
    }
    
    ISO27001_REQUIREMENTS = {
        "information_security_policies": {
            "title": "Information Security Policies",
            "checks": ["security_policy", "review_process"],
            "weight": 0.15
        },
        "asset_management": {
            "title": "Asset Management",
            "checks": ["asset_inventory", "classification", "handling"],
            "weight": 0.15
        },
        "access_control": {
            "title": "Access Control",
            "checks": ["authentication", "authorization", "access_review"],
            "weight": 0.2
        },
        "cryptography": {
            "title": "Cryptography",
            "checks": ["encryption", "key_management", "ssl"],
            "weight": 0.2
        },
        "operations_security": {
            "title": "Operations Security",
            "checks": ["change_management", "capacity_management", "malware"],
            "weight": 0.15
        },
        "communications_security": {
            "title": "Communications Security",
            "checks": ["network_security", "secure_transmission", "segregation"],
            "weight": 0.15
        }
    }
    
    @staticmethod
    def generate_executive_summary(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        standards: List[str]
    ) -> ExecutiveSummary:
        
        critical_count = analysis.summary_counts.get('critical', 0)
        high_count = analysis.summary_counts.get('high', 0)
        
        if analysis.score >= 90:
            overall_status = "Excellent"
            risk_level = "Low"
        elif analysis.score >= 75:
            overall_status = "Good"
            risk_level = "Medium"
        elif analysis.score >= 60:
            overall_status = "Fair"
            risk_level = "Medium-High"
        else:
            overall_status = "Poor"
            risk_level = "High"
        
        key_findings = []
        for finding in analysis.findings[:5]:
            if finding.severity in ['critical', 'high']:
                key_findings.append(f"{finding.severity.upper()}: {finding.message}")
        
        recommendations = []
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical security issues immediately")
        if high_count > 0:
            recommendations.append(f"Resolve {high_count} high-severity findings within 30 days")
        if "GDPR" in standards and analysis.score < 80:
            recommendations.append("Improve GDPR compliance to avoid potential fines")
        if "PCI-DSS" in standards and analysis.score < 85:
            recommendations.append("Enhance PCI-DSS compliance before processing payments")
        
        if analysis.score < 60:
            business_impact = "HIGH RISK: Significant vulnerabilities pose serious business risks including data breaches, regulatory fines, and reputational damage."
        elif analysis.score < 75:
            business_impact = "MEDIUM RISK: Several security gaps exist that could lead to compliance violations and potential security incidents."
        else:
            business_impact = "LOW RISK: Security posture is generally good with minor improvements needed."
        
        return ExecutiveSummary(
            overall_status=overall_status,
            risk_level=risk_level,
            key_findings=key_findings,
            critical_issues=critical_count,
            compliance_score=analysis.score,
            recommendations=recommendations,
            business_impact=business_impact
        )
    
    @classmethod
    def analyze_compliance_section(
        cls,
        standard: str,
        section_key: str,
        section_config: Dict,
        findings: List[FindingDetail]
    ) -> ComplianceSection:
        
        section_findings = [
            f for f in findings
            if any(check in f.category.lower() if f.category else False 
                   for check in section_config["checks"])
        ]
        
        total_checks = len(section_config["checks"])
        failed_checks = len([f for f in section_findings if f.severity in ['critical', 'high']])
        section_score = max(0, int(100 * (1 - failed_checks / max(total_checks, 1))))
        
        if section_score >= 90:
            status = "compliant"
        elif section_score >= 70:
            status = "partial"
        else:
            status = "non-compliant"
        
        requirements = [
            {
                "check": check,
                "status": "pass" if not any(check in f.category.lower() if f.category else False 
                                           for f in section_findings if f.severity in ['critical', 'high'])
                         else "fail",
                "severity": next((f.severity for f in section_findings 
                                 if check in (f.category.lower() if f.category else "")), "pass")
            }
            for check in section_config["checks"]
        ]
        
        recommendations = []
        for finding in section_findings:
            if finding.severity in ['critical', 'high']:
                recommendations.append(f"Fix: {finding.message}")
        
        return ComplianceSection(
            title=section_config["title"],
            status=status,
            score=section_score,
            requirements=requirements,
            findings=section_findings,
            recommendations=recommendations[:5]
        )
    
    @classmethod
    def generate_compliance_report(
        cls,
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str,
        format: str = "html"
    ) -> None:
        
        output_path = Path(output_path)
        standards = scan_results.get('standards', [])
        
        exec_summary = cls.generate_executive_summary(scan_results, analysis, standards)
        
        compliance_sections = {}
        
        if "GDPR" in standards:
            compliance_sections["GDPR"] = {
                section_key: cls.analyze_compliance_section(
                    "GDPR", section_key, section_config, analysis.findings
                )
                for section_key, section_config in cls.GDPR_REQUIREMENTS.items()
            }
        
        if "PCI-DSS" in standards:
            compliance_sections["PCI-DSS"] = {
                section_key: cls.analyze_compliance_section(
                    "PCI-DSS", section_key, section_config, analysis.findings
                )
                for section_key, section_config in cls.PCI_DSS_REQUIREMENTS.items()
            }
        
        if "ISO 27001" in standards:
            compliance_sections["ISO 27001"] = {
                section_key: cls.analyze_compliance_section(
                    "ISO 27001", section_key, section_config, analysis.findings
                )
                for section_key, section_config in cls.ISO27001_REQUIREMENTS.items()
            }
        
        if format == "html":
            cls._generate_html_report(
                scan_results, analysis, exec_summary, compliance_sections, output_path
            )
        elif format == "markdown":
            cls._generate_markdown_report(
                scan_results, analysis, exec_summary, compliance_sections, output_path
            )
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Generated compliance report: {output_path}")
    
    @staticmethod
    def _generate_html_report(
        scan_results: Dict,
        analysis: AnalysisResult,
        exec_summary: ExecutiveSummary,
        compliance_sections: Dict,
        output_path: Path
    ) -> None:
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Compliance Report - {scan_results.get('start_url', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background:
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color:
        h2 {{ color:
        h3 {{ color:
        .executive-summary {{ background:
        .risk-high {{ color:
        .risk-medium {{ color:
        .risk-low {{ color:
        .score {{ font-size: 48px; font-weight: bold; color:
        .status-compliant {{ color:
        .status-partial {{ color:
        .status-non-compliant {{ color:
        .finding {{ background:
        .finding-critical {{ border-left-color:
        .finding-high {{ border-left-color:
        .finding-medium {{ border-left-color:
        .finding-low {{ border-left-color:
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid
        th {{ background:
        .metadata {{ color:
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Compliance Report</h1>
        <div class="metadata">
            <p><strong>URL:</strong> {scan_results.get('start_url', 'N/A')}</p>
            <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'N/A')}</p>
            <p><strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Standards:</strong> {', '.join(scan_results.get('standards', []))}</p>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Overall Status:</strong> {exec_summary.overall_status}</p>
            <p><strong>Risk Level:</strong> <span class="risk-{exec_summary.risk_level.lower().replace('-', '')}">{exec_summary.risk_level}</span></p>
            <p><strong>Compliance Score:</strong> <span class="score">{exec_summary.compliance_score}/100</span></p>
            <p><strong>Critical Issues:</strong> {exec_summary.critical_issues}</p>
            
            <h3>Business Impact</h3>
            <p>{exec_summary.business_impact}</p>
            
            <h3>Key Findings</h3>
            <ul>
                {''.join(f'<li>{finding}</li>' for finding in exec_summary.key_findings)}
            </ul>
            
            <h3>Recommendations</h3>
            <ol>
                {''.join(f'<li>{rec}</li>' for rec in exec_summary.recommendations)}
            </ol>
        </div>

        <h2>{standard} Compliance Analysis</h2>

        <h3>{section.title} - <span class="{status_class}">{section.status.upper()}</span> ({section.score}/100)</h3>
        
        <table>
            <tr>
                <th>Requirement</th>
                <th>Status</th>
                <th>Severity</th>
            </tr>

            <tr>
                <td>{req['check'].replace('_', ' ').title()}</td>
                <td>{status_icon} {req['status'].upper()}</td>
                <td>{req['severity'].upper()}</td>
            </tr>

        </table>

        <h4>Recommendations</h4>
        <ul>

        </ul>

        <h2>Detailed Findings</h2>

        <div class="finding {severity_class}">
            <strong>[{finding.severity.upper()}]</strong> {finding.message}
            {f'<br><small>Location: {finding.location}</small>' if finding.location else ''}
            {f'<br><small>Standards: {", ".join(finding.standards)}</small>' if finding.standards else ''}
        </div>

    </div>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    @staticmethod
    def _generate_markdown_report(
        scan_results: Dict,
        analysis: AnalysisResult,
        exec_summary: ExecutiveSummary,
        compliance_sections: Dict,
        output_path: Path
    ) -> None:
        
        lines = [
            "# Security Compliance Report",
            "",
            "## Metadata",
            "",
            f"- **URL**: {scan_results.get('start_url', 'N/A')}",
            f"- **Scan ID**: {scan_results.get('scan_id', 'N/A')}",
            f"- **Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Standards**: {', '.join(scan_results.get('standards', []))}",
            "",
            "## Executive Summary",
            "",
            f"**Overall Status**: {exec_summary.overall_status}",
            f"**Risk Level**: {exec_summary.risk_level}",
            f"**Compliance Score**: {exec_summary.compliance_score}/100",
            f"**Critical Issues**: {exec_summary.critical_issues}",
            "",
            "### Business Impact",
            "",
            exec_summary.business_impact,
            "",
            "### Key Findings",
            "",
        ]
        
        for finding in exec_summary.key_findings:
            lines.append(f"- {finding}")
        
        lines.extend([
            "",
            "### Recommendations",
            ""
        ])
        
        for i, rec in enumerate(exec_summary.recommendations, 1):
            lines.append(f"{i}. {rec}")
        
        for standard, sections in compliance_sections.items():
            lines.extend([
                "",
                f"## {standard} Compliance Analysis",
                ""
            ])
            
            for section_key, section in sections.items():
                lines.extend([
                    f"### {section.title} - {section.status.upper()} ({section.score}/100)",
                    "",
                    "| Requirement | Status | Severity |",
                    "|-------------|--------|----------|"
                ])
                
                for req in section.requirements:
                    status_icon = "✓" if req["status"] == "pass" else "✗"
                    lines.append(f"| {req['check'].replace('_', ' ').title()} | {status_icon} {req['status'].upper()} | {req['severity'].upper()} |")
                
                if section.recommendations:
                    lines.extend([
                        "",
                        "**Recommendations:**",
                        ""
                    ])
                    for rec in section.recommendations:
                        lines.append(f"- {rec}")
                
                lines.append("")
        
        lines.extend([
            "## Detailed Findings",
            ""
        ])
        
        for finding in analysis.findings:
            if finding.severity != 'pass':
                lines.append(f"### [{finding.severity.upper()}] {finding.message}")
                if finding.location:
                    lines.append(f"**Location**: `{finding.location}`")
                if finding.standards:
                    lines.append(f"**Standards**: {', '.join(finding.standards)}")
                lines.append("")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
