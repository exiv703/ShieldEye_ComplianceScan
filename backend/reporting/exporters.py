from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from ..core.analysis import AnalysisResult, FindingDetail
from ..core.exceptions import ReportGenerationError

logger = logging.getLogger("shieldeye.exporters")

class ExportManager:
    
    @staticmethod
    def export_to_csv(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str
    ) -> None:
        try:
            output_path = Path(output_path)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                writer.writerow(['ShieldEye ComplianceScan - Scan Results'])
                writer.writerow([])
                writer.writerow(['Scan ID', scan_results.get('scan_id', 'N/A')])
                writer.writerow(['URL', scan_results.get('start_url', 'N/A')])
                writer.writerow(['Standards', ', '.join(scan_results.get('standards', []))])
                writer.writerow(['Mode', scan_results.get('mode', 'N/A')])
                writer.writerow(['Score', f"{analysis.score}/100"])
                writer.writerow([])
                
                writer.writerow(['Summary'])
                writer.writerow(['Severity', 'Count'])
                for severity, count in analysis.summary_counts.items():
                    writer.writerow([severity.capitalize(), count])
                writer.writerow([])
                
                writer.writerow(['Findings'])
                writer.writerow(['Severity', 'Category', 'Message', 'Location', 'Standards'])
                
                for finding in analysis.findings:
                    if finding.severity != 'pass':
                        writer.writerow([
                            finding.severity.upper(),
                            finding.category or 'N/A',
                            finding.message,
                            finding.location or 'N/A',
                            ', '.join(finding.standards) if finding.standards else 'N/A'
                        ])
            
            logger.info(f"Exported scan to CSV: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to export CSV: {e}")
    
    @staticmethod
    def export_to_xml(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str
    ) -> None:
        try:
            output_path = Path(output_path)
            
            root = ET.Element('scan')
            root.set('version', '1.0')
            root.set('timestamp', datetime.utcnow().isoformat())
            
            metadata = ET.SubElement(root, 'metadata')
            ET.SubElement(metadata, 'scan_id').text = scan_results.get('scan_id', 'N/A')
            ET.SubElement(metadata, 'url').text = scan_results.get('start_url', 'N/A')
            ET.SubElement(metadata, 'mode').text = scan_results.get('mode', 'N/A')
            ET.SubElement(metadata, 'score').text = str(analysis.score)
            
            standards_elem = ET.SubElement(metadata, 'standards')
            for standard in scan_results.get('standards', []):
                ET.SubElement(standards_elem, 'standard').text = standard
            
            summary = ET.SubElement(root, 'summary')
            for severity, count in analysis.summary_counts.items():
                severity_elem = ET.SubElement(summary, 'severity')
                severity_elem.set('type', severity)
                severity_elem.text = str(count)
            
            findings = ET.SubElement(root, 'findings')
            for finding in analysis.findings:
                if finding.severity != 'pass':
                    finding_elem = ET.SubElement(findings, 'finding')
                    finding_elem.set('severity', finding.severity)
                    
                    ET.SubElement(finding_elem, 'category').text = finding.category or 'N/A'
                    ET.SubElement(finding_elem, 'message').text = finding.message
                    ET.SubElement(finding_elem, 'location').text = finding.location or 'N/A'
                    
                    if finding.standards:
                        standards_elem = ET.SubElement(finding_elem, 'standards')
                        for standard in finding.standards:
                            ET.SubElement(standards_elem, 'standard').text = standard
            
            tree = ET.ElementTree(root)
            ET.indent(tree, space='  ')
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Exported scan to XML: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to export XML: {e}")
    
    @staticmethod
    def export_to_sarif(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str
    ) -> None:
        try:
            output_path = Path(output_path)
            
            sarif = {
                "version": "2.1.0",
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "ShieldEye ComplianceScan",
                                "version": "1.0.0",
                                "informationUri": "https://github.com/yourusername/shieldeye",
                                "rules": []
                            }
                        },
                        "results": [],
                        "properties": {
                            "scan_id": scan_results.get('scan_id', 'N/A'),
                            "url": scan_results.get('start_url', 'N/A'),
                            "mode": scan_results.get('mode', 'N/A'),
                            "standards": scan_results.get('standards', []),
                            "score": analysis.score
                        }
                    }
                ]
            }
            
            severity_map = {
                'critical': 'error',
                'high': 'error',
                'medium': 'warning',
                'low': 'note',
                'info': 'note'
            }
            
            rules_added = set()
            
            for finding in analysis.findings:
                if finding.severity == 'pass':
                    continue
                
                rule_id = f"{finding.category or 'general'}_{finding.severity}"
                
                if rule_id not in rules_added:
                    sarif["runs"][0]["tool"]["driver"]["rules"].append({
                        "id": rule_id,
                        "name": finding.category or "General",
                        "shortDescription": {
                            "text": f"{finding.category or 'General'} - {finding.severity.upper()}"
                        },
                        "fullDescription": {
                            "text": finding.message
                        },
                        "defaultConfiguration": {
                            "level": severity_map.get(finding.severity, 'warning')
                        },
                        "properties": {
                            "tags": finding.standards if finding.standards else []
                        }
                    })
                    rules_added.add(rule_id)
                
                result = {
                    "ruleId": rule_id,
                    "level": severity_map.get(finding.severity, 'warning'),
                    "message": {
                        "text": finding.message
                    },
                    "locations": []
                }
                
                if finding.location:
                    result["locations"].append({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location
                            }
                        }
                    })
                
                if finding.standards:
                    result["properties"] = {
                        "standards": finding.standards
                    }
                
                sarif["runs"][0]["results"].append(result)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif, f, indent=2)
            
            logger.info(f"Exported scan to SARIF: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to export SARIF: {e}")
    
    @staticmethod
    def export_to_json(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str,
        pretty: bool = True
    ) -> None:
        try:
            output_path = Path(output_path)
            
            export_data = {
                "metadata": {
                    "scan_id": scan_results.get('scan_id', 'N/A'),
                    "url": scan_results.get('start_url', 'N/A'),
                    "mode": scan_results.get('mode', 'N/A'),
                    "standards": scan_results.get('standards', []),
                    "timestamp": datetime.utcnow().isoformat()
                },
                "score": analysis.score,
                "summary": analysis.summary_counts,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "message": f.message,
                        "location": f.location,
                        "standards": f.standards
                    }
                    for f in analysis.findings if f.severity != 'pass'
                ],
                "raw_results": scan_results
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(export_data, f, indent=2, default=str)
                else:
                    json.dump(export_data, f, default=str)
            
            logger.info(f"Exported scan to JSON: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to export JSON: {e}")
    
    @staticmethod
    def export_to_markdown(
        scan_results: Dict[str, Any],
        analysis: AnalysisResult,
        output_path: Path | str
    ) -> None:
        try:
            output_path = Path(output_path)
            
            lines = [
                "# ShieldEye ComplianceScan - Scan Report",
                "",
                "## Metadata",
                "",
                f"- **Scan ID**: {scan_results.get('scan_id', 'N/A')}",
                f"- **URL**: {scan_results.get('start_url', 'N/A')}",
                f"- **Mode**: {scan_results.get('mode', 'N/A')}",
                f"- **Standards**: {', '.join(scan_results.get('standards', []))}",
                f"- **Score**: {analysis.score}/100",
                f"- **Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "",
                "## Summary",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]
            
            for severity, count in analysis.summary_counts.items():
                lines.append(f"| {severity.capitalize()} | {count} |")
            
            lines.extend([
                "",
                "## Findings",
                ""
            ])
            
            for severity in ['critical', 'high', 'medium', 'low']:
                findings_of_severity = [f for f in analysis.findings if f.severity == severity]
                if findings_of_severity:
                    lines.append(f"### {severity.upper()} Severity")
                    lines.append("")
                    
                    for finding in findings_of_severity:
                        lines.append(f"#### {finding.category or 'General'}")
                        lines.append("")
                        lines.append(f"**Message**: {finding.message}")
                        if finding.location:
                            lines.append(f"**Location**: `{finding.location}`")
                        if finding.standards:
                            lines.append(f"**Standards**: {', '.join(finding.standards)}")
                        lines.append("")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            logger.info(f"Exported scan to Markdown: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to export Markdown: {e}")

def export_scan(
    scan_results: Dict[str, Any],
    analysis: AnalysisResult,
    output_path: Path | str,
    format: str = 'json'
) -> None:

    exporter = ExportManager()
    
    format = format.lower()
    if format == 'json':
        exporter.export_to_json(scan_results, analysis, output_path)
    elif format == 'csv':
        exporter.export_to_csv(scan_results, analysis, output_path)
    elif format == 'xml':
        exporter.export_to_xml(scan_results, analysis, output_path)
    elif format == 'sarif':
        exporter.export_to_sarif(scan_results, analysis, output_path)
    elif format == 'markdown' or format == 'md':
        exporter.export_to_markdown(scan_results, analysis, output_path)
    else:
        raise ReportGenerationError(f"Unsupported export format: {format}")
