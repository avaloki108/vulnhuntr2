"""
SARIF export and GitHub Advanced Security integration for vulnhuntr2 Phase 5.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import json

from ..core.models import Finding, Severity
from ..core.version import VERSION


class SarifExporter:
    """
    SARIF (Static Analysis Results Interchange Format) exporter.
    Compatible with GitHub Advanced Security code scanning.
    """
    
    def __init__(self, tool_name: str = "vulnhuntr2"):
        self.tool_name = tool_name
        self.tool_version = VERSION
    
    def export_findings(self, findings: List[Finding], output_path: Path, run_metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Export findings to SARIF format.
        
        Args:
            findings: List of findings to export
            output_path: Path to write SARIF file
            run_metadata: Additional metadata about the run
        """
        sarif_document = self._create_sarif_document(findings, run_metadata or {})
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(sarif_document, f, indent=2)
    
    def _create_sarif_document(self, findings: List[Finding], run_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create complete SARIF document."""
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                self._create_run(findings, run_metadata)
            ]
        }
    
    def _create_run(self, findings: List[Finding], run_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create SARIF run object."""
        return {
            "tool": self._create_tool_object(),
            "results": [self._create_result(finding) for finding in findings],
            "artifacts": self._create_artifacts(findings),
            "invocation": self._create_invocation(run_metadata),
            "properties": {
                "vulnhuntr2_metadata": run_metadata
            }
        }
    
    def _create_tool_object(self) -> Dict[str, Any]:
        """Create SARIF tool object."""
        return {
            "driver": {
                "name": self.tool_name,
                "version": self.tool_version,
                "informationUri": "https://github.com/avaloki108/vulnhuntr2",
                "semanticVersion": self.tool_version,
                "rules": self._create_rules_metadata()
            }
        }
    
    def _create_rules_metadata(self) -> List[Dict[str, Any]]:
        """Create metadata for vulnerability detection rules."""
        # This would be populated with actual detector metadata
        # For now, return basic structure
        return [
            {
                "id": "VH001",
                "name": "smart-contract-vulnerability",
                "shortDescription": {
                    "text": "Smart Contract Vulnerability"
                },
                "fullDescription": {
                    "text": "Detects various types of smart contract vulnerabilities including reentrancy, oracle manipulation, and access control issues."
                },
                "help": {
                    "text": "Review the identified vulnerability and implement appropriate security measures."
                },
                "properties": {
                    "category": "security",
                    "precision": "medium",
                    "problem.severity": "warning",
                    "tags": ["security", "smart-contracts", "vulnerability"]
                }
            }
        ]
    
    def _create_result(self, finding: Finding) -> Dict[str, Any]:
        """Create SARIF result object for a finding."""
        return {
            "ruleId": self._get_rule_id(finding),
            "ruleIndex": 0,  # Would map to actual rule index
            "message": {
                "text": finding.title,
                "markdown": self._create_markdown_message(finding)
            },
            "level": self._map_severity_to_level(finding.severity),
            "locations": [
                self._create_location(finding)
            ],
            "properties": {
                "detector": finding.detector,
                "category": finding.category,
                "confidence": finding.confidence,
                "severity": finding.severity.name,
                "cwe_id": finding.cwe_id,
                "function_name": finding.function_name,
                "contract_name": finding.contract_name,
                "remediation": finding.remediation,
                "references": finding.references,
                "tags": list(finding.tags)
            },
            "fingerprints": {
                "vulnhuntr2/detector": finding.detector,
                "vulnhuntr2/location": f"{finding.file}:{finding.line}"
            }
        }
    
    def _create_location(self, finding: Finding) -> Dict[str, Any]:
        """Create SARIF location object."""
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": finding.line,
                    "startColumn": 1
                }
            }
        }
        
        # Add end line if available
        if finding.end_line:
            location["physicalLocation"]["region"]["endLine"] = finding.end_line
        
        # Add code snippet if available
        if finding.code:
            location["physicalLocation"]["region"]["snippet"] = {
                "text": finding.code
            }
        
        return location
    
    def _create_artifacts(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create SARIF artifacts array."""
        files = set(finding.file for finding in findings)
        return [
            {
                "location": {
                    "uri": file_path,
                    "uriBaseId": "%SRCROOT%"
                },
                "mimeType": "text/plain"
            }
            for file_path in sorted(files)
        ]
    
    def _create_invocation(self, run_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create SARIF invocation object."""
        return {
            "commandLine": run_metadata.get("command_line", "vulnhuntr2 scan"),
            "startTimeUtc": run_metadata.get("start_time", datetime.now(timezone.utc).isoformat()),
            "endTimeUtc": run_metadata.get("end_time", datetime.now(timezone.utc).isoformat()),
            "exitCode": run_metadata.get("exit_code", 0),
            "executionSuccessful": run_metadata.get("execution_successful", True),
            "toolExecutionNotifications": []
        }
    
    def _create_markdown_message(self, finding: Finding) -> str:
        """Create markdown formatted message for finding."""
        markdown = f"**{finding.title}**\n\n"
        
        if finding.description:
            markdown += f"{finding.description}\n\n"
        
        if finding.code:
            markdown += f"```solidity\n{finding.code}\n```\n\n"
        
        markdown += f"- **Severity:** {finding.severity.name}\n"
        markdown += f"- **Confidence:** {finding.confidence:.2f}\n"
        markdown += f"- **Category:** {finding.category}\n"
        
        if finding.function_name:
            markdown += f"- **Function:** {finding.function_name}\n"
        
        if finding.contract_name:
            markdown += f"- **Contract:** {finding.contract_name}\n"
        
        if finding.remediation:
            markdown += f"\n**Remediation:**\n{finding.remediation}\n"
        
        if finding.references:
            markdown += "\n**References:**\n"
            for ref in finding.references:
                markdown += f"- {ref}\n"
        
        return markdown
    
    def _get_rule_id(self, finding: Finding) -> str:
        """Get SARIF rule ID for finding."""
        # Map detector to rule ID - for now use generic
        return "VH001"
    
    def _map_severity_to_level(self, severity: Severity) -> str:
        """Map vulnhuntr severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error", 
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "warning")


class GitHubCodeScanningIntegration:
    """
    GitHub Advanced Security code scanning integration.
    """
    
    def __init__(self, sarif_exporter: Optional[SarifExporter] = None):
        self.sarif_exporter = sarif_exporter or SarifExporter()
    
    def export_for_github(self, findings: List[Finding], output_path: Path, github_metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Export findings in GitHub code scanning compatible format.
        
        Args:
            findings: List of findings to export
            output_path: Path to write SARIF file  
            github_metadata: GitHub-specific metadata
        """
        # Enhance metadata for GitHub
        enhanced_metadata = github_metadata or {}
        enhanced_metadata.update({
            "github_integration": True,
            "tool_name": "vulnhuntr2",
            "analysis_type": "security"
        })
        
        # Filter findings appropriate for code scanning
        filtered_findings = self._filter_for_github(findings)
        
        # Export with GitHub-specific enhancements
        self.sarif_exporter.export_findings(filtered_findings, output_path, enhanced_metadata)
    
    def _filter_for_github(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings appropriate for GitHub code scanning."""
        # Filter out INFO level findings and low confidence findings
        filtered = []
        for finding in findings:
            if finding.severity == Severity.INFO:
                continue
            if finding.confidence < 0.3:  # Skip very low confidence
                continue
            filtered.append(finding)
        
        return filtered
    
    def create_code_scanning_config(self, output_path: Path) -> None:
        """Create GitHub code scanning workflow configuration."""
        workflow_content = """
name: "Vulnhuntr2 Security Analysis"

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-analysis:
    name: Security Analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
    - name: Checkout repository
      uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install vulnhuntr2
      run: |
        pip install vulnhuntr2

    - name: Run security analysis
      run: |
        vulnhuntr2 scan . --format sarif --sarif-file vulnhuntr2-results.sarif

    - name: Upload SARIF to GitHub
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: vulnhuntr2-results.sarif
        category: vulnhuntr2
"""
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(workflow_content)


# Export main classes
__all__ = ['SarifExporter', 'GitHubCodeScanningIntegration']