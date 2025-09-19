"""
SARIF (Static Analysis Results Interchange Format) output formatter.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from vulnhuntr.core.registry import Finding
import vulnhuntr

class SarifReport:
    """Generate SARIF reports from analysis findings."""
    
    def __init__(self):
        self.tool_name = "vulnhuntr2"
        self.tool_version = vulnhuntr.__version__
        
    def _convert_severity(self, severity: str) -> str:
        """Convert internal severity to SARIF severity level."""
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note"
        }
        return severity_map.get(severity, "warning")
    
    def _create_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a finding to a SARIF result object."""
        severity = self._convert_severity(finding.severity)
        
        # Create location
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file
                }
            }
        }
        
        # Add line information if available
        if finding.line is not None:
            location["physicalLocation"]["region"] = {
                "startLine": finding.line
            }
            
        # Create fix recommendation if available
        fixes = []
        if hasattr(finding, "recommendation") and finding.recommendation:
            fixes.append({
                "description": {
                    "text": finding.recommendation
                }
            })
        
        return {
            "ruleId": finding.detector,
            "message": {
                "text": finding.title
            },
            "level": severity,
            "locations": [location],
            "fixes": fixes if fixes else None,
            "properties": {
                "tags": [finding.severity, finding.detector],
                "precision": "high" if hasattr(finding, "confidence") and finding.confidence > 0.8 else "medium"
            }
        }
    
    def _create_rule(self, detector_name: str, findings: List[Finding]) -> Dict[str, Any]:
        """Create a SARIF rule from detector information."""
        # Use the first finding to get detector metadata
        finding = findings[0]
        
        return {
            "id": detector_name,
            "name": detector_name,
            "shortDescription": {
                "text": detector_name.replace("_", " ").title()
            },
            "fullDescription": {
                "text": f"Detector for {detector_name.replace('_', ' ')} issues"
            },
            "defaultConfiguration": {
                "level": self._convert_severity(finding.severity)
            },
            "properties": {
                "tags": [finding.severity],
                "precision": "high" if hasattr(finding, "confidence") and finding.confidence > 0.8 else "medium"
            }
        }
    
    def generate(self, findings: List[Finding], output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a SARIF report from findings.
        
        Args:
            findings: List of analysis findings
            output_path: Path to write the SARIF report (if None, report is not written to file)
            
        Returns:
            SARIF report as dictionary
        """
        # Group findings by detector
        findings_by_detector = {}
        for finding in findings:
            if finding.detector not in findings_by_detector:
                findings_by_detector[finding.detector] = []
            findings_by_detector[finding.detector].append(finding)
        
        # Create rules
        rules = [self._create_rule(detector, detector_findings) 
                for detector, detector_findings in findings_by_detector.items()]
        
        # Create results
        results = [self._create_result(finding) for finding in findings]
        
        # Create SARIF report
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/avaloki108/vulnhuntr2",
                            "rules": rules
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "timestamp": datetime.utcnow().isoformat(),
                            "toolExecutionNotifications": []
                        }
                    ]
                }
            ]
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(sarif, f, indent=2)
        
        return sarif