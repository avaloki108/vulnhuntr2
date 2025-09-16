"""
Reporting and CI gating functionality.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

from ..core.models import Finding, Severity, CorrelatedFinding
from ..config.schema import RunConfig
from ..config.loader import compute_config_hash
from ..core.version import VERSION


class ReportingEngine:
    """Handles result packaging and CI gating evaluation."""
    
    def __init__(self, config: RunConfig):
        self.config = config
        self.run_started = datetime.now(timezone.utc)
    
    def package_results(
        self,
        gating_findings: List[Finding],
        display_findings: List[Finding],
        correlated_findings: List[CorrelatedFinding],
        enabled_detectors: List[Any],
        warnings: List[str]
    ) -> Tuple[int, List[str], Dict[str, Any]]:
        """
        Package results and evaluate gating conditions.
        
        Args:
            gating_findings: Raw findings used for CI gating evaluation
            display_findings: Filtered findings used for display and output
            correlated_findings: Correlated findings from analysis
            enabled_detectors: List of enabled detectors
            warnings: Configuration and processing warnings
        
        Returns:
            Tuple of (exit_code, gating_reasons, report_object)
        """
        run_finished = datetime.now(timezone.utc)
        
        # Evaluate gating conditions against raw findings
        exit_code, gating_reasons = self._evaluate_gating(gating_findings)
        
        # Build metadata block
        metadata = {
            "version": VERSION,
            "config_hash": compute_config_hash(self.config),
            "run_started": self.run_started.isoformat(),
            "run_finished": run_finished.isoformat(),
            "total_findings": len(display_findings),  # Use display findings for report count
            "total_raw_findings": len(gating_findings),  # Include raw count for transparency
            "detectors_enabled": len(enabled_detectors),
            "detector_names": [getattr(d, 'name', str(d)) for d in enabled_detectors],
            "gating": {
                "triggered": exit_code != 0,
                "reasons": gating_reasons
            },
            "warnings": warnings
        }
        
        # Build report object with display findings
        report = {
            "meta": metadata,
            "findings": [finding.to_dict() for finding in display_findings],
            "correlated_findings": [cf.to_dict() for cf in correlated_findings] if correlated_findings else []
        }
        
        return exit_code, gating_reasons, report
    
    def _evaluate_gating(self, findings: List[Finding]) -> Tuple[int, List[str]]:
        """
        Evaluate CI gating conditions.
        
        Returns:
            Tuple of (exit_code, reasons)
        """
        reasons = []
        
        # Check basic fail_on_findings
        if self.config.reporting.fail_on_findings and findings:
            reasons.append(f"Found {len(findings)} findings (fail_on_findings=true)")
        
        # Check severity threshold
        if self.config.reporting.fail_on_severity:
            try:
                threshold_severity = Severity.from_string(self.config.reporting.fail_on_severity)
                high_severity_findings = [
                    f for f in findings 
                    if f.severity.score >= threshold_severity.score
                ]
                if high_severity_findings:
                    reasons.append(
                        f"Found {len(high_severity_findings)} findings >= {threshold_severity.value} "
                        f"(fail_on_severity={threshold_severity.value})"
                    )
            except ValueError:
                reasons.append(f"Invalid fail_on_severity value: {self.config.reporting.fail_on_severity}")
        
        # Check confidence threshold
        if self.config.reporting.fail_on_confidence is not None:
            high_confidence_findings = [
                f for f in findings 
                if f.confidence >= self.config.reporting.fail_on_confidence
            ]
            if high_confidence_findings:
                reasons.append(
                    f"Found {len(high_confidence_findings)} findings >= {self.config.reporting.fail_on_confidence} confidence "
                    f"(fail_on_confidence={self.config.reporting.fail_on_confidence})"
                )
        
        # Check finding count threshold
        if self.config.reporting.fail_on_finding_count is not None:
            if len(findings) >= self.config.reporting.fail_on_finding_count:
                reasons.append(
                    f"Found {len(findings)} findings >= {self.config.reporting.fail_on_finding_count} "
                    f"(fail_on_finding_count={self.config.reporting.fail_on_finding_count})"
                )
        
        # Return non-zero exit code if any gating condition triggered
        exit_code = 1 if reasons else 0
        
        return exit_code, reasons
    
    def format_exit_summary(self, exit_code: int, reasons: List[str]) -> str:
        """Format a clear exit summary for display."""
        if exit_code == 0:
            return "✅ All gating conditions passed"
        else:
            summary = "❌ CI gating triggered:\n"
            for i, reason in enumerate(reasons, 1):
                summary += f"  {i}. {reason}\n"
            return summary.rstrip()
    
    def save_json_report(self, report: Dict[str, Any], output_path: Path) -> None:
        """Save report to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def save_sarif_report(self, findings: List[Finding], output_path: Path) -> None:
        """Save findings in SARIF format (future enhancement)."""
        # Placeholder for SARIF implementation
        sarif_report = self._convert_to_sarif(findings)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _convert_to_sarif(self, findings: List[Finding]) -> Dict[str, Any]:
        """Convert findings to SARIF format (placeholder)."""
        # Basic SARIF structure - can be enhanced in future
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "vulnhuntr2",
                            "version": VERSION,
                            "informationUri": "https://github.com/avaloki108/vulnhuntr2"
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding.detector,
                            "message": {"text": finding.title},
                            "level": self._severity_to_sarif_level(finding.severity),
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": finding.file},
                                        "region": {"startLine": finding.line}
                                    }
                                }
                            ]
                        }
                        for finding in findings
                    ]
                }
            ]
        }
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert our severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error", 
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "note")