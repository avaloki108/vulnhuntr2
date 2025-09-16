from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict, Any

from .registry import get_registered_detectors
from .models import Finding, ScanContext, ContractInfo, Severity


class Orchestrator:
    """Enhanced orchestrator for running vulnerability detection with new architecture."""

    def __init__(self, detectors: List[Any] = None) -> None:
        self.detectors = detectors if detectors is not None else get_registered_detectors()

    def collect_sources(self, target: Path) -> List[Path]:
        if target.is_file():
            return [target] if target.suffix.lower() == ".sol" else []
        collected: List[Path] = []
        for root, _dirs, files in os.walk(target):
            for f in files:
                if f.lower().endswith(".sol"):
                    collected.append(Path(root) / f)
        return collected

    def run(self, target: Path) -> List[Dict[str, Any]]:
        """Legacy run method for backward compatibility."""
        context = ScanContext(target_path=target)
        findings = self.run_enhanced(context)
        
        # Convert to legacy format
        legacy_findings = []
        for finding in findings:
            legacy_findings.append({
                "detector": finding.detector,
                "title": finding.title,
                "file": finding.file,
                "line": finding.line,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "code": finding.code,
                "description": finding.description,
            })
        
        return legacy_findings

    def run_enhanced(self, context: ScanContext) -> List[Finding]:
        """Enhanced run method using new models and architecture."""
        sources = self.collect_sources(context.target_path)
        all_findings: List[Finding] = []

        # Parse contracts (mock implementation for now)
        for src in sources:
            contract_info = self._parse_contract_mock(src)
            context.contracts.append(contract_info)

        # Run detectors with new interface
        for det in self.detectors:
            try:
                # Check if detector uses new interface
                if hasattr(det, 'analyze') and callable(det.analyze):
                    # Try new interface first
                    try:
                        findings = list(det.analyze(context))
                        all_findings.extend(findings)
                    except TypeError:
                        # Fall back to old interface
                        for src in sources:
                            try:
                                content = src.read_text(encoding="utf-8", errors="ignore")
                                old_findings = det.analyze(str(src), content)
                                
                                # Convert old findings to new format
                                for old_finding in old_findings:
                                    new_finding = self._convert_old_finding(old_finding)
                                    all_findings.append(new_finding)
                                    
                            except Exception as e:
                                # Create error finding
                                error_finding = Finding(
                                    detector="orchestrator",
                                    title="Detector Error",
                                    file=str(src),
                                    line=0,
                                    severity=Severity.INFO,
                                    code="",
                                    description=f"Error running detector {det.name}: {e}"
                                )
                                all_findings.append(error_finding)
                                
            except Exception as e:
                # Create error finding for detector failure
                error_finding = Finding(
                    detector="orchestrator",
                    title="Detector Initialization Error",
                    file=str(context.target_path),
                    line=0,
                    severity=Severity.INFO,
                    code="",
                    description=f"Failed to initialize detector {getattr(det, 'name', 'unknown')}: {e}"
                )
                all_findings.append(error_finding)

        return all_findings

    def _parse_contract_mock(self, source_path: Path) -> ContractInfo:
        """Mock contract parsing - to be replaced with real Slither/tree-sitter integration."""
        
        try:
            content = source_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        
        # Extract contract name from filename or content
        contract_name = source_path.stem
        
        # Simple regex to find contract declaration
        import re
        contract_match = re.search(r'contract\s+(\w+)', content, re.IGNORECASE)
        if contract_match:
            contract_name = contract_match.group(1)
        
        # Create mock contract info
        return ContractInfo(
            name=contract_name,
            file_path=str(source_path),
            inheritance=[],
            functions=[],
            state_variables=[],
            events=[],
            modifiers=[]
        )

    def _convert_old_finding(self, old_finding) -> Finding:
        """Convert old Finding format to new Finding format."""
        
        # Handle both dict and object formats
        if hasattr(old_finding, 'detector'):
            # Object format
            severity_str = getattr(old_finding, 'severity', 'INFO')
            if isinstance(severity_str, str):
                try:
                    severity = Severity.from_string(severity_str)
                except ValueError:
                    severity = Severity.INFO
            else:
                severity = severity_str
                
            return Finding(
                detector=old_finding.detector,
                title=old_finding.title,
                file=old_finding.file,
                line=old_finding.line,
                severity=severity,
                code=old_finding.code,
                description=getattr(old_finding, 'description', None)
            )
        else:
            # Dict format
            severity_str = old_finding.get('severity', 'INFO')
            try:
                severity = Severity.from_string(severity_str)
            except ValueError:
                severity = Severity.INFO
                
            return Finding(
                detector=old_finding.get('detector', 'unknown'),
                title=old_finding.get('title', 'Unknown vulnerability'),
                file=old_finding.get('file', ''),
                line=old_finding.get('line', 0),
                severity=severity,
                code=old_finding.get('code', ''),
                description=old_finding.get('description')
            )
