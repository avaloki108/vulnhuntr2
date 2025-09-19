"""
Core orchestration engine with Phase 5 enhancements.
"""
from __future__ import annotations

import os
import inspect
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import time

from .registry import get_registered_detectors, discover_detectors
from .models import Finding, ScanContext, Contract, Severity
from .triage import TriageEngine, TriageResult
from .incremental import IncrementalScanner, IncrementalScanContext
from .sarif_export import SarifExporter
from .pattern_engine import PatternEngine
from ..plugins import PluginManager
from ..config.settings import Settings


class Orchestrator:
    """Enhanced orchestrator for running vulnerability detection with Phase 5 features."""

    def __init__(self, detectors: List[Any] = None, config: Optional[Settings] = None) -> None:
        # Auto-discover detectors if not provided
        if detectors is None:
            discover_detectors()
            self.detectors = get_registered_detectors()
        else:
            self.detectors = detectors
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Phase 5 components (initialized only if enabled)
        self.plugin_manager: Optional[PluginManager] = None
        self.triage_engine: Optional[TriageEngine] = None
        self.incremental_scanner: Optional[IncrementalScanner] = None
        self.sarif_exporter: Optional[SarifExporter] = None
        self.pattern_engine: Optional[PatternEngine] = None
        
        if config:
            self._initialize_phase5_components(config)

    def _initialize_phase5_components(self, config: Settings) -> None:
        """Initialize Phase 5 components based on configuration."""
        
        # Plugin system - disabled for now as we don't have plugins config in Settings yet
        # if hasattr(config, 'plugins') and config.plugins.enable_plugins:
        #     self.plugin_manager = PluginManager({...})
        #     self.logger.info("Plugin system enabled")
        
        # AI Triage
        if config.llm.enabled:
            try:
                self.triage_engine = TriageEngine(config.llm)
                self.logger.info("AI triage system enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize triage engine: {e}")
        
        # Incremental scanning - disabled for now
        # if hasattr(config.analysis, 'enable_incremental') and config.analysis.enable_incremental:
        #     self.incremental_scanner = IncrementalScanner(config.analysis.diff_base)
        #     self.logger.info(f"Incremental scanning enabled")
        
        # SARIF export
        if config.reporting.sarif or config.output.format == "sarif":
            try:
                self.sarif_exporter = SarifExporter()
                self.logger.info("SARIF export enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize SARIF exporter: {e}")
        
        # Pattern engine - disabled for now
        # if hasattr(config, 'pattern_dirs') and config.pattern_dirs:
        #     self.pattern_engine = PatternEngine(...)
        #     self.logger.info("Pattern engine enabled")

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
        """Enhanced run method with Phase 5 features."""
        # Phase 5: Check for incremental scanning
        incremental_context = None
        if self.incremental_scanner:
            incremental_context = self.incremental_scanner.create_incremental_context(context)
            self.logger.info(f"Incremental scan: {len(incremental_context.changed_files)} changed files")
        
        sources = self.collect_sources(context.target_path)
        all_findings: List[Finding] = []
        
        # Filter sources for incremental scanning
        if incremental_context:
            filtered_sources: List[Path] = []
            for src in sources:
                if self.incremental_scanner.should_scan_file(str(src), incremental_context):
                    filtered_sources.append(src)
            sources = filtered_sources
            self.logger.info(f"Incremental filtering: scanning {len(sources)} files")
        
        # Optional: Slither enrichment if enabled in config
        if getattr(self.config, 'analysis', None) and getattr(self.config.analysis, 'use_slither', False):
            try:
                from ..parsing.slither_adapter import run_slither
                slither_result = run_slither(str(context.target_path))
                if slither_result is not None:
                    # Map contracts (minimal) and store raw
                    for c in slither_result.contracts:
                        context.contracts.append(
                            Contract(
                                name=c.name,
                                file_path=c.file,
                                line_start=c.line_start,
                                line_end=c.line_end,
                                variables=[],
                                is_abstract=False,
                                inherits_from=[],
                                source=""
                            )
                        )
                    context.tool_artifacts['slither'] = slither_result.raw_data
                    self.logger.info("Slither enrichment completed")
            except Exception as e:
                self.logger.warning(f"Slither enrichment skipped: {e}")
 
        # Parse contracts (mock implementation for now) if none populated
        if not context.contracts:
            for src in sources:
                contract_info = self._parse_contract_mock(src)
                context.contracts.append(contract_info)

        # Phase 5: Apply pattern engine if available
        if self.pattern_engine:
            for src in sources:
                try:
                    content = src.read_text(encoding="utf-8", errors="ignore")
                    pattern_findings = self.pattern_engine.apply_patterns(content, str(src), context)
                    all_findings.extend(pattern_findings)
                except Exception as e:
                    self.logger.error(f"Pattern engine failed for {src}: {e}")

        # Phase 5: Execute plugin detectors
        if self.plugin_manager:
            detector_plugins = [p for p in self.plugin_manager.loaded_plugins.values() 
                              if hasattr(p, 'analyze')]
            for plugin in detector_plugins:
                try:
                    plugin_findings = self.plugin_manager.execute_detector_plugin(plugin, context)
                    all_findings.extend(plugin_findings)
                except Exception as e:
                    self.logger.error(f"Plugin detector failed: {e}")

        # Run traditional detectors with new interface
        for det_cls in self.detectors:
            try:
                # Instantiate the detector
                det = det_cls()
                
                # Check if detector uses new interface
                if hasattr(det, 'analyze') and callable(det.analyze):
                    # Check method signature to determine interface
                    sig = inspect.signature(det.analyze)
                    
                    if "context" in sig.parameters or "scan_context" in sig.parameters:
                        # New interface - pass ScanContext
                        try:
                            findings = list(det.analyze(context))
                            all_findings.extend(findings)
                        except Exception as e:
                            self.logger.error(f"Error with new interface for {det.name}: {e}", exc_info=True)
                            # Create error finding
                            error_finding = Finding(
                                detector="orchestrator", 
                                title=f"Detector Error: {det.name}",
                                file=str(context.target_path),
                                line=0,
                                severity=Severity.INFO,
                                code="",
                                description=f"Error running detector {det.name}: {e}"
                            )
                            all_findings.append(error_finding)
                    else:
                        # Old interface - iterate sources
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
                                self.logger.error(f"Error running detector {det.name} on {src}: {e}", exc_info=True)
                                error_finding = Finding(
                                    detector="orchestrator",
                                    title=f"Detector Error: {det.name}",
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
                    description=f"Failed to initialize detector {getattr(det_cls, 'name', getattr(det_cls, '__name__', 'unknown'))}: {e}"
                )
                all_findings.append(error_finding)

        # Phase 5: Enricher plugins
        if self.plugin_manager:
            enricher_plugins = [p for p in self.plugin_manager.loaded_plugins.values() 
                               if hasattr(p, 'enrich')]
            for plugin in enricher_plugins:
                try:
                    all_findings = self.plugin_manager.execute_enricher_plugin(plugin, all_findings, context)
                except Exception as e:
                    self.logger.error(f"Plugin enricher failed: {e}")

        # Phase 5: AI Triage
        triage_results: Dict[str, TriageResult] = {}
        if self.triage_engine:
            try:
                triage_results = self.triage_engine.triage_findings(all_findings, context)
                self.logger.info(f"AI triage completed for {len(triage_results)} findings")
            except Exception as e:
                self.logger.error(f"AI triage failed: {e}")

        # Phase 5: Postprocessor plugins
        if self.plugin_manager:
            postprocessor_plugins = [p for p in self.plugin_manager.loaded_plugins.values() 
                                   if hasattr(p, 'postprocess')]
            for plugin in postprocessor_plugins:
                try:
                    all_findings = self.plugin_manager.execute_postprocessor_plugin(plugin, all_findings, context)
                except Exception as e:
                    self.logger.error(f"Plugin postprocessor failed: {e}")

        # Attach triage results to findings
        if triage_results:
            for finding in all_findings:
                finding_id = self._generate_finding_id(finding)
                if finding_id in triage_results:
                    setattr(finding, 'triage_result', triage_results[finding_id])

        return all_findings
    
    def export_sarif(self, findings: List[Finding], output_path: Path, run_metadata: Optional[Dict[str, Any]] = None) -> None:
        """Export findings to SARIF format."""
        if not self.sarif_exporter:
            self.sarif_exporter = SarifExporter()
        
        self.sarif_exporter.export_findings(findings, output_path, run_metadata or {})
        self.logger.info(f"SARIF export completed: {output_path}")
        
    def get_phase5_status(self) -> Dict[str, bool]:
        """Get status of Phase 5 components."""
        return {
            "plugin_system": self.plugin_manager is not None,
            "ai_triage": self.triage_engine is not None,
            "incremental_scanning": self.incremental_scanner is not None,
            "sarif_export": self.sarif_exporter is not None,
            "pattern_engine": self.pattern_engine is not None
        }
    
    def _generate_finding_id(self, finding: Finding) -> str:
        """Generate deterministic ID for finding (matches triage engine)."""
        import hashlib
        content = f"{finding.detector}:{finding.title}:{finding.file}:{finding.line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _parse_contract_mock(self, source_path: Path) -> Contract:
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
        return Contract(
            name=contract_name,
            file_path=str(source_path),
            line_start=0,
            line_end=0,
            variables=[],
            is_abstract=False,
            inherits_from=[],
            source=content
        )

def scan_directory(target: str, config=None) -> List[Finding]:
    """Scan a directory for vulnerabilities (wrapper for CLI compatibility)."""
    from pathlib import Path
    target_path = Path(target)
    
    # Initialize orchestrator
    orchestrator = Orchestrator(config=config)
    
    # Create scan context
    context = ScanContext(target_path=target_path)
    
    # Run enhanced scan
    findings = orchestrator.run_enhanced(context)
    return findings


def scan_file(target: str, config=None) -> List[Finding]:
    """Scan a single file for vulnerabilities (wrapper for CLI compatibility)."""
    from pathlib import Path
    target_path = Path(target)
    
    # Initialize orchestrator  
    orchestrator = Orchestrator(config=config)
    
    # Create scan context
    context = ScanContext(target_path=target_path)
    
    # Run enhanced scan
    findings = orchestrator.run_enhanced(context)
    return findings


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
