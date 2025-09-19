"""
Enhanced reporting and CI gating functionality with Phase 4 metadata.
"""
from __future__ import annotations

import json
import time
import platform
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

from ..core.models import Finding, Severity, CorrelatedFinding
from ..config.schema import RunConfig
from ..config.loader import compute_config_hash
from ..core.version import VERSION


class EnhancedReportingEngine:
    """Enhanced reporting engine with Phase 4 metadata and timing metrics."""
    
    def __init__(self, config: RunConfig):
        self.config = config
        self.run_started = datetime.now(timezone.utc)
        self.start_time = time.time()
        
        # Timing metrics
        self.timing_metrics = {
            "startup_time": 0.0,
            "detector_loading_time": 0.0,
            "slither_analysis_time": 0.0,
            "path_slicing_time": 0.0,
            "correlation_time": 0.0,
            "symbolic_exploration_time": 0.0,
            "scoring_time": 0.0,
            "reporting_time": 0.0,
            "total_time": 0.0
        }
        
        # Budget consumption tracking
        self.budget_consumption = {
            "symbolic_time_used": 0.0,
            "symbolic_functions_analyzed": 0,
            "path_slices_generated": 0,
            "correlation_patterns_matched": 0
        }
        
        # Compiler context
        self.compiler_context = {
            "solc_version": "",
            "evm_version": "",
            "optimizer_enabled": False,
            "optimizer_runs": 200
        }
    
    def set_timing_metric(self, metric_name: str, duration: float):
        """Set a timing metric"""
        self.timing_metrics[metric_name] = duration
    
    def update_budget_consumption(self, budget_data: Dict[str, Any]):
        """Update budget consumption data"""
        self.budget_consumption.update(budget_data)
    
    def set_compiler_context(self, context: Dict[str, Any]):
        """Set compiler context information"""
        self.compiler_context.update(context)
    
    def package_results(
        self,
        gating_findings: List[Finding],
        display_findings: List[Finding],
        correlated_findings: List[CorrelatedFinding],
        enabled_detectors: List[Any],
        warnings: List[str],
        path_slices: Optional[List[Any]] = None,
        symbolic_traces: Optional[List[Any]] = None,
        scoring_results: Optional[List[Any]] = None
    ) -> Tuple[int, List[str], Dict[str, Any]]:
        """
        Package results with enhanced Phase 4 metadata.
        
        Args:
            gating_findings: Raw findings used for CI gating evaluation
            display_findings: Filtered findings used for display and output
            correlated_findings: Correlated findings from analysis
            enabled_detectors: List of enabled detectors
            warnings: Configuration and processing warnings
            path_slices: Optional path slicing results
            symbolic_traces: Optional symbolic execution traces
            scoring_results: Optional scoring analysis results
        
        Returns:
            Tuple of (exit_code, gating_reasons, report_object)
        """
        run_finished = datetime.now(timezone.utc)
        total_duration = time.time() - self.start_time
        self.timing_metrics["total_time"] = total_duration
        
        # Evaluate gating conditions against raw findings
        exit_code, gating_reasons = self._evaluate_gating(gating_findings)
        
        # Build enhanced metadata block
        metadata = self._build_enhanced_metadata(
            run_finished, total_duration, display_findings, gating_findings,
            enabled_detectors, warnings, path_slices, symbolic_traces, scoring_results,
            exit_code, gating_reasons
        )
        
        # Generate dynamic report title
        report_title = self._generate_dynamic_title(display_findings)

        # Build comprehensive report object
        report = {
            "title": report_title,
            "meta": metadata,
            "findings": [finding.to_dict() for finding in display_findings],
            "correlated_findings": [cf.to_dict() for cf in correlated_findings] if correlated_findings else [],

            # Phase 4 enhancements
            "path_slices": self._serialize_path_slices(path_slices) if path_slices else [],
            "symbolic_traces": self._serialize_symbolic_traces(symbolic_traces) if symbolic_traces else [],
            "scoring_results": self._serialize_scoring_results(scoring_results) if scoring_results else [],

            # Enhanced analysis metadata
            "analysis_summary": self._generate_analysis_summary(
                display_findings, correlated_findings, path_slices, symbolic_traces
            )
        }
        
        return exit_code, gating_reasons, report
    
    def _build_enhanced_metadata(
        self, run_finished: datetime, total_duration: float,
        display_findings: List[Finding], gating_findings: List[Finding],
        enabled_detectors: List[Any], warnings: List[str],
        path_slices: Optional[List[Any]], symbolic_traces: Optional[List[Any]],
        scoring_results: Optional[List[Any]], exit_code: int, gating_reasons: List[str]
    ) -> Dict[str, Any]:
        """Build enhanced metadata with Phase 4 information"""
        
        return {
            # Core metadata
            "version": VERSION,
            "config_hash": compute_config_hash(self.config),
            "deterministic_config_hash": self._generate_deterministic_config_hash(),
            "artifact_hashes": self._generate_artifact_hashes(),
            
            # Timing information
            "run_started": self.run_started.isoformat(),
            "run_finished": run_finished.isoformat(),
            "timing_metrics": self.timing_metrics,
            "total_duration_seconds": total_duration,
            
            # Finding statistics
            "total_findings": len(display_findings),
            "total_raw_findings": len(gating_findings),
            "correlated_clusters": len([cf for cf in ([] if not hasattr(self, '_correlated_findings') else self._correlated_findings) if len(cf.all_findings) > 1]),
            
            # Detector information
            "detectors_enabled": len(enabled_detectors),
            "detector_names": [getattr(d, 'name', str(d)) for d in enabled_detectors],
            "detector_metadata": self._extract_detector_metadata(enabled_detectors),
            
            # Compiler context
            "compiler_context": self.compiler_context,
            
            # System information
            "system_info": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture()[0]
            },
            
            # Budget consumption
            "budget_consumption": self.budget_consumption,
            
            # Analysis statistics
            "analysis_stats": {
                "path_slices_generated": len(path_slices) if path_slices else 0,
                "symbolic_traces_generated": len(symbolic_traces) if symbolic_traces else 0,
                "scoring_analyses_performed": len(scoring_results) if scoring_results else 0,
                "patterns_matched": self.budget_consumption.get("correlation_patterns_matched", 0)
            },
            
            # CI/CD gating
            "gating": {
                "triggered": exit_code != 0,
                "exit_code": exit_code,
                "reasons": gating_reasons
            },
            
            # Warnings and diagnostics
            "warnings": warnings,
            "diagnostics": self._generate_diagnostics()
        }
    
    def _generate_deterministic_config_hash(self) -> str:
        """Generate deterministic configuration hash excluding runtime paths"""
        import hashlib
        
        # Create normalized config without runtime-specific fields
        normalized_config = {
            "detectors": {
                "enabled": sorted(self.config.detectors.enabled),
                "disabled": sorted(self.config.detectors.disabled),
                "categories": sorted(self.config.detectors.categories),
                "min_confidence": self.config.detectors.min_confidence,
                "max_confidence": self.config.detectors.max_confidence
            },
            "analysis": {
                "enable_correlation": self.config.analysis.enable_correlation,
                "enable_path_slicing": getattr(self.config.analysis, 'enable_path_slicing', True),
                "enable_symbolic_exploration": getattr(self.config.analysis, 'enable_symbolic_exploration', False),
                "enable_scoring": getattr(self.config.analysis, 'enable_scoring', True)
            },
            "llm": {
                "enabled": self.config.llm.enabled,
                "provider": self.config.llm.provider,
                "model": self.config.llm.model,
                "temperature": self.config.llm.temperature
            }
        }
        
        canonical_json = json.dumps(normalized_config, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
    
    def _generate_artifact_hashes(self) -> Dict[str, str]:
        """Generate hashes of important artifacts"""
        import hashlib
        
        hashes = {}
        
        # Config file hash
        if self.config.config_file and self.config.config_file.exists():
            with open(self.config.config_file, 'rb') as f:
                hashes["config_file"] = hashlib.sha256(f.read()).hexdigest()
        
        # Pattern file hash (if exists)
        patterns_path = Path(__file__).parent.parent / "correlation" / "patterns.yml"
        if patterns_path.exists():
            with open(patterns_path, 'rb') as f:
                hashes["correlation_patterns"] = hashlib.sha256(f.read()).hexdigest()
        
        return hashes
    
    def _extract_detector_metadata(self, enabled_detectors: List[Any]) -> List[Dict[str, Any]]:
        """Extract metadata from enabled detectors"""
        metadata = []
        
        for detector in enabled_detectors:
            det_meta = {
                "name": getattr(detector, 'name', 'unknown'),
                "category": getattr(detector, 'category', 'unknown'),
                "stability": getattr(detector, 'stability', 'unknown'),
                "severity": getattr(detector, 'severity', 'unknown')
            }
            
            # Convert severity enum to string if needed
            if hasattr(det_meta["severity"], 'value'):
                det_meta["severity"] = det_meta["severity"].value
            
            metadata.append(det_meta)
        
        return metadata
    
    def _serialize_path_slices(self, path_slices: List[Any]) -> List[Dict[str, Any]]:
        """Serialize path slices for JSON output"""
        serialized = []
        
        for slice_obj in path_slices:
            slice_data = {
                "contract": getattr(slice_obj, 'contract', ''),
                "function": getattr(slice_obj, 'function', ''),
                "node_sequence": getattr(slice_obj, 'node_sequence', []),
                "path_fingerprint": getattr(slice_obj, 'path_fingerprint', ''),
                "termination_reason": getattr(slice_obj, 'termination_reason', ''),
                "has_reentrancy_guard": getattr(slice_obj, 'has_reentrancy_guard', False),
                "external_calls_count": len(getattr(slice_obj, 'external_calls', [])),
                "state_modifications_count": len(getattr(slice_obj, 'state_modifications', [])),
                "hop_count": getattr(slice_obj, 'hop_count', 0)
            }
            serialized.append(slice_data)
        
        return serialized
    
    def _serialize_symbolic_traces(self, symbolic_traces: List[Any]) -> List[Dict[str, Any]]:
        """Serialize symbolic traces for JSON output"""
        serialized = []
        
        for trace in symbolic_traces:
            trace_data = {
                "function_name": getattr(trace, 'function_name', ''),
                "contract_name": getattr(trace, 'contract_name', ''),
                "trace_id": getattr(trace, 'trace_id', ''),
                "vulnerability_type": getattr(trace, 'vulnerability_type', ''),
                "exploitability_score": getattr(trace, 'exploitability_score', 0.0),
                "analysis_time_s": getattr(trace, 'analysis_time_s', 0.0),
                "paths_explored": getattr(trace, 'paths_explored', 0),
                "termination_reason": getattr(trace, 'termination_reason', ''),
                "execution_steps_count": len(getattr(trace, 'execution_steps', []))
            }
            serialized.append(trace_data)
        
        return serialized
    
    def _serialize_scoring_results(self, scoring_results: List[Any]) -> List[Dict[str, Any]]:
        """Serialize scoring results for JSON output"""
        serialized = []
        
        for result in scoring_results:
            if hasattr(result, 'to_dict'):
                serialized.append(result.to_dict())
            else:
                # Fallback serialization
                result_data = {
                    "total_score": getattr(result, 'total_score', 0.0),
                    "severity_adjustment": getattr(result, 'severity_adjustment', 0.0),
                    "confidence_adjustment": getattr(result, 'confidence_adjustment', 0.0),
                    "adjustment_rationale": getattr(result, 'adjustment_rationale', '')
                }
                serialized.append(result_data)
        
        return serialized
    
    def _generate_analysis_summary(
        self, findings: List[Finding], correlated_findings: List[CorrelatedFinding],
        path_slices: Optional[List[Any]], symbolic_traces: Optional[List[Any]]
    ) -> Dict[str, Any]:
        """Generate high-level analysis summary"""
        
        # Severity distribution
        severity_counts = {}
        for finding in findings:
            sev_name = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            severity_counts[sev_name] = severity_counts.get(sev_name, 0) + 1
        
        # Category distribution
        category_counts = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        # Detector distribution
        detector_counts = {}
        for finding in findings:
            detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
        
        # Correlation statistics
        correlation_stats = {
            "total_clusters": len(correlated_findings),
            "multi_finding_clusters": len([cf for cf in correlated_findings if len(cf.all_findings) > 1]),
            "average_cluster_size": sum(len(cf.all_findings) for cf in correlated_findings) / len(correlated_findings) if correlated_findings else 0,
            "pattern_matched_clusters": len([cf for cf in correlated_findings if hasattr(cf, 'cluster_metadata') and getattr(cf.cluster_metadata, 'pattern_name', None)])
        }
        
        return {
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "detector_distribution": detector_counts,
            "correlation_statistics": correlation_stats,
            "analysis_coverage": {
                "contracts_analyzed": len(set(f.contract_name for f in findings if f.contract_name)),
                "functions_with_findings": len(set(f.function_name for f in findings if f.function_name)),
                "files_with_findings": len(set(f.file for f in findings))
            }
        }
    
    def _generate_diagnostics(self) -> Dict[str, Any]:
        """Generate diagnostic information"""
        return {
            "memory_usage_mb": self._get_memory_usage(),
            "performance_metrics": {
                "findings_per_second": self._calculate_findings_per_second(),
                "average_detector_time": self._calculate_average_detector_time()
            },
            "warnings_by_category": self._categorize_warnings()
        }
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
    
    def _calculate_findings_per_second(self) -> float:
        """Calculate findings generation rate"""
        total_time = self.timing_metrics.get("total_time", 0.0)
        if total_time > 0:
            return len(getattr(self, '_total_findings', [])) / total_time
        return 0.0
    
    def _calculate_average_detector_time(self) -> float:
        """Calculate average time per detector"""
        detector_time = self.timing_metrics.get("detector_loading_time", 0.0)
        num_detectors = len(getattr(self, '_enabled_detectors', []))
        if num_detectors > 0:
            return detector_time / num_detectors
        return 0.0
    
    def _categorize_warnings(self) -> Dict[str, int]:
        """Categorize warnings by type"""
        categories = {"config": 0, "detector": 0, "analysis": 0, "other": 0}
        
        for warning in getattr(self, '_warnings', []):
            warning_lower = warning.lower()
            if "config" in warning_lower:
                categories["config"] += 1
            elif "detector" in warning_lower:
                categories["detector"] += 1
            elif any(keyword in warning_lower for keyword in ["analysis", "correlation", "symbolic", "path"]):
                categories["analysis"] += 1
            else:
                categories["other"] += 1
        
        return categories
    
    def _evaluate_gating(self, findings: List[Finding]) -> Tuple[int, List[str]]:
        """Evaluate CI gating conditions (same as original)"""
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
                        f"Found {len(high_severity_findings)} findings >= {threshold_severity.name} "
                        f"(fail_on_severity={threshold_severity.name})"
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
    
    def save_evidence_export(self, correlated_findings: List[CorrelatedFinding], output_path: Path) -> None:
        """Save evidence bundles to separate export file"""
        evidence_data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_bundles": []
        }
        
        for corr_finding in correlated_findings:
            if hasattr(corr_finding, 'evidence_bundle') and corr_finding.evidence_bundle:
                bundle_data = {
                    "evidence_id": getattr(corr_finding.evidence_bundle, 'evidence_id', ''),
                    "finding_id": getattr(corr_finding.evidence_bundle, 'finding_id', ''),
                    "variables_of_interest": getattr(corr_finding.evidence_bundle, 'variables_of_interest', []),
                    "rationale": getattr(corr_finding.evidence_bundle, 'rationale', ''),
                    "path_slices": getattr(corr_finding.evidence_bundle, 'path_slices', []),
                    "symbolic_traces": getattr(corr_finding.evidence_bundle, 'symbolic_traces', []),
                    "mini_repro_sources": getattr(corr_finding.evidence_bundle, 'mini_repro_sources', []),
                    "compiler_context": getattr(corr_finding.evidence_bundle, 'compiler_context', {}),
                    "timing_metrics": getattr(corr_finding.evidence_bundle, 'timing_metrics', {}),
                    "budget_consumption": getattr(corr_finding.evidence_bundle, 'budget_consumption', {})
                }
                evidence_data["evidence_bundles"].append(bundle_data)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(evidence_data, f, indent=2, default=str)

    def _generate_dynamic_title(self, findings: List[Finding]) -> str:
        """Generate dynamic report title with date, time, and scan summary"""
        import os
        from pathlib import Path

        # Get current timestamp
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S UTC")

        # Determine scan target from config or current directory
        scan_target = "Unknown Target"
        if hasattr(self.config, 'target_path') and self.config.target_path:
            scan_target = Path(self.config.target_path).name
        else:
            # Fall back to current working directory name
            scan_target = Path(os.getcwd()).name

        # Generate findings summary
        finding_count = len(findings)
        if finding_count == 0:
            findings_summary = "No vulnerabilities detected"
        else:
            # Count by severity
            severity_counts = {}
            for finding in findings:
                severity = str(finding.severity.value).upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Create summary string
            severity_parts = []
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    severity_parts.append(f"{count} {severity.lower()}")

            if severity_parts:
                findings_summary = f"{finding_count} vulnerabilities found: {', '.join(severity_parts)}"
            else:
                findings_summary = f"{finding_count} vulnerabilities found"

        # Construct title
        title = f"VulnHuntr Security Analysis Report - {scan_target} | {date_str} {time_str} | {findings_summary}"

        return title

    def get_optimal_output_format(self, findings: List[Finding]) -> str:
        """Determine optimal output format based on findings and context"""
        # For now, JSON is the most comprehensive format
        # Could expand this logic based on findings complexity, number, etc.
        if len(findings) > 0:
            return "json"  # Rich data needs JSON
        else:
            return "table"  # Simple output for no findings


# Backward compatibility
ReportingEngine = EnhancedReportingEngine