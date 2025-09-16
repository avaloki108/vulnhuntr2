"""
Selective symbolic exploration via optional Mythril wrapper with multi-level budget fuses.
Phase 4 implementation with concise trace summaries and significance thresholds.
"""
from __future__ import annotations

import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
import subprocess
import json
import tempfile


@dataclass
class SymbolicConfig:
    """Configuration for symbolic exploration"""
    enable: bool = False
    engine: str = "mythril"  # Currently only mythril supported
    max_time_s: int = 60  # Per function timeout
    max_total_time_s: int = 300  # Total runtime budget
    max_paths: int = 10  # Maximum paths to explore per function
    max_functions: int = 5  # Maximum functions to analyze
    trigger_min_severity: str = "MEDIUM"  # Minimum severity to trigger symbolic analysis
    trigger_min_cluster_size: int = 2  # Minimum cluster size to trigger
    trigger_min_significance: float = 0.55  # Minimum cluster significance to trigger


@dataclass
class SymbolicTrace:
    """Concise symbolic execution trace"""
    
    function_name: str
    contract_name: str
    trace_id: str
    execution_steps: List[Dict[str, Any]] = field(default_factory=list)
    
    # Trace metadata
    path_condition: str = ""
    symbolic_variables: List[str] = field(default_factory=list)
    external_calls: List[Dict[str, Any]] = field(default_factory=list)
    state_changes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Vulnerability information
    vulnerability_type: str = ""
    vulnerability_description: str = ""
    exploitability_score: float = 0.0
    
    # Budget tracking
    analysis_time_s: float = 0.0
    paths_explored: int = 0
    termination_reason: str = ""  # "complete", "timeout", "max_paths", "error"
    
    def generate_trace_id(self) -> str:
        """Generate deterministic trace ID"""
        trace_data = f"{self.contract_name}:{self.function_name}:{self.path_condition}"
        self.trace_id = hashlib.sha256(trace_data.encode()).hexdigest()[:16]
        return self.trace_id


@dataclass
class BudgetTracker:
    """Tracks budget consumption across symbolic exploration"""
    
    total_time_budget: float
    function_time_budget: float
    max_functions: int
    max_paths: int
    
    # Current consumption
    total_time_used: float = 0.0
    functions_analyzed: int = 0
    current_function_time: float = 0.0
    
    def start_function(self) -> bool:
        """Start analyzing a new function, return True if budget allows"""
        if self.functions_analyzed >= self.max_functions:
            return False
        if self.total_time_used >= self.total_time_budget:
            return False
        
        self.functions_analyzed += 1
        self.current_function_time = 0.0
        return True
    
    def check_function_budget(self, elapsed: float) -> bool:
        """Check if function still has budget"""
        self.current_function_time = elapsed
        return (
            elapsed < self.function_time_budget and
            self.total_time_used + elapsed < self.total_time_budget
        )
    
    def finish_function(self, elapsed: float):
        """Complete function analysis and update total budget"""
        self.total_time_used += elapsed


class SymbolicExplorer:
    """
    Symbolic exploration engine with multi-level budget fuses and selective triggering.
    """
    
    def __init__(self, config: Optional[SymbolicConfig] = None):
        self.config = config or SymbolicConfig()
        self.mythril_available = self._check_mythril_availability()
        
        # Budget tracker
        self.budget_tracker = BudgetTracker(
            total_time_budget=self.config.max_total_time_s,
            function_time_budget=self.config.max_time_s,
            max_functions=self.config.max_functions,
            max_paths=self.config.max_paths
        )
    
    def should_trigger_symbolic_analysis(self, findings: List[Any], correlated_findings: List[Any]) -> bool:
        """
        Determine if symbolic analysis should be triggered based on significance thresholds.
        
        Args:
            findings: List of raw findings
            correlated_findings: List of correlated findings with cluster metadata
            
        Returns:
            True if symbolic analysis should be triggered
        """
        if not self.config.enable or not self.mythril_available:
            return False
        
        # Check individual finding severity threshold
        for finding in findings:
            if self._meets_severity_threshold(finding):
                return True
        
        # Check cluster-based triggers
        for corr_finding in correlated_findings:
            # Check cluster size
            total_findings = len(corr_finding.all_findings)
            if total_findings >= self.config.trigger_min_cluster_size:
                return True
            
            # Check significance score
            if hasattr(corr_finding, 'significance') and corr_finding.significance >= self.config.trigger_min_significance:
                return True
        
        return False
    
    def analyze_contracts(self, source_files: List[Path], target_functions: Optional[List[str]] = None) -> List[SymbolicTrace]:
        """
        Perform selective symbolic analysis on contracts.
        
        Args:
            source_files: List of Solidity source files
            target_functions: Optional list of function names to analyze
            
        Returns:
            List of SymbolicTrace objects
        """
        if not self.config.enable or not self.mythril_available:
            return []
        
        symbolic_traces = []
        
        for source_file in source_files:
            if not self.budget_tracker.start_function():
                break
            
            traces = self._analyze_file(source_file, target_functions)
            symbolic_traces.extend(traces)
        
        return symbolic_traces
    
    def _analyze_file(self, source_file: Path, target_functions: Optional[List[str]]) -> List[SymbolicTrace]:
        """Analyze a single Solidity file with Mythril"""
        traces = []
        start_time = time.time()
        
        try:
            # Run Mythril analysis
            mythril_results = self._run_mythril(source_file)
            
            if mythril_results:
                # Convert Mythril results to SymbolicTrace objects
                file_traces = self._convert_mythril_results(mythril_results, target_functions)
                traces.extend(file_traces)
        
        except Exception as e:
            # Create error trace
            error_trace = SymbolicTrace(
                function_name="unknown",
                contract_name=source_file.stem,
                trace_id="error",
                termination_reason="error",
                vulnerability_description=f"Symbolic analysis error: {e}"
            )
            traces.append(error_trace)
        
        # Update budget
        elapsed = time.time() - start_time
        self.budget_tracker.finish_function(elapsed)
        
        return traces
    
    def _run_mythril(self, source_file: Path) -> Optional[Dict[str, Any]]:
        """Run Mythril analysis on a source file"""
        if not self.mythril_available:
            return None
        
        # Create temporary directory for Mythril output
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "mythril_output.json"
            
            # Build Mythril command
            cmd = [
                "myth",
                "analyze",
                str(source_file),
                "--output", "json",
                "--execution-timeout", str(self.config.max_time_s),
                "--max-depth", "10",  # Reasonable depth limit
                "--call-depth-limit", "5"  # Prevent infinite recursion
            ]
            
            try:
                # Run Mythril with timeout
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.max_time_s + 10,  # Add buffer for process overhead
                    cwd=temp_dir
                )
                
                # Parse JSON output
                if result.returncode == 0 and result.stdout:
                    try:
                        return json.loads(result.stdout)
                    except json.JSONDecodeError:
                        # Mythril might output non-JSON messages
                        return {"raw_output": result.stdout, "stderr": result.stderr}
                else:
                    return {"error": result.stderr or "Mythril analysis failed", "returncode": result.returncode}
            
            except subprocess.TimeoutExpired:
                return {"error": "Mythril analysis timed out", "timeout": True}
            except Exception as e:
                return {"error": f"Failed to run Mythril: {e}"}
    
    def _convert_mythril_results(self, mythril_results: Dict[str, Any], target_functions: Optional[List[str]]) -> List[SymbolicTrace]:
        """Convert Mythril analysis results to SymbolicTrace objects"""
        traces = []
        
        # Handle different Mythril output formats
        if "error" in mythril_results:
            # Error case
            error_trace = SymbolicTrace(
                function_name="unknown",
                contract_name="unknown",
                trace_id="error",
                termination_reason="error",
                vulnerability_description=mythril_results["error"]
            )
            traces.append(error_trace)
            return traces
        
        # Parse successful results
        issues = mythril_results.get("issues", [])
        if not issues and "raw_output" in mythril_results:
            # Try to parse raw output
            issues = self._parse_raw_mythril_output(mythril_results["raw_output"])
        
        for issue in issues:
            trace = self._create_trace_from_issue(issue, target_functions)
            if trace:
                traces.append(trace)
        
        return traces
    
    def _parse_raw_mythril_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse raw Mythril output when JSON parsing fails"""
        issues = []
        
        # Simple parsing of Mythril text output
        lines = raw_output.split('\n')
        current_issue = {}
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("==== "):
                # New issue
                if current_issue:
                    issues.append(current_issue)
                    current_issue = {}
                current_issue["title"] = line.replace("====", "").strip()
            
            elif line.startswith("Type:"):
                current_issue["type"] = line.split(":", 1)[1].strip()
            
            elif line.startswith("Contract:"):
                current_issue["contract"] = line.split(":", 1)[1].strip()
            
            elif line.startswith("Function name:"):
                current_issue["function"] = line.split(":", 1)[1].strip()
            
            elif line.startswith("PC address:"):
                current_issue["pc"] = line.split(":", 1)[1].strip()
            
            elif line.startswith("Description:"):
                current_issue["description"] = line.split(":", 1)[1].strip()
        
        # Add final issue
        if current_issue:
            issues.append(current_issue)
        
        return issues
    
    def _create_trace_from_issue(self, issue: Dict[str, Any], target_functions: Optional[List[str]]) -> Optional[SymbolicTrace]:
        """Create SymbolicTrace from Mythril issue"""
        
        # Extract basic information
        function_name = issue.get("function", "unknown")
        contract_name = issue.get("contract", "unknown")
        
        # Filter by target functions if specified
        if target_functions and function_name not in target_functions:
            return None
        
        # Create trace
        trace = SymbolicTrace(
            function_name=function_name,
            contract_name=contract_name,
            trace_id="",  # Will be generated
            vulnerability_type=issue.get("type", "unknown"),
            vulnerability_description=issue.get("description", "No description available")
        )
        
        # Extract execution steps if available
        if "debug" in issue:
            trace.execution_steps = self._extract_execution_steps(issue["debug"])
        
        # Extract path condition
        if "pc" in issue:
            trace.path_condition = f"PC={issue['pc']}"
        
        # Calculate exploitability score
        trace.exploitability_score = self._calculate_exploitability_score(issue)
        
        # Generate trace ID
        trace.generate_trace_id()
        
        return trace
    
    def _extract_execution_steps(self, debug_info: Any) -> List[Dict[str, Any]]:
        """Extract execution steps from Mythril debug information"""
        steps = []
        
        # This would depend on Mythril's debug output format
        # For now, create a simplified representation
        if isinstance(debug_info, list):
            for i, step in enumerate(debug_info):
                step_info = {
                    "step": i,
                    "operation": str(step),
                    "type": "execution"
                }
                steps.append(step_info)
        
        return steps
    
    def _calculate_exploitability_score(self, issue: Dict[str, Any]) -> float:
        """Calculate exploitability score for a symbolic trace"""
        score = 0.0
        
        # Base score from vulnerability type
        vuln_type = issue.get("type", "").lower()
        if "reentrancy" in vuln_type:
            score += 0.8
        elif "integer" in vuln_type or "overflow" in vuln_type:
            score += 0.7
        elif "unchecked" in vuln_type:
            score += 0.6
        elif "assert" in vuln_type:
            score += 0.5
        else:
            score += 0.3
        
        # Adjust based on description content
        description = issue.get("description", "").lower()
        if "external call" in description:
            score += 0.1
        if "state change" in description:
            score += 0.1
        if "ether" in description or "value" in description:
            score += 0.1
        
        return min(1.0, score)
    
    def _meets_severity_threshold(self, finding: Any) -> bool:
        """Check if finding meets severity threshold for symbolic analysis"""
        if not hasattr(finding, 'severity'):
            return False
        
        # Convert threshold to severity enum
        from ..core.models import Severity
        try:
            threshold_severity = Severity.from_string(self.config.trigger_min_severity)
            return finding.severity.score >= threshold_severity.score
        except ValueError:
            return False
    
    def _check_mythril_availability(self) -> bool:
        """Check if Mythril is available in the system"""
        try:
            result = subprocess.run(
                ["myth", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def get_budget_summary(self) -> Dict[str, Any]:
        """Get summary of budget consumption"""
        return {
            "total_time_budget": self.budget_tracker.total_time_budget,
            "total_time_used": self.budget_tracker.total_time_used,
            "time_remaining": max(0, self.budget_tracker.total_time_budget - self.budget_tracker.total_time_used),
            "functions_analyzed": self.budget_tracker.functions_analyzed,
            "max_functions": self.budget_tracker.max_functions,
            "budget_exhausted": (
                self.budget_tracker.total_time_used >= self.budget_tracker.total_time_budget or
                self.budget_tracker.functions_analyzed >= self.budget_tracker.max_functions
            )
        }