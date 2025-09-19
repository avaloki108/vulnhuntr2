"""
Detector for gas griefing vulnerabilities and unbounded loops.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class GasGriefingDetector(BaseDetector):
    """
    Detects potential gas griefing attacks through unbounded loops
    and gas-sensitive branching patterns.
    """
    
    name = "gas_griefing"
    description = "Detects unbounded loops and gas-sensitive operations that could enable griefing attacks"
    severity = Severity.MEDIUM
    category = "gas"
    cwe_id = "CWE-400"  # Uncontrolled Resource Consumption
    confidence = 0.7
    
    stability = "experimental"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for gas griefing vulnerabilities.
        """
        for func in context.functions:
            yield from self._analyze_function(func)
    
    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for gas griefing patterns.
        """
        # Check for unbounded loops based on function characteristics
        if self._has_unbounded_loop(func):
            yield Finding(
                detector=self.name,
                title="Unbounded Loop Detected",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Unbounded loop in {func.name}",
                description="Unbounded loop may enable gas griefing attacks by consuming excessive gas",
                recommendation="Consider adding loop bounds or gas limits to prevent griefing attacks",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )
        
        # Check for gas-sensitive patterns based on function attributes
        if self._is_gas_sensitive(func):
            yield Finding(
                detector=self.name,
                title="Gas-Sensitive Function",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.LOW,
                code=f"Gas-sensitive operations in {func.name}",
                description="Function contains operations that may be sensitive to gas costs",
                recommendation="Consider using gas-independent logic or adding gas limits",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )
    
    def _has_unbounded_loop(self, func: Function) -> bool:
        """
        Check if function likely contains unbounded loops based on heuristics.
        """
        # Heuristic: functions with many state variable writes might have loops
        if len(func.state_vars_written) > 3:
            return True
        
        # Functions with names suggesting iteration
        loop_indicators = ['loop', 'iterate', 'batch', 'process', 'for']
        if any(indicator in func.name.lower() for indicator in loop_indicators):
            return True
            
        return False
    
    def _is_gas_sensitive(self, func: Function) -> bool:
        """
        Check if function is potentially gas-sensitive.
        """
        # Functions that make many external calls might be gas-sensitive
        if len(func.external_calls) > 2:
            return True
        
        # Functions that modify many state variables
        if len(func.state_vars_written) > 2:
            return True
            
        return False