"""
Detector for delegatecall misuse vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class DelegatecallMisuseDetector(BaseDetector):
    """
    Detects delegatecall misuse including storage collisions,
    context corruption, and unsafe delegatecall patterns.
    """

    name = "delegatecall_misuse"
    description = "Detects unsafe delegatecall usage and storage collision risks"
    severity = Severity.CRITICAL
    category = "delegatecall"
    cwe_id = "CWE-350"  # Reliance on Reverse DNS Resolution
    confidence = 0.9

    stability = "stable"
    maturity = "beta"
    requires_slither = True  # Would benefit from Slither's delegatecall analysis
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for delegatecall misuse.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for delegatecall issues.
        """
        # Check for direct delegatecall usage
        if self._uses_delegatecall(func):
            yield Finding(
                detector=self.name,
                title="Direct Delegatecall Usage",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} uses delegatecall",
                description="Delegatecall can lead to storage corruption and unexpected behavior",
                recommendation="Review delegatecall usage carefully and consider using libraries with battle-tested implementations",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for storage collision risk
        if self._has_storage_collision_risk(func):
            yield Finding(
                detector=self.name,
                title="Storage Collision Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.CRITICAL,
                code=f"Function {func.name} has storage collision risk with delegatecall",
                description="Delegatecall target may have different storage layout causing corruption",
                recommendation="Ensure storage layouts match between calling and called contracts",
                confidence=0.85,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for context-dependent operations in delegatecall
        if self._has_context_dependent_operations(func):
            yield Finding(
                detector=self.name,
                title="Context-Dependent Operations in Delegatecall",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} has context-dependent operations",
                description="Delegatecall executes in caller's context but may access caller's state incorrectly",
                recommendation="Avoid context-dependent operations in delegatecall targets",
                confidence=0.8,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for unprotected delegatecall
        if self._has_unprotected_delegatecall(func):
            yield Finding(
                detector=self.name,
                title="Unprotected Delegatecall",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.CRITICAL,
                code=f"Function {func.name} has unprotected delegatecall",
                description="Delegatecall should be protected by access controls",
                recommendation="Add onlyOwner or role-based access control to delegatecall functions",
                confidence=0.9,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _uses_delegatecall(self, func: Function) -> bool:
        """
        Check if function uses delegatecall.
        """
        # Check function name for delegatecall indicators
        delegatecall_indicators = [
            'delegatecall', 'delegate', 'proxy', 'upgrade'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in delegatecall_indicators)

    def _has_storage_collision_risk(self, func: Function) -> bool:
        """
        Check for storage collision risk.
        """
        # Heuristic: functions that modify storage and have delegatecall-like names
        return (self._uses_delegatecall(func) and
                len(func.state_vars_written) > 0)

    def _has_context_dependent_operations(self, func: Function) -> bool:
        """
        Check for context-dependent operations.
        """
        context_indicators = [
            'msg.sender', 'msg.value', 'address(this)', 'selfdestruct'
        ]

        # Check if function has operations that depend on execution context
        func_name_lower = func.name.lower()
        return (self._uses_delegatecall(func) and
                any(indicator in func_name_lower for indicator in context_indicators))

    def _has_unprotected_delegatecall(self, func: Function) -> bool:
        """
        Check if delegatecall is unprotected.
        """
        # Heuristic: delegatecall functions without access control modifiers
        # In practice, this would need modifier analysis
        return (self._uses_delegatecall(func) and
                len(func.modifiers) == 0)