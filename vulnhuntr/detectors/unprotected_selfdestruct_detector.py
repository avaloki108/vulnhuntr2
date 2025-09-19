"""
Detector for unprotected selfdestruct vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class UnprotectedSelfdestructDetector(BaseDetector):
    """
    Detects unprotected selfdestruct operations that can lead to
    accidental or malicious contract destruction.
    """

    name = "unprotected_selfdestruct"
    description = "Detects unprotected selfdestruct operations"
    severity = Severity.CRITICAL
    category = "selfdestruct"
    cwe_id = "CWE-284"  # Improper Access Control
    confidence = 0.95

    stability = "stable"
    maturity = "stable"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for unprotected selfdestruct.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for selfdestruct issues.
        """
        # Check for selfdestruct operations
        if self._has_selfdestruct(func):
            if not self._has_access_control(func):
                yield Finding(
                    detector=self.name,
                    title="Unprotected Selfdestruct",
                    file=func.file_path,
                    line=func.line_start,
                    severity=Severity.CRITICAL,
                    code=f"Function {func.name} contains unprotected selfdestruct",
                    description="Selfdestruct can permanently destroy the contract and should be protected",
                    recommendation="Add onlyOwner modifier or multi-signature requirement for selfdestruct",
                    confidence=self.confidence,
                    contract_name=func.contract_name,
                    function_name=func.name
                )
            else:
                # Even with access control, warn about selfdestruct usage
                yield Finding(
                    detector=self.name,
                    title="Selfdestruct Operation Detected",
                    file=func.file_path,
                    line=func.line_start,
                    severity=Severity.MEDIUM,
                    code=f"Function {func.name} contains selfdestruct operation",
                    description="Selfdestruct permanently destroys the contract - use with extreme caution",
                    recommendation="Consider using pause/unpause pattern instead of selfdestruct",
                    confidence=0.8,
                    contract_name=func.contract_name,
                    function_name=func.name
                )

        # Check for indirect selfdestruct through delegatecall
        if self._has_indirect_selfdestruct(func):
            yield Finding(
                detector=self.name,
                title="Indirect Selfdestruct Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} may trigger selfdestruct indirectly",
                description="Delegatecall may execute selfdestruct in target contract",
                recommendation="Audit delegatecall targets for selfdestruct operations",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _has_selfdestruct(self, func: Function) -> bool:
        """
        Check if function contains selfdestruct operation.
        """
        selfdestruct_indicators = [
            'selfdestruct', 'suicide', 'kill', 'destroy'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in selfdestruct_indicators)

    def _has_access_control(self, func: Function) -> bool:
        """
        Check if function has access control.
        """
        access_patterns = [
            'onlyOwner', 'onlyowner', 'ownerOnly',
            'hasRole', 'checkRole', 'requireRole',
            'modifier', 'auth', 'authorized'
        ]

        # Check function modifiers
        if hasattr(func, 'modifiers') and func.modifiers:
            for modifier in func.modifiers:
                if any(pattern in modifier.lower() for pattern in access_patterns):
                    return True

        return False

    def _has_indirect_selfdestruct(self, func: Function) -> bool:
        """
        Check for indirect selfdestruct through delegatecall.
        """
        # Heuristic: functions that use delegatecall and have destruction-related names
        destroy_indicators = ['destroy', 'kill', 'terminate', 'shutdown']

        func_name_lower = func.name.lower()
        has_destroy_name = any(indicator in func_name_lower for indicator in destroy_indicators)
        has_delegatecall = 'delegate' in func_name_lower

        return has_destroy_name and has_delegatecall