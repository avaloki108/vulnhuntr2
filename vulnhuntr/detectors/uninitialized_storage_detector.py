"""
Detector for uninitialized storage vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class UninitializedStorageDetector(BaseDetector):
    """
    Detects uninitialized storage variables and potential storage
    collision vulnerabilities in upgradeable contracts.
    """

    name = "uninitialized_storage"
    description = "Detects uninitialized storage variables and storage collision risks"
    severity = Severity.MEDIUM
    category = "storage"
    cwe_id = "CWE-909"  # Missing Initialization of Resource
    confidence = 0.7

    stability = "experimental"
    maturity = "beta"
    requires_slither = True  # Would benefit from Slither's storage analysis
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for uninitialized storage issues.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for storage issues.
        """
        # Check for potential uninitialized storage reads
        if self._reads_potentially_uninitialized_storage(func):
            yield Finding(
                detector=self.name,
                title="Potential Uninitialized Storage Read",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} may read uninitialized storage",
                description="Reading uninitialized storage can return unexpected values",
                recommendation="Initialize storage variables in constructor or explicitly check for initialization",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for storage collision in upgradeable contracts
        if self._has_storage_collision_risk(func):
            yield Finding(
                detector=self.name,
                title="Storage Collision Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} has storage collision risk",
                description="Upgradeable contracts may have storage layout conflicts",
                recommendation="Use structured storage patterns and avoid storage gaps",
                confidence=0.8,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for missing constructor initialization
        if self._missing_constructor_initialization(func):
            yield Finding(
                detector=self.name,
                title="Missing Constructor Initialization",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} may not initialize critical storage",
                description="Critical storage variables should be initialized in constructor",
                recommendation="Initialize all storage variables in constructor",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for delegatecall storage corruption
        if self._has_delegatecall_storage_risk(func):
            yield Finding(
                detector=self.name,
                title="Delegatecall Storage Corruption Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.CRITICAL,
                code=f"Function {func.name} risks storage corruption via delegatecall",
                description="Delegatecall can corrupt storage if layouts don't match",
                recommendation="Ensure identical storage layouts between contracts",
                confidence=0.9,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _reads_potentially_uninitialized_storage(self, func: Function) -> bool:
        """
        Check if function reads potentially uninitialized storage.
        """
        # Heuristic: functions that read storage but have simple logic
        return (len(func.state_vars_read) > 0 and
                len(func.state_vars_written) == 0 and
                len(func.external_calls) == 0)

    def _has_storage_collision_risk(self, func: Function) -> bool:
        """
        Check for storage collision risk in upgradeable contracts.
        """
        upgrade_indicators = ['upgrade', 'proxy', 'implementation', 'delegate']

        func_name_lower = func.name.lower()
        is_upgrade_related = any(indicator in func_name_lower for indicator in upgrade_indicators)

        # Risk if upgrade-related and modifies storage
        return is_upgrade_related and len(func.state_vars_written) > 0

    def _missing_constructor_initialization(self, func: Function) -> bool:
        """
        Check for missing constructor initialization.
        """
        # Heuristic: constructor-like functions that don't write to storage
        constructor_indicators = ['constructor', 'initialize', 'init', '__init']

        func_name_lower = func.name.lower()
        is_constructor = any(indicator in func_name_lower for indicator in constructor_indicators)

        # Flag if seems like constructor but doesn't initialize storage
        return is_constructor and len(func.state_vars_written) == 0

    def _has_delegatecall_storage_risk(self, func: Function) -> bool:
        """
        Check for delegatecall storage corruption risk.
        """
        delegate_indicators = ['delegatecall', 'delegate']

        func_name_lower = func.name.lower()
        uses_delegatecall = any(indicator in func_name_lower for indicator in delegate_indicators)

        # Risk if uses delegatecall and accesses storage
        return (uses_delegatecall and
                (len(func.state_vars_read) > 0 or len(func.state_vars_written) > 0))