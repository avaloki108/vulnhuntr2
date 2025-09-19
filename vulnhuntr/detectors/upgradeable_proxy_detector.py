"""
Detector for upgradeable proxy anti-patterns.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class UpgradeableProxyDetector(BaseDetector):
    """
    Detects upgradeable proxy anti-patterns including storage gaps,
    missing initializer modifiers, and unsafe upgrade patterns.
    """

    name = "upgradeable_proxy"
    description = "Detects upgradeable proxy anti-patterns and storage layout issues"
    severity = Severity.HIGH
    category = "proxy"
    cwe_id = "CWE-664"  # Improper Control of a Resource Through its Lifetime
    confidence = 0.8

    stability = "experimental"
    maturity = "beta"
    requires_slither = True  # Would benefit from Slither's inheritance analysis
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for upgradeable proxy issues.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for proxy-related issues.
        """
        # Check for missing initializer modifier
        if self._is_initializer_function(func) and not self._has_initializer_modifier(func):
            yield Finding(
                detector=self.name,
                title="Missing Initializer Modifier",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.CRITICAL,
                code=f"Function {func.name} is initializer without modifier",
                description="Initializer functions must have initializer modifier to prevent re-initialization",
                recommendation="Add initializer modifier to prevent multiple initialization",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for storage gaps
        if self._has_storage_gap_issues(func):
            yield Finding(
                detector=self.name,
                title="Storage Gap Issues",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} has storage gap issues",
                description="Storage gaps prevent storage collision during upgrades",
                recommendation="Add __gap array to reserve storage slots for future upgrades",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for unsafe upgrade pattern
        if self._has_unsafe_upgrade_pattern(func):
            yield Finding(
                detector=self.name,
                title="Unsafe Upgrade Pattern",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} has unsafe upgrade pattern",
                description="Upgrade functions should validate new implementation",
                recommendation="Add validation for new implementation address",
                confidence=0.8,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for missing renounce ownership
        if self._should_have_renounce_ownership(func):
            yield Finding(
                detector=self.name,
                title="Missing Renounce Ownership Pattern",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} should implement renounce ownership",
                description="Upgradeable contracts should have renounceOwnership disabled",
                recommendation="Override renounceOwnership to revert or implement proper access control",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _is_initializer_function(self, func: Function) -> bool:
        """
        Check if function is an initializer.
        """
        initializer_indicators = [
            'initialize', 'init', '__init', 'setup'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in initializer_indicators)

    def _has_initializer_modifier(self, func: Function) -> bool:
        """
        Check if function has initializer modifier.
        """
        if hasattr(func, 'modifiers') and func.modifiers:
            return 'initializer' in [mod.lower() for mod in func.modifiers]

        return False

    def _has_storage_gap_issues(self, func: Function) -> bool:
        """
        Check for storage gap issues.
        """
        # Heuristic: upgradeable contracts should have gap variables
        upgrade_indicators = ['upgrade', 'proxy', 'implementation']

        func_name_lower = func.name.lower()
        is_upgrade_related = any(indicator in func_name_lower for indicator in upgrade_indicators)

        # Check if contract has storage gap (this would need better analysis)
        return is_upgrade_related

    def _has_unsafe_upgrade_pattern(self, func: Function) -> bool:
        """
        Check for unsafe upgrade patterns.
        """
        upgrade_indicators = ['upgrade', 'setImplementation', 'setProxy']

        func_name_lower = func.name.lower()
        is_upgrade_function = any(indicator in func_name_lower for indicator in upgrade_indicators)

        # Unsafe if upgrade function doesn't validate input
        return is_upgrade_function and len(func.external_calls) == 0

    def _should_have_renounce_ownership(self, func: Function) -> bool:
        """
        Check if contract should have renounce ownership disabled.
        """
        ownership_indicators = ['owner', 'ownership', 'Ownable']

        # Check if contract seems to be ownable/upgradeable
        func_name_lower = func.name.lower()
        has_ownership = any(indicator in func_name_lower for indicator in ownership_indicators)

        return has_ownership and 'upgrade' in func_name_lower