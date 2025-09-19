"""
Detector for oracle manipulation vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class OracleManipulationDetector(BaseDetector):
    """
    Detects oracle manipulation vulnerabilities including stale price feeds,
    lack of validation, and manipulation attack surfaces.
    """

    name = "oracle_manipulation"
    description = "Detects oracle manipulation vulnerabilities and stale data risks"
    severity = Severity.HIGH
    category = "oracle"
    cwe_id = "CWE-349"  # Acceptance of Extraneous Untrusted Data With Trusted Data
    confidence = 0.75

    stability = "experimental"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for oracle manipulation vulnerabilities.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for oracle-related issues.
        """
        # Check for stale oracle data usage
        if self._uses_oracle_data(func) and not self._has_freshness_check(func):
            yield Finding(
                detector=self.name,
                title="Potential Stale Oracle Data",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} uses oracle data without freshness validation",
                description="Oracle data should be validated for freshness to prevent stale price attacks",
                recommendation="Add timestamp validation and maximum age checks for oracle data",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for single oracle dependency
        if self._depends_on_single_oracle(func):
            yield Finding(
                detector=self.name,
                title="Single Oracle Dependency",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} depends on single oracle source",
                description="Using multiple oracles reduces manipulation risk",
                recommendation="Implement oracle aggregation or use decentralized oracle networks",
                confidence=0.8,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for lack of price validation
        if self._uses_price_data(func) and not self._has_price_validation(func):
            yield Finding(
                detector=self.name,
                title="Missing Price Validation",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} uses price data without validation",
                description="Price data should be validated for reasonableness",
                recommendation="Add minimum/maximum price bounds and circuit breakers",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for flash loan attack surface
        if self._vulnerable_to_flash_loan_attack(func):
            yield Finding(
                detector=self.name,
                title="Flash Loan Oracle Manipulation Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} vulnerable to flash loan oracle manipulation",
                description="Price-dependent operations can be manipulated via flash loans",
                recommendation="Use time-weighted average prices (TWAP) or implement manipulation-resistant mechanisms",
                confidence=0.85,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _uses_oracle_data(self, func: Function) -> bool:
        """
        Check if function uses oracle data.
        """
        oracle_indicators = [
            'price', 'oracle', 'feed', 'rate', 'value', 'getPrice',
            'latestAnswer', 'latestRoundData', 'decimals'
        ]

        func_name_lower = func.name.lower()
        return any(indicator.lower() in func_name_lower for indicator in oracle_indicators)

    def _has_freshness_check(self, func: Function) -> bool:
        """
        Check if function validates data freshness.
        """
        # Heuristic: functions that read timestamps or have time-related operations
        time_indicators = ['timestamp', 'time', 'block.timestamp', 'updatedAt', 'lastUpdate']

        # Check if function reads time-related state variables
        for var in func.state_vars_read:
            if any(indicator in var.lower() for indicator in time_indicators):
                return True

        return False

    def _depends_on_single_oracle(self, func: Function) -> bool:
        """
        Check if function depends on single oracle source.
        """
        # Heuristic: functions that read from single price-related variable
        price_vars = [var for var in func.state_vars_read if 'price' in var.lower() or 'rate' in var.lower()]
        return len(price_vars) == 1 and len(func.external_calls) <= 1

    def _uses_price_data(self, func: Function) -> bool:
        """
        Check if function uses price data.
        """
        price_indicators = ['price', 'rate', 'value', 'amount', 'cost']

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in price_indicators)

    def _has_price_validation(self, func: Function) -> bool:
        """
        Check if function validates price data.
        """
        # Heuristic: functions that have multiple conditions or comparisons
        # This would need more sophisticated analysis in practice
        return len(func.state_vars_read) > 2  # Simple heuristic

    def _vulnerable_to_flash_loan_attack(self, func: Function) -> bool:
        """
        Check if function is vulnerable to flash loan oracle manipulation.
        """
        # Heuristic: functions that use price data and have external calls
        return (self._uses_price_data(func) and
                len(func.external_calls) > 0 and
                len(func.state_vars_written) > 0)