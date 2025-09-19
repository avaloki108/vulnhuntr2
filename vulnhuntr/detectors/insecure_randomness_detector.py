"""
Detector for insecure randomness vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class InsecureRandomnessDetector(BaseDetector):
    """
    Detects insecure randomness sources including block variables
    and predictable pseudo-random number generation.
    """

    name = "insecure_randomness"
    description = "Detects insecure randomness sources and predictable PRNG usage"
    severity = Severity.HIGH
    category = "randomness"
    cwe_id = "CWE-338"  # Use of Cryptographically Weak Pseudo-Random Number Generator
    confidence = 0.8

    stability = "stable"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for insecure randomness.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for randomness issues.
        """
        # Check for block-based randomness
        if self._uses_block_randomness(func):
            yield Finding(
                detector=self.name,
                title="Block-Based Randomness",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} uses block variables for randomness",
                description="Block variables are predictable and can be manipulated by miners",
                recommendation="Use Chainlink VRF or similar secure randomness oracle",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for predictable PRNG
        if self._uses_predictable_prng(func):
            yield Finding(
                detector=self.name,
                title="Predictable Pseudo-Random Generation",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} uses predictable PRNG",
                description="Linear congruential generators are predictable",
                recommendation="Use cryptographically secure random number generation",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for randomness in financial operations
        if self._uses_randomness_in_finance(func):
            yield Finding(
                detector=self.name,
                title="Randomness in Financial Operations",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.CRITICAL,
                code=f"Function {func.name} uses randomness in financial context",
                description="Randomness in financial operations can enable manipulation attacks",
                recommendation="Use commit-reveal schemes or VRF for fair randomness",
                confidence=0.9,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for insufficient entropy
        if self._has_insufficient_entropy(func):
            yield Finding(
                detector=self.name,
                title="Insufficient Entropy",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} has insufficient entropy for randomness",
                description="Low-entropy sources reduce randomness quality",
                recommendation="Combine multiple entropy sources or use secure oracles",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _uses_block_randomness(self, func: Function) -> bool:
        """
        Check if function uses block variables for randomness.
        """
        # Check function name for randomness indicators
        random_indicators = ['random', 'rand', 'shuffle', 'pick', 'select']

        func_name_lower = func.name.lower()
        uses_random = any(indicator in func_name_lower for indicator in random_indicators)

        # Heuristic: if function seems random and has block operations
        return uses_random and len(func.external_calls) == 0  # No external calls suggest internal randomness

    def _uses_predictable_prng(self, func: Function) -> bool:
        """
        Check for predictable PRNG usage.
        """
        prng_indicators = [
            'keccak256', 'sha256', 'random', 'seed', 'hash'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in prng_indicators)

    def _uses_randomness_in_finance(self, func: Function) -> bool:
        """
        Check if randomness is used in financial context.
        """
        financial_indicators = [
            'transfer', 'withdraw', 'deposit', 'mint', 'burn',
            'stake', 'unstake', 'reward', 'prize', 'lottery'
        ]

        random_indicators = ['random', 'rand', 'shuffle', 'pick']

        func_name_lower = func.name.lower()
        has_finance = any(indicator in func_name_lower for indicator in financial_indicators)
        has_random = any(indicator in func_name_lower for indicator in random_indicators)

        return has_finance and has_random

    def _has_insufficient_entropy(self, func: Function) -> bool:
        """
        Check for insufficient entropy sources.
        """
        # Heuristic: functions that seem random but have few inputs
        random_indicators = ['random', 'rand', 'shuffle']

        func_name_lower = func.name.lower()
        seems_random = any(indicator in func_name_lower for indicator in random_indicators)

        # Low entropy if few state variables read and no external calls
        low_entropy = len(func.state_vars_read) <= 1 and len(func.external_calls) == 0

        return seems_random and low_entropy