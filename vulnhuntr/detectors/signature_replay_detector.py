"""
Detector for signature replay vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class SignatureReplayDetector(BaseDetector):
    """
    Detects signature replay vulnerabilities including missing nonce validation,
    EIP-712 misuse, and cross-chain replay attacks.
    """

    name = "signature_replay"
    description = "Detects signature replay vulnerabilities and EIP-712 misuse"
    severity = Severity.HIGH
    category = "signature"
    cwe_id = "CWE-294"  # Authentication Bypass by Capture-replay
    confidence = 0.8

    stability = "experimental"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for signature replay issues.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for signature issues.
        """
        # Check for signature verification without nonce
        if self._verifies_signature(func) and not self._uses_nonce(func):
            yield Finding(
                detector=self.name,
                title="Signature Verification Without Nonce",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} verifies signatures without nonce protection",
                description="Signatures without nonces can be replayed multiple times",
                recommendation="Add nonce parameter and track used nonces to prevent replay attacks",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for EIP-712 domain separator issues
        if self._uses_eip712(func) and not self._validates_domain_separator(func):
            yield Finding(
                detector=self.name,
                title="Weak EIP-712 Domain Separator",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} has weak EIP-712 domain separator validation",
                description="Domain separator should include contract address and chain ID",
                recommendation="Use proper domain separator with contract address and chainId",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for cross-chain replay vulnerability
        if self._vulnerable_to_cross_chain_replay(func):
            yield Finding(
                detector=self.name,
                title="Cross-Chain Signature Replay Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Function {func.name} vulnerable to cross-chain replay",
                description="Signatures may be replayed across different chains",
                recommendation="Include chainId in domain separator to prevent cross-chain replay",
                confidence=0.8,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for signature malleability
        if self._has_signature_malleability(func):
            yield Finding(
                detector=self.name,
                title="Signature Malleability Risk",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} has signature malleability risk",
                description="Signature verification may accept multiple valid signatures for same message",
                recommendation="Use ecrecover with proper validation to prevent malleability",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _verifies_signature(self, func: Function) -> bool:
        """
        Check if function verifies signatures.
        """
        signature_indicators = [
            'verify', 'signature', 'sign', 'ecrecover', 'recover',
            'validate', 'check', 'auth'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in signature_indicators)

    def _uses_nonce(self, func: Function) -> bool:
        """
        Check if function uses nonce for replay protection.
        """
        nonce_indicators = ['nonce', 'seq', 'sequence', 'counter']

        # Check if function reads nonce-related state variables
        for var in func.state_vars_read:
            if any(indicator in var.lower() for indicator in nonce_indicators):
                return True

        return False

    def _uses_eip712(self, func: Function) -> bool:
        """
        Check if function uses EIP-712 structured data.
        """
        eip712_indicators = [
            'eip712', '712', 'domain', 'separator', 'typed',
            'structured', 'hashStruct', 'encode'
        ]

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in eip712_indicators)

    def _validates_domain_separator(self, func: Function) -> bool:
        """
        Check if domain separator is properly validated.
        """
        # Heuristic: functions that use EIP-712 should have domain-related operations
        domain_indicators = ['domain', 'separator', 'chainid', 'chainId']

        func_name_lower = func.name.lower()
        return any(indicator in func_name_lower for indicator in domain_indicators)

    def _vulnerable_to_cross_chain_replay(self, func: Function) -> bool:
        """
        Check for cross-chain replay vulnerability.
        """
        # Heuristic: signature functions without chain ID validation
        return (self._verifies_signature(func) and
                not self._validates_domain_separator(func))

    def _has_signature_malleability(self, func: Function) -> bool:
        """
        Check for signature malleability issues.
        """
        # Heuristic: functions that recover signatures but don't validate properly
        recover_indicators = ['ecrecover', 'recover']

        func_name_lower = func.name.lower()
        uses_recover = any(indicator in func_name_lower for indicator in recover_indicators)

        # If it uses recover but has few validation checks
        return uses_recover and len(func.state_vars_read) <= 2