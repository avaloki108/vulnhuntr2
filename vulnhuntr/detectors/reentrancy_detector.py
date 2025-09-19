"""
Enhanced reentrancy detector that uses Slither analysis data.
"""

from typing import List, Optional

from vulnhuntr.core.models import Finding, ScanContext, Severity
from vulnhuntr.core.registry import register


@register
class ReentrancyDetector:
    """
    Detects potential reentrancy vulnerabilities in Solidity contracts.
    """
    
    name = "reentrancy_detector"
    description = "Detects potential reentrancy vulnerabilities"
    severity = Severity.HIGH
    
    def analyze(self, scan_context: ScanContext) -> List[Finding]:
        """
        Analyze contracts for reentrancy vulnerabilities.
        
        Args:
            scan_context: Analysis context with contract information
            
        Returns:
            List of reentrancy findings
        """
        findings = []
        
        for function in scan_context.functions:
            # Skip if no external calls or state variable writes
            if not function.external_calls or not function.state_vars_written:
                continue
            
            # Check if function has external calls and state variable writes
            # Classic reentrancy pattern: external call followed by state change
            if self._has_potential_reentrancy(function):
                findings.append(
                    Finding(
                        detector=self.name,
                        title="Potential Reentrancy Vulnerability",
                        file=function.file_path,
                        line=function.line_start,
                        severity=self.severity,
                        code=f"{function.contract_name}.{function.name}",
                        description=(
                            f"The function {function.name} makes external calls and "
                            f"modifies state variables, which could lead to reentrancy attacks. "
                            f"External calls: {', '.join(function.external_calls)}. "
                            f"State variables modified: {', '.join(function.state_vars_written)}."
                        ),
                        recommendation=(
                            "Consider using the checks-effects-interactions pattern or a reentrancy guard. "
                            "Make sure state changes happen before external calls."
                        ),
                        confidence=0.7,  # Not 100% confident without analyzing order of operations
                        contract_name=function.contract_name,
                        function_name=function.name,
                        references=[
                            "https://swcregistry.io/docs/SWC-107",
                            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"
                        ]
                    )
                )
        
        return findings
    
    def _has_potential_reentrancy(self, function) -> bool:
        """
        Check if a function has potential reentrancy issues.
        
        Currently using a simple heuristic: external calls + state changes.
        Future versions could analyze the order of operations, check for safeguards, etc.
        
        Args:
            function: The function to analyze
            
        Returns:
            True if potential reentrancy risk exists
        """
        # Look for any external calls that might be dangerous
        dangerous_calls = [
            call for call in function.external_calls
            if ".call" in call or ".transfer" in call or ".send" in call
        ]
        
        # Check for ReentrancyGuard usage
        has_reentrancy_guard = any(
            "nonReentrant" in modifier for modifier in function.modifiers
        )
        
        # If we have dangerous calls, state changes, and no reentrancy guard
        return bool(dangerous_calls and function.state_vars_written and not has_reentrancy_guard)