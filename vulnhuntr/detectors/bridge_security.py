"""
Bridge security detector for cross-chain vulnerabilities.
"""
from typing import Iterator, Dict, Any
import re

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import BaseDetector


@register
class BridgeSecurityDetector(BaseDetector):
    """
    Detects security vulnerabilities in cross-chain bridge implementations.
    
    Covers:
    - Centralized bridge authorities
    - Weak signature verification
    - Insufficient finality checks
    - Cross-chain replay attacks
    - Bridge token minting/burning issues
    """

    name = "Bridge Security Vulnerabilities"
    description = "Detects cross-chain bridge security issues"
    severity = Severity.HIGH
    confidence = 0.8

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Analyze contracts for bridge security vulnerabilities."""
        for contract in context.contracts:
            yield from self._check_centralized_bridge_authority(contract, context)
            yield from self._check_weak_signature_verification(contract, context)
            yield from self._check_finality_requirements(contract, context)
            yield from self._check_cross_chain_replay_protection(contract, context)
            yield from self._check_bridge_token_security(contract, context)

    def _check_centralized_bridge_authority(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Check for centralized bridge authority patterns."""
        # Look for single authority patterns
        authority_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
            r'single.*validator',
            r'trusted.*relayer'
        ]
        
        for func in context.functions:
            if func.contract_name != contract.name:
                continue
                
            # Check for bridge-related functions with single authority
            if any(keyword in func.name.lower() for keyword in ['bridge', 'relay', 'mint', 'burn', 'deposit', 'withdraw']):
                for pattern in authority_patterns:
                    if re.search(pattern, func.signature, re.IGNORECASE):
                        yield Finding(
                            detector=self.name,
                            title="Centralized Bridge Authority",
                            file=func.file_path,
                            line=func.line_start,
                            severity=Severity.HIGH,
                            code=func.signature,
                            description=f"Function {func.name} in bridge contract uses centralized authority control",
                            recommendation="""Implement multi-signature validation or decentralized consensus:
1. Use multi-sig wallets for critical bridge operations
2. Implement validator set with minimum threshold requirements
3. Add time delays for authority changes
4. Consider using decentralized oracle networks for cross-chain verification""",
                            confidence=0.9,
                            contract_name=contract.name,
                            function_name=func.name
                        )

    def _check_weak_signature_verification(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Check for weak signature verification in bridge operations."""
        weak_sig_patterns = [
            r'ecrecover\s*\(',
            r'recover\s*\(',
            r'verify.*single',
            r'signature\s*==',
            r'\.call\s*\(',  # Potential unsafe external calls
        ]
        
        for func in context.functions:
            if func.contract_name != contract.name:
                continue
                
            # Focus on verification or validation functions
            if any(keyword in func.name.lower() for keyword in ['verify', 'validate', 'check', 'confirm']):
                for pattern in weak_sig_patterns:
                    if re.search(pattern, func.signature, re.IGNORECASE):
                        yield Finding(
                            detector=self.name,
                            title="Weak Signature Verification",
                            file=func.file_path,
                            line=func.line_start,
                            severity=Severity.HIGH,
                            code=func.signature,
                            description=f"Function {func.name} may use weak signature verification patterns",
                            recommendation="""Strengthen signature verification:
1. Use cryptographically secure signature schemes (ECDSA with proper nonce handling)
2. Implement signature aggregation for multiple validators
3. Add replay protection with nonces or timestamps
4. Validate signature parameters (r, s, v values)
5. Use established libraries like OpenZeppelin's cryptography utilities""",
                            confidence=0.75,
                            contract_name=contract.name,
                            function_name=func.name
                        )

    def _check_finality_requirements(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Check for proper finality requirements in cross-chain operations."""
        finality_indicators = [
            r'block\.number',
            r'finality',
            r'confirmation',
            r'depth',
            r'wait.*block'
        ]
        
        missing_finality_patterns = [
            r'immediate.*process',
            r'instant.*bridge',
            r'no.*wait',
            r'single.*block'
        ]
        
        for func in context.functions:
            if func.contract_name != contract.name:
                continue
                
            # Check bridge processing functions
            if any(keyword in func.name.lower() for keyword in ['process', 'execute', 'relay', 'bridge']):
                has_finality_check = any(re.search(pattern, func.signature, re.IGNORECASE) 
                                       for pattern in finality_indicators)
                has_risky_pattern = any(re.search(pattern, func.signature, re.IGNORECASE) 
                                      for pattern in missing_finality_patterns)
                
                if has_risky_pattern or not has_finality_check:
                    yield Finding(
                        detector=self.name,
                        title="Insufficient Finality Requirements",
                        file=func.file_path,
                        line=func.line_start,
                        severity=Severity.MEDIUM,
                        code=func.signature,
                        description=f"Function {func.name} may not properly check transaction finality before processing",
                        recommendation="""Implement proper finality checks:
1. Wait for sufficient block confirmations based on source chain characteristics
2. Use finality-aware block depth requirements (12+ blocks for Ethereum)
3. Implement exponential backoff for finality checking
4. Consider probabilistic finality for chains without deterministic finality
5. Add emergency halt mechanisms for deep reorganizations""",
                        confidence=0.7,
                        contract_name=contract.name,
                        function_name=func.name
                    )

    def _check_cross_chain_replay_protection(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Check for cross-chain replay attack protection."""
        replay_protection_patterns = [
            r'nonce',
            r'chain.*id',
            r'chainId',
            r'network.*id',
            r'sequence',
            r'used.*hash'
        ]
        
        for func in context.functions:
            if func.contract_name != contract.name:
                continue
                
            # Check message processing functions
            if any(keyword in func.name.lower() for keyword in ['process', 'execute', 'relay', 'handle']):
                has_replay_protection = any(re.search(pattern, func.signature, re.IGNORECASE) 
                                          for pattern in replay_protection_patterns)
                
                if not has_replay_protection:
                    yield Finding(
                        detector=self.name,
                        title="Missing Cross-Chain Replay Protection",
                        file=func.file_path,
                        line=func.line_start,
                        severity=Severity.HIGH,
                        code=func.signature,
                        description=f"Function {func.name} lacks replay protection for cross-chain messages",
                        recommendation="""Implement replay protection:
1. Include chain ID in message hashing to prevent cross-chain replays
2. Use incrementing nonces for message ordering and uniqueness
3. Store processed message hashes to prevent double processing
4. Implement message expiration timestamps
5. Use domain separator patterns to isolate different message types""",
                        confidence=0.85,
                        contract_name=contract.name,
                        function_name=func.name
                    )

    def _check_bridge_token_security(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Check for bridge token minting/burning security issues."""
        token_patterns = [
            r'mint\s*\(',
            r'burn\s*\(',
            r'totalSupply',
            r'balanceOf',
            r'transfer'
        ]
        
        security_check_patterns = [
            r'require\s*\(',
            r'assert\s*\(',
            r'onlyBridge',
            r'onlyMinter',
            r'whenNotPaused'
        ]
        
        for func in context.functions:
            if func.contract_name != contract.name:
                continue
                
            # Check token manipulation functions
            if any(re.search(pattern, func.signature, re.IGNORECASE) for pattern in token_patterns):
                has_security_checks = any(re.search(pattern, func.signature, re.IGNORECASE) 
                                        for pattern in security_check_patterns)
                
                if any(keyword in func.name.lower() for keyword in ['mint', 'burn']) and not has_security_checks:
                    yield Finding(
                        detector=self.name,
                        title="Unsafe Bridge Token Operations",
                        file=func.file_path,
                        line=func.line_start,
                        severity=Severity.CRITICAL,
                        code=func.signature,
                        description=f"Function {func.name} performs token operations without adequate security checks",
                        recommendation="""Secure bridge token operations:
1. Implement strict access controls for mint/burn functions
2. Add total supply validation to prevent inflation attacks
3. Use pausable patterns for emergency situations
4. Implement rate limiting for large operations
5. Add cross-chain supply consistency checks
6. Use reentrancy guards for external calls
7. Validate burn amounts against actual balances""",
                        confidence=0.9,
                        contract_name=contract.name,
                        function_name=func.name
                    )

    def get_bridge_risk_assessment(self, context: ScanContext) -> Dict[str, Any]:
        """
        Assess overall bridge security risk level.
        """
        findings = list(self.analyze(context))
        
        # Categorize findings by risk type
        authority_risks = [f for f in findings if "Centralized" in f.title]
        signature_risks = [f for f in findings if "Signature" in f.title] 
        finality_risks = [f for f in findings if "Finality" in f.title]
        replay_risks = [f for f in findings if "Replay" in f.title]
        token_risks = [f for f in findings if "Token" in f.title]
        
        # Calculate risk scores
        total_critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        total_high = len([f for f in findings if f.severity == Severity.HIGH])
        total_medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        
        overall_risk = "LOW"
        if total_critical > 0:
            overall_risk = "CRITICAL"
        elif total_high > 2:
            overall_risk = "HIGH"
        elif total_high > 0 or total_medium > 3:
            overall_risk = "MEDIUM"
            
        return {
            "overall_risk": overall_risk,
            "total_findings": len(findings),
            "risk_breakdown": {
                "authority_centralization": len(authority_risks),
                "signature_weaknesses": len(signature_risks),
                "finality_issues": len(finality_risks),
                "replay_vulnerabilities": len(replay_risks),
                "token_security": len(token_risks)
            },
            "severity_distribution": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium
            },
            "recommendations": {
                "immediate": [
                    "Implement multi-signature validation",
                    "Add cross-chain replay protection",
                    "Secure token mint/burn operations"
                ],
                "short_term": [
                    "Add finality checking mechanisms",
                    "Implement emergency pause functionality",
                    "Add comprehensive access controls"
                ],
                "long_term": [
                    "Consider decentralized validator networks",
                    "Implement formal verification",
                    "Add comprehensive monitoring and alerting"
                ]
            }
        }