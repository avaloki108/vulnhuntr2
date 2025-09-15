"""
Domain Separator Reuse Detector - detects EIP-712 domain separator vulnerabilities.
"""
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import HeuristicDetector


@register
class DomainSeparatorReuseDetector(HeuristicDetector):
    """
    Detects EIP-712 domain separator reuse and related vulnerabilities.
    
    This detector identifies:
    - Missing chain ID in domain separator construction
    - Hardcoded domain separators that don't update on fork
    - Domain separator collision risks
    - Missing contract address in domain separator
    - Signature replay across different contracts/chains
    """
    
    name = "domain_separator_reuse"
    description = "Detects EIP-712 domain separator vulnerabilities and signature replay risks"
    severity = Severity.MEDIUM
    category = "cryptography"
    cwe_id = "CWE-294"  # Authentication Bypass by Capture-replay
    confidence = 0.7
    
    def __init__(self):
        super().__init__()
        self.tags.add("eip712")
        self.tags.add("domain_separator")
        self.tags.add("signature")
        self.references = [
            "https://eips.ethereum.org/EIPS/eip-712",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for domain separator vulnerabilities."""
        
        # Pattern 1: Domain separator without chain ID
        self.add_pattern(
            r"DOMAIN_SEPARATOR.*(?!chainId|chain_id|block\.chainid)",
            "Domain separator missing chain ID",
            "Domain separator construction doesn't include chain ID for replay protection",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Hardcoded domain separator
        self.add_pattern(
            r"DOMAIN_SEPARATOR\s*=\s*0x[a-fA-F0-9]{64}",
            "Hardcoded domain separator",
            "Domain separator is hardcoded and won't update on chain forks",
            confidence=0.9,
            severity=Severity.MEDIUM
        )
        
        # Pattern 3: Domain separator without contract address
        self.add_pattern(
            r"keccak256.*EIP712Domain.*(?!address\(this\)|address)",
            "Domain separator missing contract address",
            "Domain separator doesn't include contract address, allowing cross-contract replay",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 4: EIP-712 signature verification without domain separator
        self.add_pattern(
            r"(ecrecover|recover).*hash.*(?!DOMAIN_SEPARATOR)",
            "EIP-712 signature without domain separator",
            "Signature verification doesn't use proper domain separator",
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 5: Domain separator computed in constructor only
        self.add_pattern(
            r"constructor.*DOMAIN_SEPARATOR.*(?!function.*DOMAIN_SEPARATOR)",
            "Domain separator only computed in constructor",
            "Domain separator computed only once in constructor, not updated on forks",
            confidence=0.5,
            severity=Severity.LOW
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*domain")
        self.add_exclusion_pattern(r"block\.chainid")
        self.add_exclusion_pattern(r"address\(this\)")
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with domain separator specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced domain separator analysis
        for contract in context.contracts:
            yield from self._analyze_eip712_implementation(contract, context)
            yield from self._analyze_signature_verification(contract, context)
            yield from self._analyze_domain_separator_construction(contract, context)
    
    def _analyze_eip712_implementation(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze EIP-712 implementation for security issues."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for EIP-712 implementations
        eip712_pattern = re.compile(
            r"(EIP712|eip712|_domainSeparatorV4|DOMAIN_SEPARATOR)",
            re.IGNORECASE
        )
        
        if not eip712_pattern.search(content):
            return  # No EIP-712 usage detected
        
        # Check for proper domain separator components
        required_components = {
            'name': r'name',
            'version': r'version', 
            'chainId': r'(chainId|chain_id|block\.chainid)',
            'verifyingContract': r'(address\(this\)|verifyingContract)'
        }
        
        missing_components = []
        for component, pattern in required_components.items():
            if not re.search(pattern, content, re.IGNORECASE):
                missing_components.append(component)
        
        if missing_components:
            yield self.create_finding(
                title=f"Domain separator missing components: {', '.join(missing_components)}",
                file_path=contract.file_path,
                line=1,
                code="EIP-712 implementation",
                description=f"Domain separator lacks required components: {', '.join(missing_components)}",
                contract_name=contract.name,
                confidence=0.8,
                severity=Severity.MEDIUM
            )
    
    def _analyze_signature_verification(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze signature verification patterns."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find signature verification functions
        verify_pattern = re.compile(
            r"function\s+(\w*verify\w*|\w*check\w*)\s*\([^)]*\)\s*.*?\{(.*?)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in verify_pattern.finditer(content):
            func_name = match.group(1)
            func_body = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if function uses ecrecover
            if re.search(r"ecrecover|recover", func_body, re.IGNORECASE):
                # Check if domain separator is used
                if not re.search(r"DOMAIN_SEPARATOR|domainSeparator", func_body, re.IGNORECASE):
                    yield self.create_finding(
                        title="Signature verification without domain separator",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:200],
                        description="Signature verification function doesn't use domain separator for EIP-712 compliance",
                        function_name=func_name,
                        contract_name=contract.name,
                        confidence=0.7,
                        severity=Severity.MEDIUM
                    )
                
                # Check for nonce usage
                if not re.search(r"nonce|sequence|counter", func_body, re.IGNORECASE):
                    yield self.create_finding(
                        title="Signature verification without nonce",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:200],
                        description="Signature verification lacks nonce mechanism for replay protection",
                        function_name=func_name,
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
    
    def _analyze_domain_separator_construction(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze domain separator construction patterns."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for domain separator construction
        separator_pattern = re.compile(
            r"DOMAIN_SEPARATOR\s*=.*keccak256\s*\((.*?)\)",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in separator_pattern.finditer(content):
            construction = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for dynamic chain ID usage
            if "block.chainid" not in construction.lower() and "chainid" not in construction.lower():
                yield self.create_finding(
                    title="Domain separator uses static chain ID",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Domain separator construction doesn't use dynamic chain ID",
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.MEDIUM
                )
            
            # Check for contract address inclusion
            if "address(this)" not in construction and "verifyingContract" not in construction:
                yield self.create_finding(
                    title="Domain separator missing contract address",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Domain separator doesn't include contract address for proper isolation",
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
        
        # Check for domain separator caching issues
        cache_pattern = re.compile(
            r"(private|internal).*DOMAIN_SEPARATOR.*(?!function)",
            re.IGNORECASE
        )
        
        cached_separator = cache_pattern.search(content)
        if cached_separator:
            # Look for fork handling
            if not re.search(r"getChainId|chainid.*!=|fork", content, re.IGNORECASE):
                line_num = content[:cached_separator.start()].count('\n') + 1
                yield self.create_finding(
                    title="Cached domain separator without fork handling",
                    file_path=contract.file_path,
                    line=line_num,
                    code=cached_separator.group(0),
                    description="Cached domain separator doesn't handle chain forks properly",
                    contract_name=contract.name,
                    confidence=0.6,
                    severity=Severity.LOW
                )