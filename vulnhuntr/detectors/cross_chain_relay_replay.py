"""
Cross-Chain Relay Replay Detector - detects replay attack vulnerabilities in cross-chain protocols.
"""
from __future__ import annotations

import re
from typing import Iterator, List, Dict

from ..core.models import Finding, ScanContext, Severity
from .base import HeuristicDetector


class CrossChainRelayReplayDetector(HeuristicDetector):
    """
    Detects cross-chain replay attack vulnerabilities.
    
    This detector identifies:
    - Missing nonce validation in cross-chain messages
    - Chain ID validation issues
    - Signature replay vulnerabilities
    - Bridge message validation problems
    - Insufficient relay validation
    """
    
    name = "cross_chain_relay_replay"
    description = "Detects cross-chain replay attack vulnerabilities"
    severity = Severity.HIGH
    category = "cross_chain"
    cwe_id = "CWE-294"  # Authentication Bypass by Capture-replay
    confidence = 0.75
    
    def __init__(self):
        super().__init__()
        self.tags.add("cross_chain")
        self.tags.add("replay")
        self.tags.add("bridge")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/",
            "https://blog.openzeppelin.com/arbitrary-address-spoofing-vulnerability-eip712-signed-messages/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for cross-chain replay vulnerabilities."""
        
        # Pattern 1: Cross-chain message without nonce validation
        self.add_pattern(
            r"(bridge|relay|cross|message).*(?!nonce|sequence|id)",
            "Cross-chain message missing nonce validation",
            "Cross-chain message processing lacks nonce or sequence validation",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Chain ID not validated in signature verification
        self.add_pattern(
            r"(ecrecover|recover|verify).*(?!chainId|chain_id)",
            "Signature verification missing chain ID",
            "Signature verification doesn't include chain ID validation",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 3: Bridge function without proper message hash validation
        self.add_pattern(
            r"function\s+(\w*bridge\w*|\w*relay\w*)\s*\([^)]*\).*(?!hash|digest)",
            "Bridge function missing message hash validation",
            "Bridge function doesn't properly validate message hash",
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 4: Cross-chain call without destination validation
        self.add_pattern(
            r"(sendMessage|relayMessage|crossChainCall).*(?!require.*destination|assert.*target)",
            "Cross-chain call missing destination validation",
            "Cross-chain call doesn't validate destination address or chain",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 5: Message replay without used message tracking
        self.add_pattern(
            r"processMessage.*(?!used|processed|executed|consumed)",
            "Message processing without replay protection",
            "Message processing lacks replay protection mechanism",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 6: Cross-chain signature without domain separator
        self.add_pattern(
            r"(sign|signature).*cross.*(?!domain|separator|EIP712)",
            "Cross-chain signature missing domain separator",
            "Cross-chain signature verification lacks proper domain separation",
            confidence=0.9,
            severity=Severity.HIGH
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*cross")
        self.add_exclusion_pattern(r"require.*nonce.*>")
        self.add_exclusion_pattern(r"mapping.*used.*messages")
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with cross-chain specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced cross-chain analysis
        for contract in context.contracts:
            yield from self._analyze_bridge_functions(contract, context)
            yield from self._analyze_signature_verification(contract, context)
            yield from self._analyze_message_validation(contract, context)
            yield from self._analyze_nonce_mechanisms(contract, context)
    
    def _analyze_bridge_functions(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze bridge function implementations."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find bridge/relay functions
        bridge_pattern = re.compile(
            r"function\s+(\w*bridge\w*|\w*relay\w*|\w*cross\w*)\s*\([^)]*\)\s*.*?\{(.*?)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in bridge_pattern.finditer(content):
            func_name = match.group(1)
            func_body = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for chain ID validation
            if not self._has_chain_id_validation(func_body):
                yield self.create_finding(
                    title="Bridge function missing chain ID validation",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Bridge function doesn't validate source or destination chain ID",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.HIGH
                )
            
            # Check for message uniqueness validation
            if not self._has_message_uniqueness_check(func_body):
                yield self.create_finding(
                    title="Bridge function missing message uniqueness check",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Bridge function lacks message uniqueness validation to prevent replay",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.9,
                    severity=Severity.HIGH
                )
            
            # Check for proper authorization
            if not self._has_proper_authorization(func_body):
                yield self.create_finding(
                    title="Bridge function missing proper authorization",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Bridge function lacks proper authorization mechanisms",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
    
    def _analyze_signature_verification(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze signature verification in cross-chain context."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find signature verification calls
        sig_verify_pattern = re.compile(
            r"(ecrecover|recover|verify|keccak256).*\((.*?)\)",
            re.IGNORECASE
        )
        
        for match in sig_verify_pattern.finditer(content):
            params = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if chain ID is included in hash
            if "chainid" not in params.lower() and "chain_id" not in params.lower():
                # Look for cross-chain context
                context_before = content[max(0, match.start()-200):match.start()]
                context_after = content[match.end():match.end()+200]
                full_context = context_before + match.group(0) + context_after
                
                if any(keyword in full_context.lower() for keyword in ['bridge', 'cross', 'relay', 'message']):
                    yield self.create_finding(
                        title="Cross-chain signature verification missing chain ID",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description="Signature verification in cross-chain context doesn't include chain ID",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
    
    def _analyze_message_validation(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze message validation mechanisms."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for message processing functions
        message_funcs = re.finditer(
            r"function\s+(\w*message\w*|\w*process\w*)\s*\([^)]*\)\s*.*?\{(.*?)\}",
            content,
            re.IGNORECASE | re.DOTALL
        )
        
        for match in message_funcs:
            func_name = match.group(1)
            func_body = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for timestamp validation
            if not self._has_timestamp_validation(func_body):
                yield self.create_finding(
                    title="Message processing missing timestamp validation",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Message processing doesn't validate timestamp to prevent old message replay",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.6,
                    severity=Severity.MEDIUM
                )
            
            # Check for message size validation
            if not self._has_size_validation(func_body):
                yield self.create_finding(
                    title="Message processing missing size validation",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Message processing lacks size validation which could lead to DoS",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.5,
                    severity=Severity.LOW
                )
    
    def _analyze_nonce_mechanisms(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze nonce/sequence number mechanisms."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for nonce-related state variables
        nonce_vars = self._find_nonce_variables(content)
        
        if not nonce_vars and self._has_cross_chain_functionality(content):
            yield self.create_finding(
                title="Cross-chain contract missing nonce mechanism",
                file_path=contract.file_path,
                line=1,
                code="contract " + contract.name,
                description="Cross-chain contract lacks nonce or sequence number mechanism for replay protection",
                contract_name=contract.name,
                confidence=0.7,
                severity=Severity.HIGH
            )
        
        # Check nonce increment patterns
        for var in nonce_vars:
            increment_pattern = rf"{var}\s*\+\+|{var}\s*\+=\s*1|\+\+{var}"
            if not re.search(increment_pattern, content, re.IGNORECASE):
                yield self.create_finding(
                    title=f"Nonce variable {var} never incremented",
                    file_path=contract.file_path,
                    line=1,
                    code=f"nonce variable: {var}",
                    description=f"Nonce variable {var} is declared but never incremented",
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.MEDIUM
                )
    
    def _has_chain_id_validation(self, func_body: str) -> bool:
        """Check if function validates chain ID."""
        chain_patterns = [
            r"chainid|chain_id",
            r"block\.chainid",
            r"getChainId",
            r"require.*chain"
        ]
        
        for pattern in chain_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_message_uniqueness_check(self, func_body: str) -> bool:
        """Check if function validates message uniqueness."""
        uniqueness_patterns = [
            r"used\s*\[.*\]|processed\s*\[.*\]|executed\s*\[.*\]",
            r"require.*!used|require.*!processed|require.*!executed",
            r"messageHash.*used|messageHash.*processed",
            r"nonce.*>=|sequence.*>="
        ]
        
        for pattern in uniqueness_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_proper_authorization(self, func_body: str) -> bool:
        """Check if function has proper authorization."""
        auth_patterns = [
            r"require.*msg\.sender",
            r"onlyRelayer|onlyBridge|onlyValidator",
            r"authorized|permitted|allowed",
            r"signature.*verify|ecrecover"
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_timestamp_validation(self, func_body: str) -> bool:
        """Check if function validates timestamps."""
        timestamp_patterns = [
            r"block\.timestamp",
            r"now\s*[<>]",
            r"timestamp.*[<>]",
            r"expire|expiry|deadline"
        ]
        
        for pattern in timestamp_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_size_validation(self, func_body: str) -> bool:
        """Check if function validates message size."""
        size_patterns = [
            r"length.*[<>]",
            r"size.*[<>]", 
            r"require.*\.length",
            r"bytes.*length"
        ]
        
        for pattern in size_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _find_nonce_variables(self, content: str) -> List[str]:
        """Find nonce-related state variables."""
        nonce_pattern = re.compile(
            r"\b(nonce|sequence|counter|index)\w*\s+\w+",
            re.IGNORECASE
        )
        
        variables = []
        for match in nonce_pattern.finditer(content):
            # Extract variable name
            parts = match.group(0).split()
            if len(parts) >= 2:
                variables.append(parts[-1])
        
        return variables
    
    def _has_cross_chain_functionality(self, content: str) -> bool:
        """Check if contract has cross-chain functionality."""
        cross_chain_keywords = [
            'bridge', 'relay', 'cross', 'message', 'portal',
            'gateway', 'channel', 'tunnel', 'connector'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in cross_chain_keywords)