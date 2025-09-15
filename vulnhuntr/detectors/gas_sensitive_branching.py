"""
Gas Sensitive Branching Detector - detects gas-dependent conditional logic vulnerabilities.
"""
from __future__ import annotations

import re
from typing import Iterator, List

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import HeuristicDetector


@register
class GasSensitiveBranchingDetector(HeuristicDetector):
    """
    Detects gas-dependent conditional logic that can lead to inconsistent behavior.
    
    This detector identifies:
    - Conditional logic based on gas prices or gas left
    - DoS attacks through gas limit manipulation
    - Block gas limit dependent operations
    - Gas griefing vulnerabilities
    - Inconsistent behavior due to gas costs
    """
    
    name = "gas_sensitive_branching"
    description = "Detects gas-dependent conditional logic and DoS vulnerabilities"
    severity = Severity.MEDIUM
    category = "gas"
    cwe_id = "CWE-400"  # Uncontrolled Resource Consumption
    confidence = 0.75
    
    def __init__(self):
        super().__init__()
        self.tags.add("gas")
        self.tags.add("dos")
        self.tags.add("griefing")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
            "https://blog.openzeppelin.com/reentrancy-after-istanbul/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for gas-sensitive vulnerabilities."""
        
        # Pattern 1: Conditional logic based on gas left
        self.add_pattern(
            r"if\s*\(\s*gasleft\(\)\s*[<>]=?",
            "Conditional logic based on gas left",
            "Control flow depends on remaining gas which can be manipulated",
            confidence=0.9,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Gas price dependent operations
        self.add_pattern(
            r"(if|require|assert).*tx\.gasprice\s*[<>!=]=?",
            "Gas price dependent operation",
            "Operation behavior depends on gas price which can be manipulated",
            confidence=0.8,
            severity=Severity.MEDIUM
        )
        
        # Pattern 3: Block gas limit assumptions
        self.add_pattern(
            r"(gaslimit|block\.gaslimit).*[<>]=?.*\d+",
            "Block gas limit assumption",
            "Code assumes specific block gas limit which can change",
            confidence=0.7,
            severity=Severity.LOW
        )
        
        # Pattern 4: Gas stipend usage in loops
        self.add_pattern(
            r"for\s*\([^)]*\).*\{[^}]*\.call\{gas:\s*\d+\}",
            "Fixed gas stipend in loop",
            "Fixed gas stipend in loop can cause DoS if gas costs change",
            confidence=0.8,
            severity=Severity.MEDIUM
        )
        
        # Pattern 5: Large array operations without gas checks
        self.add_pattern(
            r"for\s*\([^)]*length[^)]*\).*(?!gasleft|gas\s*<)",
            "Large array operation without gas check",
            "Loop over array without gas limit check can cause DoS",
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 6: Gas estimation in require statements
        self.add_pattern(
            r"require\s*\(\s*gasleft\(\)\s*>\s*\d+",
            "Gas estimation in require",
            "Hard-coded gas requirements can fail due to gas cost changes",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*gas")
        self.add_exclusion_pattern(r"gasleft\(\)\s*>\s*2300")  # Common pattern for preventing reentrancy
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with gas-specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced gas analysis
        for contract in context.contracts:
            yield from self._analyze_loop_gas_usage(contract, context)
            yield from self._analyze_external_call_gas(contract, context)
            yield from self._analyze_gas_griefing_vectors(contract, context)
            yield from self._analyze_gas_optimization_issues(contract, context)
    
    def _analyze_loop_gas_usage(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze loops for gas-related DoS vulnerabilities."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find for loops
        loop_pattern = re.compile(
            r"for\s*\([^)]*\)\s*\{(.*?)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in loop_pattern.finditer(content):
            loop_header = match.group(0).split('{')[0]
            loop_body = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for unbounded loops
            if self._is_unbounded_loop(loop_header):
                # Check for expensive operations in loop
                expensive_ops = self._find_expensive_operations(loop_body)
                
                if expensive_ops:
                    yield self.create_finding(
                        title="Unbounded loop with expensive operations",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:300],
                        description=f"Unbounded loop contains expensive operations: {', '.join(expensive_ops)}",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
                
                # Check if loop has gas checks
                if not re.search(r"gasleft|gas.*<|break", loop_body, re.IGNORECASE):
                    yield self.create_finding(
                        title="Unbounded loop without gas checks",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:200],
                        description="Unbounded loop lacks gas limit checks for DoS protection",
                        contract_name=contract.name,
                        confidence=0.7,
                        severity=Severity.MEDIUM
                    )
    
    def _analyze_external_call_gas(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze external calls for gas-related issues."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find external calls with gas specifications
        gas_call_pattern = re.compile(
            r"\.call\{gas:\s*(\w+)\}|\.call\{value:.*gas:\s*(\w+)\}",
            re.IGNORECASE
        )
        
        for match in gas_call_pattern.finditer(content):
            gas_value = match.group(1) or match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for hardcoded gas values
            if gas_value.isdigit():
                gas_amount = int(gas_value)
                
                # Flag suspicious gas amounts
                if gas_amount == 2300:
                    yield self.create_finding(
                        title="External call with 2300 gas stipend",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description="2300 gas stipend may not be sufficient for all operations",
                        contract_name=contract.name,
                        confidence=0.6,
                        severity=Severity.LOW
                    )
                
                elif gas_amount > 100000:
                    yield self.create_finding(
                        title="External call with high gas limit",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description="High gas limit in external call can facilitate DoS attacks",
                        contract_name=contract.name,
                        confidence=0.7,
                        severity=Severity.MEDIUM
                    )
    
    def _analyze_gas_griefing_vectors(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze potential gas griefing attack vectors."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for patterns that enable gas griefing
        griefing_patterns = [
            (r"while\s*\(.*\.length.*\)", "Unbounded while loop over array"),
            (r"for.*delete\s+\w+\[", "Array deletion in loop"),
            (r"for.*mapping.*delete", "Mapping deletion in loop"),
            (r"\.call\s*\([^)]*\)(?!.*require.*success)", "Unchecked external call"),
        ]
        
        for pattern, description in griefing_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                yield self.create_finding(
                    title="Potential gas griefing vector",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description=f"Gas griefing risk: {description}",
                    contract_name=contract.name,
                    confidence=0.6,
                    severity=Severity.MEDIUM
                )
    
    def _analyze_gas_optimization_issues(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze gas optimization issues that could affect security."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for inefficient patterns that could cause DoS
        inefficient_patterns = [
            (r"string\s+memory.*\+.*string", "String concatenation in memory"),
            (r"for.*i\+\+.*array\.push", "Array push in loop"),
            (r"keccak256\s*\(.*string.*\)", "Hash of dynamic string"),
        ]
        
        for pattern, description in inefficient_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            
            # Only flag if pattern appears multiple times (indicating systemic issue)
            if len(matches) >= 3:
                for match in matches[:2]:  # Report first 2 instances
                    line_num = content[:match.start()].count('\n') + 1
                    
                    yield self.create_finding(
                        title="Gas inefficient pattern",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description=f"Inefficient gas usage: {description} (found {len(matches)} times)",
                        contract_name=contract.name,
                        confidence=0.5,
                        severity=Severity.LOW
                    )
    
    def _is_unbounded_loop(self, loop_header: str) -> bool:
        """Check if loop is potentially unbounded."""
        # Check for common unbounded loop patterns
        unbounded_indicators = [
            r"\.length",  # Loop over array length
            r"users\.length",  # Loop over users
            r"balances\.length",  # Loop over balances
            r"while\s*\(true\)",  # Infinite while loop
        ]
        
        for indicator in unbounded_indicators:
            if re.search(indicator, loop_header, re.IGNORECASE):
                return True
        
        return False
    
    def _find_expensive_operations(self, loop_body: str) -> List[str]:
        """Find expensive operations within loop body."""
        expensive_ops = []
        
        expensive_patterns = [
            (r"\.call\s*\(", "external calls"),
            (r"keccak256|sha256", "cryptographic hashing"),
            (r"ecrecover", "signature recovery"),
            (r"\.delegatecall\s*\(", "delegate calls"),
            (r"new\s+\w+", "contract creation"),
            (r"selfdestruct", "contract destruction"),
            (r"sstore|SSTORE", "storage writes"),
        ]
        
        for pattern, description in expensive_patterns:
            if re.search(pattern, loop_body, re.IGNORECASE):
                expensive_ops.append(description)
        
        return expensive_ops