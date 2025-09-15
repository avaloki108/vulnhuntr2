"""
Flash Loan Invariant Breach Detector - detects violations of flash loan atomicity and invariants.
"""
from __future__ import annotations

import re
from typing import Iterator, Set, List

from ..core.models import Finding, ScanContext, Severity
from .base import HeuristicDetector


class FlashLoanInvariantBreachDetector(HeuristicDetector):
    """
    Detects flash loan invariant violations and atomicity abuse patterns.
    
    This detector identifies:
    - Flash loan functions without proper invariant checks
    - State changes that persist across flash loan execution
    - Missing flash loan callback validation
    - Reentrancy vulnerabilities in flash loan contexts
    - Arbitrage opportunities that break protocol invariants
    """
    
    name = "flashloan_invariant_breach"
    description = "Detects flash loan invariant violations and atomicity abuse"
    severity = Severity.HIGH
    category = "flashloan"
    cwe_id = "CWE-362"  # Concurrent Execution using Shared Resource with Improper Synchronization
    confidence = 0.8
    
    def __init__(self):
        super().__init__()
        self.tags.add("flashloan")
        self.tags.add("atomicity")
        self.tags.add("invariant")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
            "https://blog.openzeppelin.com/reentrancy-after-istanbul/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for flash loan invariant breaches."""
        
        # Pattern 1: Flash loan callback without caller validation
        self.add_pattern(
            r"function\s+(\w*flash\w*|\w*loan\w*)\s*\([^)]*\).*(?!require.*msg\.sender)",
            "Flash loan callback missing caller validation",
            "Flash loan callback function doesn't validate the caller",
            confidence=0.9,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Flash loan without amount validation
        self.add_pattern(
            r"flashLoan\s*\([^)]*\).*(?!require.*amount)",
            "Flash loan amount not validated",
            "Flash loan amount parameter is not properly validated",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 3: State changes in flash loan context without proper checks
        self.add_pattern(
            r"(mapping\s*\([^)]*\)\s*\w+|\w+\[\w+\]\s*=).*(?=.*flash)",
            "State modification in flash loan context",
            "State variables modified in flash loan context without invariant preservation",
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 4: Flash loan with external calls to untrusted contracts
        self.add_pattern(
            r"flash.*\.call\s*\(|\.call\s*\(.*flash",
            "External call in flash loan context",
            "External calls to untrusted contracts within flash loan execution",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 5: Flash loan profit extraction without fee validation
        self.add_pattern(
            r"transfer\s*\([^)]*profit[^)]*\)(?!.*fee)",
            "Flash loan profit extraction without fee check",
            "Profit transfer from flash loan without validating protocol fees",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 6: Missing flash loan repayment validation
        self.add_pattern(
            r"flashLoan.*(?!.*repay|.*return|.*balance.*>=)",
            "Flash loan repayment not enforced",
            "Flash loan execution doesn't enforce proper repayment validation",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*flash")
        self.add_exclusion_pattern(r"require.*msg\.sender.*==.*initiator")
        self.add_exclusion_pattern(r"onlyFlashLoan")
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with flash loan specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced flash loan analysis
        for contract in context.contracts:
            yield from self._analyze_flash_loan_functions(contract, context)
            yield from self._analyze_invariant_preservation(contract, context)
            yield from self._analyze_reentrancy_in_flash_context(contract, context)
            yield from self._analyze_arbitrage_opportunities(contract, context)
    
    def _analyze_flash_loan_functions(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze flash loan function implementations."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find flash loan functions
        flash_func_pattern = re.compile(
            r"function\s+(\w*flash\w*|\w*loan\w*)\s*\([^)]*\)\s*.*?\{(.*?)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in flash_func_pattern.finditer(content):
            func_name = match.group(1)
            func_body = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check for proper access control
            if not self._has_access_control(func_body):
                yield self.create_finding(
                    title="Flash loan function lacks access control",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Flash loan function doesn't implement proper access control mechanisms",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
            
            # Check for balance invariant validation
            if not self._has_balance_validation(func_body):
                yield self.create_finding(
                    title="Flash loan missing balance invariant check",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Flash loan function doesn't validate balance invariants before and after execution",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.HIGH
                )
            
            # Check for callback validation
            if not self._has_callback_validation(func_body):
                yield self.create_finding(
                    title="Flash loan callback validation missing",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Flash loan doesn't properly validate callback execution",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.9,
                    severity=Severity.HIGH
                )
    
    def _analyze_invariant_preservation(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze invariant preservation across flash loan execution."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for state variables that should maintain invariants
        state_vars = self._extract_state_variables(content)
        
        # Find functions that modify these variables in flash loan context
        for var in state_vars:
            modification_pattern = re.compile(
                rf"{var}\s*[=\+\-\*\/]=.*flash|flash.*{var}\s*[=\+\-\*\/]=",
                re.IGNORECASE
            )
            
            for match in modification_pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                
                yield self.create_finding(
                    title=f"State variable {var} modified in flash loan context",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description=f"State variable {var} is modified during flash loan execution without invariant checks",
                    contract_name=contract.name,
                    confidence=0.6,
                    severity=Severity.MEDIUM
                )
    
    def _analyze_reentrancy_in_flash_context(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze reentrancy vulnerabilities in flash loan context."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for external calls within flash loan functions
        flash_sections = self._extract_flash_loan_sections(content)
        
        for section_start, section_end, section_content in flash_sections:
            external_calls = re.finditer(
                r"\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(",
                section_content,
                re.IGNORECASE
            )
            
            for call_match in external_calls:
                call_line = section_start + section_content[:call_match.start()].count('\n')
                
                # Check if there's a reentrancy guard
                if not self._has_reentrancy_protection(section_content):
                    yield self.create_finding(
                        title="Reentrancy risk in flash loan context",
                        file_path=contract.file_path,
                        line=call_line,
                        code=call_match.group(0),
                        description="External call in flash loan context without reentrancy protection",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
    
    def _analyze_arbitrage_opportunities(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze potential arbitrage opportunities that break protocol invariants."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for price-dependent operations in flash loan context
        arbitrage_patterns = [
            r"swap.*flash|flash.*swap",
            r"exchange.*flash|flash.*exchange", 
            r"trade.*flash|flash.*trade",
            r"arbitrage.*flash|flash.*arbitrage"
        ]
        
        for pattern in arbitrage_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                yield self.create_finding(
                    title="Potential arbitrage opportunity in flash loan",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Flash loan combined with price-dependent operations creates arbitrage opportunity",
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
    
    def _has_access_control(self, func_body: str) -> bool:
        """Check if function has access control."""
        access_patterns = [
            r"require.*msg\.sender",
            r"onlyOwner",
            r"onlyRole",
            r"authorized",
            r"_checkRole"
        ]
        
        for pattern in access_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_balance_validation(self, func_body: str) -> bool:
        """Check if function validates balance invariants."""
        balance_patterns = [
            r"require.*balance.*>=",
            r"assert.*balance.*>=",
            r"balanceBefore.*balanceAfter",
            r"invariant.*balance"
        ]
        
        for pattern in balance_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _has_callback_validation(self, func_body: str) -> bool:
        """Check if function validates callback execution."""
        callback_patterns = [
            r"require.*success",
            r"assert.*success", 
            r"callback.*return",
            r"executeOperation.*require"
        ]
        
        for pattern in callback_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        return False
    
    def _extract_state_variables(self, content: str) -> List[str]:
        """Extract state variable names from contract."""
        state_var_pattern = re.compile(
            r"^\s*(mapping\s*\([^)]*\)\s*)?(\w+\s+)?(\w+)\s*[=;]",
            re.MULTILINE
        )
        
        variables = []
        for match in state_var_pattern.finditer(content):
            var_name = match.group(3)
            if var_name and not var_name.startswith('_') and len(var_name) > 2:
                variables.append(var_name)
        
        return variables
    
    def _extract_flash_loan_sections(self, content: str) -> List[tuple]:
        """Extract flash loan function sections with line numbers."""
        sections = []
        
        flash_func_pattern = re.compile(
            r"function\s+(\w*flash\w*|\w*loan\w*)\s*\([^)]*\)\s*.*?\{(.*?)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in flash_func_pattern.finditer(content):
            start_line = content[:match.start()].count('\n') + 1
            end_line = content[:match.end()].count('\n') + 1
            section_content = match.group(2)
            
            sections.append((start_line, end_line, section_content))
        
        return sections
    
    def _has_reentrancy_protection(self, section_content: str) -> bool:
        """Check if section has reentrancy protection."""
        protection_patterns = [
            r"nonReentrant",
            r"reentrancyGuard",
            r"_status.*ENTERED",
            r"require.*!_locked"
        ]
        
        for pattern in protection_patterns:
            if re.search(pattern, section_content, re.IGNORECASE):
                return True
        return False