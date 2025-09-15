"""
Logic Oracle Mismatch Detector - detects discrepancies between oracle logic and business logic.
"""
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Finding, ScanContext, Severity
from .base import HeuristicDetector


class LogicOracleMismatchDetector(HeuristicDetector):
    """
    Detects potential mismatches between oracle price feeds and business logic assumptions.
    
    This detector identifies patterns where:
    - Oracle prices are used without proper validation
    - Business logic assumes price ranges that oracles don't guarantee
    - Price staleness checks are missing
    - Multiple oracle sources are not properly aggregated
    """
    
    name = "logic_oracle_mismatch"
    description = "Detects oracle logic mismatches and price manipulation vulnerabilities"
    severity = Severity.HIGH
    category = "oracle"
    cwe_id = "CWE-345"  # Insufficient Verification of Data Authenticity
    confidence = 0.75
    
    def __init__(self):
        super().__init__()
        self.tags.add("oracle")
        self.tags.add("price_manipulation")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/#dont-use-transfer-or-send",
            "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for oracle mismatches."""
        
        # Pattern 1: Direct oracle price usage without validation
        self.add_pattern(
            r"\.latestRoundData\(\s*\).*(?!require|assert|if)",
            "Oracle price used without validation",
            "Oracle price data is used directly without validating staleness, bounds, or sanity checks",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Missing staleness checks
        self.add_pattern(
            r"latestRoundData\(\s*\).*[^;]*(?!timestamp|updatedAt)",
            "Oracle staleness check missing", 
            "Oracle data timestamp is not checked for staleness",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 3: Single oracle source without fallback
        self.add_pattern(
            r"AggregatorV3Interface.*(?!.*fallback|.*backup|.*secondary)",
            "Single oracle without fallback",
            "Only one oracle source used without fallback mechanism",
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 4: Price bounds assumptions
        self.add_pattern(
            r"price\s*[<>]=?\s*\d+.*(?=require|assert)",
            "Hardcoded price bounds",
            "Business logic assumes specific price ranges that oracle doesn't guarantee", 
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 5: Division by oracle price without zero check
        self.add_pattern(
            r"[/]\s*price(?!\s*[><!])",
            "Division by oracle price without zero check",
            "Oracle price used in division without checking for zero value",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 6: Oracle price in loop without gas optimization
        self.add_pattern(
            r"for\s*\(.*\).*\{[^}]*latestRoundData",
            "Oracle call in loop",
            "Oracle price fetched inside loop causing gas issues and potential DoS",
            confidence=0.9,
            severity=Severity.MEDIUM
        )
        
        # Exclusion patterns for false positives
        self.add_exclusion_pattern(r"//.*oracle.*test")
        self.add_exclusion_pattern(r"require.*price.*>\s*0")
        self.add_exclusion_pattern(r"assert.*timestamp.*>\s*0")
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with oracle-specific checks."""
        # First run basic pattern matching
        yield from super().analyze(context)
        
        # Then run advanced oracle-specific analysis
        for contract in context.contracts:
            yield from self._analyze_oracle_aggregation(contract, context)
            yield from self._analyze_price_manipulation_vectors(contract, context)
            yield from self._analyze_oracle_dependencies(contract, context)
    
    def _analyze_oracle_aggregation(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze oracle price aggregation logic."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for aggregation functions
        aggregation_pattern = re.compile(
            r"function\s+(\w*aggregate\w*|\w*median\w*|\w*average\w*)\s*\([^)]*\)\s*.*\{([^}]*)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in aggregation_pattern.finditer(content):
            func_name = match.group(1)
            func_body = match.group(2)
            
            # Check for proper outlier detection
            if "outlier" not in func_body.lower() and "deviation" not in func_body.lower():
                line_num = content[:match.start()].count('\n') + 1
                
                yield self.create_finding(
                    title="Oracle aggregation missing outlier detection",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Oracle price aggregation function lacks outlier detection mechanism",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
    
    def _analyze_price_manipulation_vectors(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze potential price manipulation attack vectors."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            if self._should_skip_line(line):
                continue
            
            # Check for flash loan + oracle combination
            if ("flashloan" in line.lower() or "flashborrow" in line.lower()) and i < len(lines) - 5:
                # Look ahead for oracle usage
                lookahead = "\n".join(lines[i:i+5])
                if re.search(r"latestRoundData|getPrice", lookahead, re.IGNORECASE):
                    yield self.create_finding(
                        title="Flash loan near oracle usage - manipulation risk",
                        file_path=contract.file_path,
                        line=i,
                        code=line.strip(),
                        description="Flash loan functionality near oracle price usage creates manipulation risk",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
            
            # Check for large value operations with oracle prices
            large_value_pattern = re.compile(r"(\d{6,}|\d+e\d+).*price", re.IGNORECASE)
            if large_value_pattern.search(line):
                yield self.create_finding(
                    title="Large value calculation with oracle price",
                    file_path=contract.file_path,
                    line=i,
                    code=line.strip(),
                    description="Large value operations using oracle prices may be vulnerable to manipulation",
                    contract_name=contract.name,
                    confidence=0.6,
                    severity=Severity.MEDIUM
                )
    
    def _analyze_oracle_dependencies(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze critical business logic dependencies on oracle data."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find functions that depend on oracle data for critical operations
        critical_patterns = [
            (r"liquidat", "liquidation"),
            (r"withdraw", "withdrawal"),
            (r"borrow", "borrowing"),
            (r"mint", "minting"),
            (r"burn", "burning"),
            (r"swap", "swapping"),
        ]
        
        for pattern, operation in critical_patterns:
            func_pattern = re.compile(
                rf"function\s+\w*{pattern}\w*\s*\([^)]*\)\s*.*\{{([^}}]*latestRoundData[^}}]*)\}}",
                re.IGNORECASE | re.DOTALL
            )
            
            for match in func_pattern.finditer(content):
                func_body = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if oracle failure is handled
                if not re.search(r"try.*catch|require.*success", func_body, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Critical {operation} function depends on oracle without failure handling",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:300],
                        description=f"Critical {operation} function relies on oracle data without proper failure handling",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )