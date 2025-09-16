"""
Base detector interface and utilities for vulnerability detection.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Iterator
import re
import fnmatch
from pathlib import Path

from ..core.models import Finding, ScanContext, Severity, ContractFunction, ContractInfo


class BaseDetector(ABC):
    """
    Abstract base class for all vulnerability detectors.
    """
    
    # Subclasses should define these
    name: str = "base_detector"
    description: str = "Base detector class"
    severity: Severity = Severity.INFO
    category: str = "unknown"
    cwe_id: Optional[str] = None
    confidence: float = 0.5
    
    # Enhanced metadata for Phase 3
    stability: str = "experimental"  # experimental, stable, legacy
    maturity: str = "alpha"  # alpha, beta, stable
    requires_slither: bool = False
    supports_llm_enrichment: bool = False
    enabled_by_default: bool = True
    
    def __init__(self):
        self.tags = set()
        self.references = []
    
    @abstractmethod
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze the scan context and yield vulnerability findings.
        
        Args:
            context: ScanContext with parsed contracts and configuration
            
        Yields:
            Finding objects for detected vulnerabilities
        """
        pass
    
    def matches_selector(self, selector: str) -> bool:
        """
        Check if this detector matches the given selector.
        
        Supports:
        - Exact name match: "detector_name"
        - Glob patterns: "detector_*", "*_reentrancy"
        - Category patterns: "category:access_control", "category:*"
        
        Args:
            selector: Selector string to match against
            
        Returns:
            True if this detector matches the selector
        """
        # Category selector
        if selector.startswith("category:"):
            category_pattern = selector[9:]  # Remove "category:" prefix
            if category_pattern == "*":
                return True
            return fnmatch.fnmatch(self.category, category_pattern)
        
        # Exact name match
        if selector == self.name:
            return True
        
        # Glob pattern match on name
        if fnmatch.fnmatch(self.name, selector):
            return True
        
        return False
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get detector metadata for introspection."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "stability": self.stability,
            "maturity": self.maturity,
            "requires_slither": self.requires_slither,
            "supports_llm_enrichment": self.supports_llm_enrichment,
            "enabled_by_default": self.enabled_by_default,
            "cwe_id": self.cwe_id,
            "tags": list(self.tags),
            "references": self.references.copy(),
        }
    
    def create_finding(
        self,
        title: str,
        file_path: str,
        line: int,
        code: str,
        description: Optional[str] = None,
        function_name: Optional[str] = None,
        contract_name: Optional[str] = None,
        end_line: Optional[int] = None,
        confidence: Optional[float] = None,
        severity: Optional[Severity] = None,
        **kwargs
    ) -> Finding:
        """
        Create a Finding object with detector defaults.
        """
        return Finding(
            detector=self.name,
            title=title,
            file=file_path,
            line=line,
            severity=severity or self.severity,
            code=code,
            description=description,
            confidence=confidence or self.confidence,
            category=self.category,
            cwe_id=self.cwe_id,
            function_name=function_name,
            contract_name=contract_name,
            end_line=end_line,
            references=self.references.copy(),
            tags=self.tags.copy(),
            **kwargs
        )


class HeuristicDetector(BaseDetector):
    """
    Base class for heuristic detectors that analyze code patterns.
    """
    
    def __init__(self):
        super().__init__()
        self.patterns = []
        self.exclude_patterns = []
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Analyze using heuristic patterns."""
        for contract in context.contracts:
            yield from self.analyze_contract(contract, context)
    
    def analyze_contract(self, contract: ContractInfo, context: ScanContext) -> Iterator[Finding]:
        """Analyze a specific contract."""
        # Read contract source code
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        lines = content.splitlines()
        
        # Analyze each line
        for line_num, line in enumerate(lines, 1):
            if self._should_skip_line(line):
                continue
            
            # Check for vulnerability patterns
            for pattern_result in self._check_patterns(line, line_num, contract):
                if pattern_result:
                    yield self._create_finding_from_pattern(
                        pattern_result, contract, line_num, line, context
                    )
    
    def _read_contract_content(self, file_path: str) -> Optional[str]:
        """Read contract source code."""
        try:
            return Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
    
    def _should_skip_line(self, line: str) -> bool:
        """Check if line should be skipped (comments, empty lines, etc.)."""
        stripped = line.strip()
        return (
            not stripped or
            stripped.startswith("//") or
            stripped.startswith("/*") or
            stripped.startswith("*") or
            stripped.startswith("*/")
        )
    
    def _check_patterns(self, line: str, line_num: int, contract: ContractInfo) -> List[Dict[str, Any]]:
        """Check line against vulnerability patterns."""
        results = []
        
        for pattern in self.patterns:
            match = pattern["regex"].search(line)
            if match:
                # Check exclusion patterns
                if self._matches_exclusion(line):
                    continue
                
                results.append({
                    "pattern": pattern,
                    "match": match,
                    "line_num": line_num,
                    "line": line
                })
        
        return results
    
    def _matches_exclusion(self, line: str) -> bool:
        """Check if line matches exclusion patterns."""
        for exclude_pattern in self.exclude_patterns:
            if exclude_pattern.search(line):
                return True
        return False
    
    def _create_finding_from_pattern(
        self, 
        pattern_result: Dict[str, Any], 
        contract: ContractInfo, 
        line_num: int, 
        line: str,
        context: ScanContext
    ) -> Finding:
        """Create Finding from pattern match result."""
        pattern = pattern_result["pattern"]
        
        # Find containing function if possible
        function_name = self._find_containing_function(contract, line_num)
        
        return self.create_finding(
            title=pattern.get("title", "Vulnerability detected"),
            file_path=contract.file_path,
            line=line_num,
            code=line.strip(),
            description=pattern.get("description"),
            function_name=function_name,
            contract_name=contract.name,
            confidence=pattern.get("confidence", self.confidence),
            severity=pattern.get("severity", self.severity)
        )
    
    def _find_containing_function(self, contract: ContractInfo, line_num: int) -> Optional[str]:
        """Find the function containing the given line number."""
        for func in contract.functions:
            if func.start_line <= line_num <= func.end_line:
                return func.name
        return None
    
    def add_pattern(
        self, 
        regex: str, 
        title: str, 
        description: str = "",
        confidence: float = 0.5,
        severity: Optional[Severity] = None
    ):
        """Add a vulnerability pattern to check."""
        self.patterns.append({
            "regex": re.compile(regex, re.IGNORECASE),
            "title": title,
            "description": description,
            "confidence": confidence,
            "severity": severity or self.severity
        })
    
    def add_exclusion_pattern(self, regex: str):
        """Add a pattern to exclude from detection."""
        self.exclude_patterns.append(re.compile(regex, re.IGNORECASE))


class FunctionAnalyzer:
    """Utility class for analyzing smart contract functions."""
    
    @staticmethod
    def has_external_call(function: ContractFunction, content: str) -> bool:
        """Check if function contains external calls."""
        lines = content.splitlines()
        func_lines = lines[function.start_line-1:function.end_line]
        func_content = "\n".join(func_lines)
        
        external_call_patterns = [
            r"\.call\s*\(",
            r"\.delegatecall\s*\(",
            r"\.staticcall\s*\(",
            r"\.send\s*\(",
            r"\.transfer\s*\(",
            r"\w+\.\w+\s*\("  # General external function call
        ]
        
        for pattern in external_call_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def has_state_changes(function: ContractFunction, content: str) -> bool:
        """Check if function modifies state variables."""
        lines = content.splitlines()
        func_lines = lines[function.start_line-1:function.end_line]
        func_content = "\n".join(func_lines)
        
        state_change_patterns = [
            r"\w+\s*=\s*",  # Assignment
            r"\w+\s*\+=\s*",  # Addition assignment
            r"\w+\s*-=\s*",  # Subtraction assignment
            r"\w+\s*\*=\s*",  # Multiplication assignment
            r"\w+\s*/=\s*",  # Division assignment
            r"\w+\+\+",  # Increment
            r"\+\+\w+",  # Pre-increment
            r"\w+--",  # Decrement
            r"--\w+",  # Pre-decrement
            r"delete\s+\w+",  # Delete statement
        ]
        
        for pattern in state_change_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def has_reentrancy_guard(function: ContractFunction, content: str) -> bool:
        """Check if function has reentrancy protection."""
        # Check function modifiers
        guard_modifiers = ["nonReentrant", "reentrancyGuard", "noReentrancy"]
        
        for modifier in function.modifiers:
            if any(guard in modifier.lower() for guard in guard_modifiers):
                return True
        
        # Check for manual guard patterns in function body
        lines = content.splitlines()
        func_lines = lines[function.start_line-1:function.end_line]
        func_content = "\n".join(func_lines)
        
        guard_patterns = [
            r"require\s*\(\s*!_reentrancyGuard",
            r"require\s*\(\s*_status\s*!=\s*_ENTERED",
            r"_reentrancyGuard\s*=\s*true",
            r"_status\s*=\s*_ENTERED",
        ]
        
        for pattern in guard_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract_function_calls(function: ContractFunction, content: str) -> List[str]:
        """Extract function calls from function body."""
        lines = content.splitlines()
        func_lines = lines[function.start_line-1:function.end_line]
        func_content = "\n".join(func_lines)
        
        # Pattern to match function calls
        call_pattern = r"(\w+(?:\.\w+)*)\s*\("
        matches = re.findall(call_pattern, func_content)
        
        return matches
    
    @staticmethod
    def has_access_control(function: ContractFunction) -> bool:
        """Check if function has access control modifiers."""
        access_modifiers = [
            "onlyOwner", "onlyAdmin", "onlyRole", "requiresAuth",
            "restricted", "authorized", "permissioned"
        ]
        
        for modifier in function.modifiers:
            if any(access_mod in modifier for access_mod in access_modifiers):
                return True
        
        return False