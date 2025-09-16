"""
Eventless Critical Action Detector - detects critical operations without proper event emission.
"""
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import HeuristicDetector


@register
class EventlessCriticalActionDetector(HeuristicDetector):
    """
    Detects critical operations that lack proper event emission for transparency.
    
    This detector identifies:
    - Token transfers without Transfer events
    - Ownership changes without events
    - Critical state changes without logging
    - Access control modifications without events
    - Configuration changes without transparency
    """
    
    name = "eventless_critical_action"
    description = "Detects critical operations missing event emission for transparency"
    severity = Severity.MEDIUM
    category = "transparency"
    cwe_id = "CWE-778"  # Insufficient Logging
    confidence = 0.7
    
    # Enhanced metadata for Phase 3
    stability = "stable"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True
    
    def __init__(self):
        super().__init__()
        self.tags.add("events")
        self.tags.add("transparency")
        self.tags.add("logging")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/",
            "https://docs.soliditylang.org/en/latest/contracts.html#events"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for eventless critical actions."""
        
        # Pattern 1: Token balance changes without Transfer event
        self.add_pattern(
            r"(balances?\[.*\]\s*[=\+\-]|_balances\[.*\]\s*[=\+\-]).*(?!emit.*Transfer)",
            "Token balance change without Transfer event",
            "Token balance modification lacks Transfer event emission",
            confidence=0.8,
            severity=Severity.MEDIUM
        )
        
        # Pattern 2: Ownership transfer without event
        self.add_pattern(
            r"owner\s*=\s*\w+(?!.*emit.*Owner)",
            "Ownership change without event",
            "Contract ownership change lacks proper event emission",
            confidence=0.9,
            severity=Severity.HIGH
        )
        
        # Pattern 3: Role assignment without event
        self.add_pattern(
            r"(grantRole|revokeRole|addRole|removeRole).*(?!emit)",
            "Role change without event",
            "Access control role modification lacks event emission",
            confidence=0.8,
            severity=Severity.MEDIUM
        )
        
        # Pattern 4: Critical configuration changes without events
        self.add_pattern(
            r"(fee|rate|threshold|limit|max|min)\s*=\s*\w+(?!.*emit)",
            "Configuration change without event",
            "Critical parameter change lacks event emission for transparency",
            confidence=0.6,
            severity=Severity.LOW
        )
        
        # Pattern 5: Contract state changes without events
        self.add_pattern(
            r"(paused|stopped|emergency|locked)\s*=\s*(true|false)(?!.*emit)",
            "State change without event",
            "Critical contract state change lacks event emission",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*event")
        self.add_exclusion_pattern(r"emit\s+\w+")
        self.add_exclusion_pattern(r"private\s+.*=")  # Private variables less critical
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with event emission specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced event analysis
        for contract in context.contracts:
            yield from self._analyze_critical_functions(contract, context)
            yield from self._analyze_erc20_compliance(contract, context)
            yield from self._analyze_access_control_events(contract, context)
        
        # Enhanced Slither analysis if available
        if "slither" in context.tool_artifacts:
            yield from self._analyze_with_slither(context)
    
    def _analyze_critical_functions(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze critical functions for proper event emission."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Define critical function patterns
        critical_functions = [
            (r"withdraw", "withdrawal"),
            (r"deposit", "deposit"), 
            (r"transfer", "transfer"),
            (r"mint", "minting"),
            (r"burn", "burning"),
            (r"pause", "pause"),
            (r"unpause", "unpause"),
            (r"emergency", "emergency action"),
        ]
        
        for pattern, action_type in critical_functions:
            func_pattern = re.compile(
                rf"function\s+\w*{pattern}\w*\s*\([^)]*\)\s*.*?\{{(.*?)\}}",
                re.IGNORECASE | re.DOTALL
            )
            
            for match in func_pattern.finditer(content):
                func_body = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                func_name = self._extract_function_name(match.group(0))
                
                # Check if function emits any events
                if not re.search(r"emit\s+\w+", func_body, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Critical {action_type} function without events",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:200],
                        description=f"Function {func_name} performs {action_type} without emitting events",
                        function_name=func_name,
                        contract_name=contract.name,
                        confidence=0.7,
                        severity=Severity.MEDIUM
                    )
    
    def _analyze_erc20_compliance(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze ERC-20 compliance for Transfer events."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Check if contract looks like ERC-20 token
        if not self._is_erc20_like(content):
            return
        
        # Look for balance modifications
        balance_modifications = re.finditer(
            r"(balances?\[.*\]\s*[=\+\-]|_balances\[.*\]\s*[=\+\-])",
            content,
            re.IGNORECASE
        )
        
        for match in balance_modifications:
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if Transfer event is emitted nearby
            context_start = max(0, match.start() - 200)
            context_end = min(len(content), match.end() + 200)
            context_content = content[context_start:context_end]
            
            if not re.search(r"emit\s+Transfer", context_content, re.IGNORECASE):
                yield self.create_finding(
                    title="ERC-20 balance change without Transfer event",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Token balance modification lacks required Transfer event emission",
                    contract_name=contract.name,
                    confidence=0.9,
                    severity=Severity.HIGH
                )
    
    def _analyze_access_control_events(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze access control operations for event emission."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Look for access control operations
        access_control_ops = [
            (r"grantRole\s*\(", "RoleGranted"),
            (r"revokeRole\s*\(", "RoleRevoked"),
            (r"owner\s*=", "OwnershipTransferred"),
            (r"admin\s*=", "AdminChanged"),
        ]
        
        for op_pattern, expected_event in access_control_ops:
            for match in re.finditer(op_pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check for corresponding event in nearby code
                func_context = self._extract_function_context(content, match.start())
                if func_context and not re.search(rf"emit\s+{expected_event}", func_context, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Access control operation without {expected_event} event",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description=f"Access control operation lacks {expected_event} event emission",
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.MEDIUM
                    )
    
    def _is_erc20_like(self, content: str) -> bool:
        """Check if contract appears to be ERC-20 token."""
        erc20_indicators = [
            r"function\s+transfer\s*\(",
            r"function\s+balanceOf\s*\(",
            r"function\s+totalSupply\s*\(",
            r"event\s+Transfer\s*\(",
            r"balances?\[",
            r"_balances\["
        ]
        
        indicator_count = 0
        for indicator in erc20_indicators:
            if re.search(indicator, content, re.IGNORECASE):
                indicator_count += 1
        
        return indicator_count >= 3  # Likely ERC-20 if multiple indicators present
    
    def _extract_function_name(self, function_def: str) -> str:
        """Extract function name from function definition."""
        match = re.search(r"function\s+(\w+)", function_def, re.IGNORECASE)
        return match.group(1) if match else "unknown"
    
    def _extract_function_context(self, content: str, position: int) -> str:
        """Extract the function context around a given position."""
        # Find function start
        func_start = content.rfind("function", 0, position)
        if func_start == -1:
            return ""
        
        # Find function end (find matching braces)
        brace_count = 0
        func_end = -1
        
        for i in range(func_start, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    func_end = i + 1
                    break
        
        if func_end == -1:
            func_end = len(content)
        
        return content[func_start:func_end]
    
    def _analyze_with_slither(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis using Slither metadata."""
        slither_result = context.tool_artifacts["slither"]
        
        for contract_info in slither_result.contracts:
            # Analyze functions for missing events using Slither metadata
            for func_info in contract_info.functions:
                if self._is_critical_function_slither(func_info.name):
                    # Check if function has no emitted events
                    if not func_info.events_emitted:
                        # Create enhanced finding with Slither metadata
                        finding = self.create_finding(
                            title=f"Critical function {func_info.name} lacks event emission",
                            file_path=contract_info.file,
                            line=func_info.line_start,
                            code=f"function {func_info.name}(...) {func_info.visibility} {func_info.mutability}",
                            description=f"Function {func_info.name} performs critical operations without emitting events for transparency",
                            function_name=func_info.name,
                            contract_name=contract_info.name,
                            confidence=0.8,
                            severity=Severity.MEDIUM
                        )
                        # Add Slither enrichment tag
                        finding.tags.add("slither_enriched")
                        yield finding
    
    def _is_critical_function_slither(self, func_name: str) -> bool:
        """Check if function name indicates critical functionality (Slither version)."""
        critical_keywords = [
            'withdraw', 'transfer', 'mint', 'burn', 'destroy', 'kill',
            'upgrade', 'pause', 'emergency', 'admin', 'owner', 'manage',
            'updatePrice', 'setPrice', 'emergencyWithdraw'
        ]
        
        func_lower = func_name.lower()
        return any(keyword in func_lower for keyword in critical_keywords)