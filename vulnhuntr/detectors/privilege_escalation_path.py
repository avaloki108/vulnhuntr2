"""
Privilege Escalation Path Detector - detects privilege escalation vulnerabilities.
"""
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import HeuristicDetector


@register
class PrivilegeEscalationPathDetector(HeuristicDetector):
    """
    Detects privilege escalation vulnerabilities and access control bypasses.
    
    This detector identifies:
    - Missing access control on critical functions
    - Role escalation vulnerabilities
    - Owner/admin privilege bypass paths
    - Delegate call privilege escalation
    - Constructor privilege issues
    """
    
    name = "privilege_escalation_path"
    description = "Detects privilege escalation and access control bypass vulnerabilities"
    severity = Severity.HIGH
    category = "access_control"
    cwe_id = "CWE-269"  # Improper Privilege Management
    confidence = 0.8
    
    def __init__(self):
        super().__init__()
        self.tags.add("access_control")
        self.tags.add("privilege_escalation")
        self.tags.add("authorization")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/",
            "https://blog.openzeppelin.com/onlyowner-prevent-unauthorized-access-solidity-smart-contracts/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for privilege escalation vulnerabilities."""
        
        # Pattern 1: Critical functions without access control
        self.add_pattern(
            r"function\s+(withdraw|transfer|mint|burn|destroy|kill|upgrade|pause)\w*\s*\([^)]*\)\s*public.*(?!only|require.*msg\.sender)",
            "Critical function without access control",
            "Critical function is publicly accessible without proper access control",
            confidence=0.9,
            severity=Severity.HIGH
        )
        
        # Pattern 2: Owner/admin assignment without protection
        self.add_pattern(
            r"(owner|admin)\s*=\s*\w+(?!.*require|.*only)",
            "Owner/admin assignment without validation",
            "Owner or admin role assignment lacks proper validation",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 3: Delegatecall to user-controlled address
        self.add_pattern(
            r"delegatecall\s*\(\s*\w+(?!.*require.*trusted|.*whitelist)",
            "Delegatecall to untrusted address",
            "Delegatecall to user-controlled or untrusted address enables privilege escalation",
            confidence=0.9,
            severity=Severity.CRITICAL
        )
        
        # Pattern 4: Role granting without proper authorization
        self.add_pattern(
            r"(grantRole|addRole|setRole)\s*\([^)]*\)(?!.*only|.*require.*admin)",
            "Role granting without authorization",
            "Role granting function lacks proper authorization checks",
            confidence=0.8,
            severity=Severity.HIGH
        )
        
        # Pattern 5: Constructor with public visibility
        self.add_pattern(
            r"constructor\s*\([^)]*\)\s*public",
            "Public constructor vulnerability",
            "Constructor with public visibility may allow initialization bypass",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Pattern 6: Fallback function with state changes
        self.add_pattern(
            r"(fallback|receive)\s*\(\s*\)\s*.*\{[^}]*(\w+\s*=|\w+\+\+|transfer|call)",
            "Fallback function with state changes",
            "Fallback/receive function modifies state without access control",
            confidence=0.7,
            severity=Severity.MEDIUM
        )
        
        # Exclusion patterns
        self.add_exclusion_pattern(r"//.*test.*privilege")
        self.add_exclusion_pattern(r"onlyOwner|onlyAdmin|onlyRole")
        self.add_exclusion_pattern(r"require.*msg\.sender.*==")
    
    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis with privilege escalation specific checks."""
        # Run basic pattern matching
        yield from super().analyze(context)
        
        # Run advanced privilege analysis
        for contract in context.contracts:
            yield from self._analyze_access_control_patterns(contract, context)
            yield from self._analyze_role_hierarchies(contract, context)
            yield from self._analyze_proxy_patterns(contract, context)
            yield from self._analyze_initialization_patterns(contract, context)
        
        # Enhanced Slither analysis if available
        if "slither" in context.tool_artifacts:
            yield from self._analyze_with_slither(context)
    
    def _analyze_access_control_patterns(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze access control implementation patterns."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find all functions and their access control
        function_pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?\s*([^{]*)\{",
            re.IGNORECASE
        )
        
        for match in function_pattern.finditer(content):
            func_name = match.group(1)
            visibility = match.group(2) or "internal"
            modifiers = match.group(3) or ""
            line_num = content[:match.start()].count('\n') + 1
            
            # Check critical functions
            if self._is_critical_function(func_name):
                if visibility.lower() in ['public', 'external']:
                    if not self._has_access_control_modifier(modifiers):
                        yield self.create_finding(
                            title=f"Critical function {func_name} lacks access control",
                            file_path=contract.file_path,
                            line=line_num,
                            code=match.group(0)[:200],
                            description=f"Critical function {func_name} is {visibility} but lacks access control modifiers",
                            function_name=func_name,
                            contract_name=contract.name,
                            confidence=0.9,
                            severity=Severity.HIGH
                        )
            
            # Check for privilege-granting functions
            if self._is_privilege_granting_function(func_name):
                if not self._has_admin_protection(modifiers):
                    yield self.create_finding(
                        title=f"Privilege-granting function {func_name} lacks admin protection",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0)[:200],
                        description=f"Function {func_name} can grant privileges without admin authorization",
                        function_name=func_name,
                        contract_name=contract.name,
                        confidence=0.8,
                        severity=Severity.HIGH
                    )
    
    def _analyze_role_hierarchies(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze role hierarchy and privilege escalation paths."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Find role definitions and assignments
        role_assignments = re.finditer(
            r"(grantRole|revokeRole|setRole|addRole)\s*\([^)]*\)",
            content,
            re.IGNORECASE
        )
        
        for match in role_assignments:
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if assignment has proper authorization
            func_context = self._extract_function_context(content, match.start())
            if func_context and not self._has_role_admin_check(func_context):
                yield self.create_finding(
                    title="Role assignment without admin verification",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Role assignment operation lacks proper admin role verification",
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.HIGH
                )
    
    def _analyze_proxy_patterns(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze proxy patterns for privilege escalation."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Check for upgradeable patterns
        upgrade_patterns = [
            r"upgradeTo\s*\([^)]*\)",
            r"upgradeToAndCall\s*\([^)]*\)",
            r"setImplementation\s*\([^)]*\)"
        ]
        
        for pattern in upgrade_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if upgrade has timelock
                func_context = self._extract_function_context(content, match.start())
                if func_context and not self._has_timelock_protection(func_context):
                    yield self.create_finding(
                        title="Upgrade function without timelock protection",
                        file_path=contract.file_path,
                        line=line_num,
                        code=match.group(0),
                        description="Contract upgrade function lacks timelock protection",
                        contract_name=contract.name,
                        confidence=0.7,
                        severity=Severity.MEDIUM
                    )
        
        # Check for delegatecall patterns
        delegatecall_pattern = re.compile(
            r"delegatecall\s*\([^)]*\)",
            re.IGNORECASE
        )
        
        for match in delegatecall_pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if delegatecall target is validated
            func_context = self._extract_function_context(content, match.start())
            if func_context and not self._has_target_validation(func_context, match.group(0)):
                yield self.create_finding(
                    title="Delegatecall without target validation",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0),
                    description="Delegatecall to potentially untrusted target without validation",
                    contract_name=contract.name,
                    confidence=0.9,
                    severity=Severity.CRITICAL
                )
    
    def _analyze_initialization_patterns(self, contract, context: ScanContext) -> Iterator[Finding]:
        """Analyze initialization patterns for privilege escalation."""
        content = self._read_contract_content(contract.file_path)
        if not content:
            return
        
        # Check for initialize functions
        init_pattern = re.compile(
            r"function\s+(initialize|init|setup)\s*\([^)]*\)\s*([^{]*)\{([^}]*)\}",
            re.IGNORECASE | re.DOTALL
        )
        
        for match in init_pattern.finditer(content):
            func_name = match.group(1)
            modifiers = match.group(2)
            func_body = match.group(3)
            line_num = content[:match.start()].count('\n') + 1
            
            # Check if initialize can be called multiple times
            if not self._has_initialization_guard(func_body, modifiers):
                yield self.create_finding(
                    title=f"Initialize function {func_name} lacks re-initialization protection",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description=f"Initialize function {func_name} can be called multiple times",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.8,
                    severity=Severity.HIGH
                )
            
            # Check if owner is set from parameter without validation
            if self._has_unsafe_owner_assignment(func_body):
                yield self.create_finding(
                    title="Unsafe owner assignment in initialize function",
                    file_path=contract.file_path,
                    line=line_num,
                    code=match.group(0)[:200],
                    description="Initialize function sets owner from parameter without validation",
                    function_name=func_name,
                    contract_name=contract.name,
                    confidence=0.7,
                    severity=Severity.MEDIUM
                )
    
    def _is_critical_function(self, func_name: str) -> bool:
        """Check if function name indicates critical functionality."""
        critical_keywords = [
            'withdraw', 'transfer', 'mint', 'burn', 'destroy', 'kill',
            'upgrade', 'pause', 'emergency', 'admin', 'owner', 'manage'
        ]
        
        func_lower = func_name.lower()
        return any(keyword in func_lower for keyword in critical_keywords)
    
    def _is_privilege_granting_function(self, func_name: str) -> bool:
        """Check if function grants privileges."""
        privilege_keywords = [
            'grant', 'add', 'set', 'assign', 'promote', 'elevate'
        ]
        
        func_lower = func_name.lower()
        return any(keyword in func_lower for keyword in privilege_keywords)
    
    def _has_access_control_modifier(self, modifiers: str) -> bool:
        """Check if modifiers contain access control."""
        access_patterns = [
            r"only\w+", r"require\w+", r"auth\w+", r"permit\w+", r"restrict\w+"
        ]
        
        for pattern in access_patterns:
            if re.search(pattern, modifiers, re.IGNORECASE):
                return True
        return False
    
    def _has_admin_protection(self, modifiers: str) -> bool:
        """Check if modifiers contain admin protection."""
        admin_patterns = [
            r"onlyAdmin", r"onlyOwner", r"onlyRole", r"requiresAuth"
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, modifiers, re.IGNORECASE):
                return True
        return False
    
    def _has_role_admin_check(self, func_context: str) -> bool:
        """Check if function has role admin verification."""
        admin_patterns = [
            r"hasRole.*ADMIN",
            r"onlyRole.*ADMIN",
            r"require.*admin",
            r"getRoleAdmin"
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, func_context, re.IGNORECASE):
                return True
        return False
    
    def _has_timelock_protection(self, func_context: str) -> bool:
        """Check if function has timelock protection."""
        timelock_patterns = [
            r"timelock", r"delay", r"schedule", r"queue", r"execute.*after"
        ]
        
        for pattern in timelock_patterns:
            if re.search(pattern, func_context, re.IGNORECASE):
                return True
        return False
    
    def _has_target_validation(self, func_context: str, delegatecall_line: str) -> bool:
        """Check if delegatecall target is validated."""
        # Extract target from delegatecall
        target_match = re.search(r"delegatecall\s*\(\s*(\w+)", delegatecall_line)
        if not target_match:
            return False
        
        target = target_match.group(1)
        
        # Check for validation patterns
        validation_patterns = [
            rf"require.*{target}.*!=.*0",
            rf"whitelist.*{target}",
            rf"trusted.*{target}",
            rf"approved.*{target}"
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, func_context, re.IGNORECASE):
                return True
        return False
    
    def _has_initialization_guard(self, func_body: str, modifiers: str) -> bool:
        """Check if function has initialization guard."""
        guard_patterns = [
            r"initializer", r"initializer", r"onlyUninitialized",
            r"require.*!initialized", r"assert.*!initialized"
        ]
        
        combined = func_body + " " + modifiers
        for pattern in guard_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        return False
    
    def _has_unsafe_owner_assignment(self, func_body: str) -> bool:
        """Check if owner is assigned from parameter without validation."""
        assignment_pattern = re.compile(
            r"owner\s*=\s*(\w+)(?!.*require|.*assert)",
            re.IGNORECASE
        )
        
        return bool(assignment_pattern.search(func_body))
    
    def _extract_function_context(self, content: str, position: int) -> str:
        """Extract the function context around a given position."""
        # Find function start
        func_start = content.rfind("function", 0, position)
        if func_start == -1:
            return ""
        
        # Find function end (next function or end of contract)
        func_end = content.find("function", position + 1)
        if func_end == -1:
            func_end = len(content)
        
        return content[func_start:func_end]
    
    def _analyze_with_slither(self, context: ScanContext) -> Iterator[Finding]:
        """Enhanced analysis using Slither metadata."""
        slither_result = context.tool_artifacts["slither"]
        
        for contract_info in slither_result.contracts:
            # Analyze functions for privilege escalation using Slither metadata
            for func_info in contract_info.functions:
                # Check critical functions without access control modifiers
                if self._is_critical_function(func_info.name):
                    if func_info.visibility in ["public", "external"]:
                        # Check if function has access control modifiers
                        has_access_control = any(
                            mod for mod in func_info.modifiers 
                            if any(access_term in mod.lower() for access_term in ['only', 'require', 'auth'])
                        )
                        
                        if not has_access_control:
                            # Create enhanced finding with Slither metadata
                            finding = self.create_finding(
                                title=f"Critical function {func_info.name} lacks access control",
                                file_path=contract_info.file,
                                line=func_info.line_start,
                                code=f"function {func_info.name}(...) {func_info.visibility} {func_info.mutability}",
                                description=f"Critical function {func_info.name} is {func_info.visibility} but lacks access control modifiers",
                                function_name=func_info.name,
                                contract_name=contract_info.name,
                                confidence=0.9,
                                severity=Severity.HIGH
                            )
                            # Add Slither enrichment tag and higher confidence
                            finding.tags.add("slither_enriched")
                            finding.confidence = 0.95  # Higher confidence due to precise metadata
                            yield finding