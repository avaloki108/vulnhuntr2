"""
Detector for access control vulnerabilities.
"""
from __future__ import annotations

from typing import Iterator

from .base import BaseDetector
from ..core.models import Finding, ScanContext, Severity, Function
from ..core.registry import register


@register
class AccessControlDetector(BaseDetector):
    """
    Detects access control vulnerabilities including missing onlyOwner checks,
    insufficient role gating, and privilege escalation paths.
    """

    name = "access_control"
    description = "Detects access control vulnerabilities and privilege escalation risks"
    severity = Severity.HIGH
    category = "access"
    cwe_id = "CWE-284"  # Improper Access Control
    confidence = 0.8

    stability = "stable"
    maturity = "beta"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Analyze contracts for access control vulnerabilities.
        """
        for func in context.functions:
            yield from self._analyze_function(func)

    def _analyze_function(self, func: Function) -> Iterator[Finding]:
        """
        Analyze a single function for access control issues.
        """
        # Check for missing access control on critical functions
        if self._is_critical_function(func) and not self._has_access_control(func):
            yield Finding(
                detector=self.name,
                title="Missing Access Control",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.HIGH,
                code=f"Critical function {func.name} lacks access control",
                description="Critical functions should have proper access control mechanisms",
                recommendation="Add onlyOwner modifier or role-based access control",
                confidence=self.confidence,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for insufficient role checks
        if self._has_weak_role_check(func):
            yield Finding(
                detector=self.name,
                title="Weak Role-Based Access Control",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Function {func.name} has insufficient role validation",
                description="Role checks should validate specific roles, not just any role",
                recommendation="Use specific role checks like hasRole(ADMIN_ROLE)",
                confidence=0.7,
                contract_name=func.contract_name,
                function_name=func.name
            )

        # Check for public functions that should be internal
        if self._is_public_critical_function(func):
            yield Finding(
                detector=self.name,
                title="Overly Permissive Function Visibility",
                file=func.file_path,
                line=func.line_start,
                severity=Severity.MEDIUM,
                code=f"Critical function {func.name} is publicly accessible",
                description="Functions performing sensitive operations should not be public",
                recommendation="Change visibility to internal or add access control",
                confidence=0.6,
                contract_name=func.contract_name,
                function_name=func.name
            )

    def _is_critical_function(self, func: Function) -> bool:
        """
        Determine if a function performs critical operations.
        """
        critical_keywords = [
            'withdraw', 'transfer', 'mint', 'burn', 'pause', 'unpause',
            'upgrade', 'set', 'update', 'admin', 'owner', 'emergency',
            'kill', 'destroy', 'selfdestruct'
        ]

        func_name_lower = func.name.lower()
        return any(keyword in func_name_lower for keyword in critical_keywords)

    def _has_access_control(self, func: Function) -> bool:
        """
        Check if function has access control mechanisms.
        """
        # Check for common access control patterns in modifiers
        access_patterns = [
            'onlyOwner', 'onlyowner', 'ownerOnly',
            'hasRole', 'checkRole', 'requireRole',
            'modifier', 'auth', 'authorized'
        ]

        # Check function modifiers (if available)
        if hasattr(func, 'modifiers') and func.modifiers:
            for modifier in func.modifiers:
                if any(pattern in modifier.lower() for pattern in access_patterns):
                    return True

        return False

    def _has_weak_role_check(self, func: Function) -> bool:
        """
        Check for weak role-based access control patterns.
        """
        # Look for generic role checks that might be too permissive
        weak_patterns = [
            'hasRole(bytes32(0))',  # Default admin role
            'hasRole(0x00)',  # Zero role
        ]

        # Check if function name suggests role checking but might be weak
        func_name_lower = func.name.lower()
        if 'role' in func_name_lower or 'admin' in func_name_lower:
            # This is a heuristic - in practice, would need source code analysis
            # For functions that seem to check roles but might be too permissive
            return len(func.state_vars_read) == 0  # Heuristic for weak checks

        return False

    def _is_public_critical_function(self, func: Function) -> bool:
        """
        Check if a critical function is overly public.
        """
        if func.visibility.lower() == 'public' and self._is_critical_function(func):
            # Check if it has external calls or state modifications
            if func.external_calls or func.state_vars_written:
                return True

        return False