"""
Correlation patterns for complex vulnerability chains.
"""
from __future__ import annotations

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from ..core.models import Finding


class CorrelationType(Enum):
    """Types of correlation patterns."""
    ORACLE_CHAIN = "oracle_chain"
    ACCESS_CONTROL_CHAIN = "access_control_chain"
    FLASH_LOAN_CHAIN = "flash_loan_chain"
    DELEGATECALL_CHAIN = "delegatecall_chain"
    RANDOMNESS_CHAIN = "randomness_chain"
    STORAGE_COLLISION_CHAIN = "storage_collision_chain"


@dataclass
class CorrelationPattern:
    """Definition of a correlation pattern."""
    name: str
    type: CorrelationType
    description: str
    detector_triggers: List[str]  # Detector names that trigger this pattern
    join_keys: List[str]  # How findings are correlated (e.g., contract, function)
    conditions: Dict[str, Any]  # Additional conditions
    severity_boost: int  # How much to boost severity
    confidence_boost: float  # How much to boost confidence


# Define correlation patterns
CORRELATION_PATTERNS = [
    CorrelationPattern(
        name="oracle_manipulation_chain",
        type=CorrelationType.ORACLE_CHAIN,
        description="Oracle data manipulation through stale feeds and single sources",
        detector_triggers=["oracle_manipulation", "logic_oracle_mismatch"],
        join_keys=["contract", "function"],
        conditions={
            "min_findings": 2,
            "shared_state_vars": True
        },
        severity_boost=1,
        confidence_boost=0.2
    ),

    CorrelationPattern(
        name="access_control_bypass_chain",
        type=CorrelationType.ACCESS_CONTROL_CHAIN,
        description="Access control bypass through missing checks and privilege escalation",
        detector_triggers=["access_control", "privilege_escalation_path"],
        join_keys=["contract"],
        conditions={
            "min_findings": 2,
            "critical_functions": True
        },
        severity_boost=2,
        confidence_boost=0.3
    ),

    CorrelationPattern(
        name="flash_loan_exploit_chain",
        type=CorrelationType.FLASH_LOAN_CHAIN,
        description="Flash loan attacks exploiting price manipulation and invariant breaches",
        detector_triggers=["flashloan_invariant_breach", "oracle_manipulation", "gas_sensitive_branching"],
        join_keys=["contract", "function"],
        conditions={
            "min_findings": 2,
            "price_operations": True
        },
        severity_boost=2,
        confidence_boost=0.4
    ),

    CorrelationPattern(
        name="delegatecall_corruption_chain",
        type=CorrelationType.DELEGATECALL_CHAIN,
        description="Delegatecall leading to storage corruption and selfdestruct",
        detector_triggers=["delegatecall_misuse", "unprotected_selfdestruct", "uninitialized_storage"],
        join_keys=["contract"],
        conditions={
            "min_findings": 2,
            "storage_operations": True
        },
        severity_boost=3,
        confidence_boost=0.5
    ),

    CorrelationPattern(
        name="randomness_exploit_chain",
        type=CorrelationType.RANDOMNESS_CHAIN,
        description="Predictable randomness enabling financial manipulation",
        detector_triggers=["insecure_randomness", "access_control"],
        join_keys=["contract", "function"],
        conditions={
            "min_findings": 2,
            "financial_context": True
        },
        severity_boost=1,
        confidence_boost=0.25
    ),

    CorrelationPattern(
        name="storage_collision_chain",
        type=CorrelationType.STORAGE_COLLISION_CHAIN,
        description="Storage collision in upgradeable contracts",
        detector_triggers=["uninitialized_storage", "upgradeable_proxy"],
        join_keys=["contract"],
        conditions={
            "min_findings": 2,
            "upgradeable": True
        },
        severity_boost=2,
        confidence_boost=0.35
    )
]


class CorrelationEngine:
    """Engine for correlating findings across detectors."""

    def __init__(self):
        self.patterns = CORRELATION_PATTERNS

    def correlate_findings(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Correlate findings based on defined patterns.

        Args:
            findings: List of individual findings

        Returns:
            List of correlation clusters
        """
        clusters = []

        for pattern in self.patterns:
            cluster = self._find_pattern_matches(pattern, findings)
            if cluster:
                clusters.append(cluster)

        return clusters

    def _find_pattern_matches(self, pattern: CorrelationPattern, findings: List[Finding]) -> Optional[Dict[str, Any]]:
        """
        Find matches for a specific correlation pattern.
        """
        # Group findings by detector
        detector_findings = {}
        for finding in findings:
            detector = getattr(finding, 'detector', 'unknown')
            if detector not in detector_findings:
                detector_findings[detector] = []
            detector_findings[detector].append(finding)

        # Check if we have findings from required detectors
        matched_findings = []
        for detector_name in pattern.detector_triggers:
            if detector_name in detector_findings:
                matched_findings.extend(detector_findings[detector_name])

        if len(matched_findings) < pattern.conditions.get('min_findings', 1):
            return None

        # Group by join keys
        grouped_findings = self._group_by_join_keys(matched_findings, pattern.join_keys)

        # Find clusters that meet conditions
        for group_key, group_findings in grouped_findings.items():
            if self._meets_conditions(group_findings, pattern.conditions):
                return {
                    'pattern': pattern.name,
                    'type': pattern.type.value,
                    'description': pattern.description,
                    'findings': [self._finding_to_dict(f) for f in group_findings],
                    'severity_boost': pattern.severity_boost,
                    'confidence_boost': pattern.confidence_boost,
                    'cluster_id': f"{pattern.name}_{hash(group_key) % 10000}"
                }

        return None

    def _group_by_join_keys(self, findings: List[Finding], join_keys: List[str]) -> Dict[tuple, List[Finding]]:
        """
        Group findings by join keys.
        """
        groups = {}

        for finding in findings:
            group_key = []
            for key in join_keys:
                if key == 'contract':
                    value = getattr(finding, 'contract_name', 'unknown')
                elif key == 'function':
                    value = getattr(finding, 'function_name', 'unknown')
                elif key == 'file':
                    value = getattr(finding, 'file', 'unknown')
                else:
                    value = 'unknown'
                group_key.append(value)

            group_key = tuple(group_key)
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(finding)

        return groups

    def _meets_conditions(self, findings: List[Finding], conditions: Dict[str, Any]) -> bool:
        """
        Check if findings meet pattern conditions.
        """
        # This is a simplified implementation
        # In practice, would need more sophisticated condition checking
        return len(findings) >= conditions.get('min_findings', 1)

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """
        Convert finding to dictionary.
        """
        return {
            'detector': getattr(finding, 'detector', 'unknown'),
            'title': getattr(finding, 'title', 'Unknown'),
            'file': getattr(finding, 'file', 'unknown'),
            'line': getattr(finding, 'line', 0),
            'severity': getattr(finding, 'severity', 'UNKNOWN'),
            'description': getattr(finding, 'description', ''),
            'contract_name': getattr(finding, 'contract_name', ''),
            'function_name': getattr(finding, 'function_name', '')
        }