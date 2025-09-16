"""
Simple reentrancy heuristic detector.
"""
from __future__ import annotations

import re
from typing import Iterator

from ..core.models import Finding, ScanContext, Severity
from ..core.registry import register
from .base import HeuristicDetector


@register
class ReentrancyHeuristic(HeuristicDetector):
    """
    Extremely naive heuristic detector for potential reentrancy risk patterns.
    This is a placeholder example: real detectors should use proper AST parsing.
    """

    name = "reentrancy_heuristic"
    description = "Flags occurrences of low-level external calls before state updates."
    severity = Severity.MEDIUM
    category = "reentrancy"
    cwe_id = "CWE-841"  # Improper Enforcement of Behavioral Workflow
    confidence = 0.6
    
    # Enhanced metadata
    stability = "experimental"
    maturity = "alpha"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def __init__(self):
        super().__init__()
        self.tags.add("reentrancy")
        self.tags.add("external_call")
        self.references = [
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            "https://blog.openzeppelin.com/reentrancy-after-istanbul/"
        ]
        
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns for reentrancy vulnerabilities."""
        
        # Pattern 1: External calls
        self.add_pattern(
            regex=r"\.call\s*\(",
            title="Potential reentrancy-sensitive external call",
            description=(
                "External call detected. Ensure state changes occur "
                "before external interactions and employ reentrancy guards."
            ),
            confidence=0.6,
            severity=Severity.MEDIUM
        )
        
        # Pattern 2: Send/transfer calls
        self.add_pattern(
            regex=r"\.(send|transfer)\s*\(",
            title="Ether transfer call detected",
            description=(
                "Ether transfer detected. Consider using withdrawal pattern "
                "or reentrancy guards to prevent attacks."
            ),
            confidence=0.5,
            severity=Severity.LOW
        )
        
        # Pattern 3: Delegatecall
        self.add_pattern(
            regex=r"\.delegatecall\s*\(",
            title="Delegatecall detected",
            description=(
                "Delegatecall can be dangerous and may allow reentrancy. "
                "Ensure proper access controls and state protection."
            ),
            confidence=0.8,
            severity=Severity.HIGH
        )
