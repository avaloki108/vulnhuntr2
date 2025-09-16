"""
Correlation engine for clustering related findings and elevating severity/confidence.
Legacy wrapper for Phase 4 enhanced correlation engine.
"""
from __future__ import annotations

from typing import List

from .models import Finding, CorrelatedFinding
from ..correlation import EnhancedCorrelationEngine


class CorrelationEngine:
    """
    Legacy correlation engine - now wraps the enhanced Phase 4 engine.
    """
    
    def __init__(self):
        # Configuration for correlation thresholds (kept for compatibility)
        self.location_proximity_lines = 10
        self.title_similarity_threshold = 0.7
        self.confidence_boost_multi_source = 0.2
        self.severity_elevation_threshold = 3  # Number of related findings needed
        
        # Use enhanced engine internally
        self._enhanced_engine = EnhancedCorrelationEngine()
    
    def correlate_findings(self, findings: List[Finding]) -> List[CorrelatedFinding]:
        """
        Analyze findings and group related ones into correlated findings.
        
        Args:
            findings: List of raw findings to correlate
            
        Returns:
            List of CorrelatedFinding objects with elevated metadata
        """
        # Use enhanced engine and return just the correlated findings (ignore warnings for legacy compatibility)
        correlated_findings, _warnings = self._enhanced_engine.correlate_findings(findings)
        return correlated_findings