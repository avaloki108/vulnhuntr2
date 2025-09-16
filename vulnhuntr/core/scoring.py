"""
Scoring Model v1: Severity adjustment & confidence recalculation with transparent factor weights.
Phase 4 implementation with sub-factor contribution export and evidence bundling.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import math

from .models import Finding, CorrelatedFinding, Severity


@dataclass
class ScoringFactors:
    """Individual scoring factors with weights and contributions"""
    
    # Base factors
    base_severity: float = 0.0
    base_confidence: float = 0.0
    
    # Context factors
    function_complexity: float = 0.0
    external_call_density: float = 0.0
    guard_presence: float = 0.0
    state_variable_impact: float = 0.0
    
    # Correlation factors
    cluster_size: float = 0.0
    detector_diversity: float = 0.0
    pattern_significance: float = 0.0
    
    # Evidence factors
    symbolic_confirmation: float = 0.0
    path_complexity: float = 0.0
    reentrancy_risk: float = 0.0
    
    # Proxy/upgrade factors
    proxy_exposure: float = 0.0
    upgrade_slot_risk: float = 0.0
    
    def to_dict(self) -> Dict[str, float]:
        """Export all factor contributions"""
        return {
            "base_severity": self.base_severity,
            "base_confidence": self.base_confidence,
            "function_complexity": self.function_complexity,
            "external_call_density": self.external_call_density,
            "guard_presence": self.guard_presence,
            "state_variable_impact": self.state_variable_impact,
            "cluster_size": self.cluster_size,
            "detector_diversity": self.detector_diversity,
            "pattern_significance": self.pattern_significance,
            "symbolic_confirmation": self.symbolic_confirmation,
            "path_complexity": self.path_complexity,
            "reentrancy_risk": self.reentrancy_risk,
            "proxy_exposure": self.proxy_exposure,
            "upgrade_slot_risk": self.upgrade_slot_risk
        }


@dataclass
class ScoringWeights:
    """Transparent factor weights for scoring model"""
    
    # Base weight (from original finding)
    base_weight: float = 0.40
    
    # Context weights
    complexity_weight: float = 0.08
    call_density_weight: float = 0.12
    guard_weight: float = 0.08
    state_impact_weight: float = 0.10
    
    # Correlation weights
    cluster_weight: float = 0.04
    diversity_weight: float = 0.03
    pattern_weight: float = 0.06
    
    # Evidence weights
    symbolic_weight: float = 0.05
    path_weight: float = 0.02
    reentrancy_weight: float = 0.02
    
    # Proxy/upgrade weights - removed to make weights sum to 1.0
    # proxy_weight: float = 0.00
    # upgrade_weight: float = 0.00
    
    def validate(self) -> bool:
        """Validate that weights sum to approximately 1.0"""
        total = sum([
            self.base_weight, self.complexity_weight, self.call_density_weight,
            self.guard_weight, self.state_impact_weight, self.cluster_weight,
            self.diversity_weight, self.pattern_weight, self.symbolic_weight,
            self.path_weight, self.reentrancy_weight
        ])
        return abs(total - 1.0) < 0.01


@dataclass
class ScoringResult:
    """Result of scoring analysis with detailed breakdown"""
    
    original_severity: Severity
    adjusted_severity: Severity
    original_confidence: float
    adjusted_confidence: float
    
    scoring_factors: ScoringFactors
    factor_weights: ScoringWeights
    
    # Detailed contributions
    severity_adjustment: float = 0.0
    confidence_adjustment: float = 0.0
    total_score: float = 0.0
    
    # Rationale
    adjustment_rationale: str = ""
    key_factors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export complete scoring analysis"""
        return {
            "original_severity": self.original_severity.value,
            "adjusted_severity": self.adjusted_severity.value,
            "original_confidence": self.original_confidence,
            "adjusted_confidence": self.adjusted_confidence,
            "severity_adjustment": self.severity_adjustment,
            "confidence_adjustment": self.confidence_adjustment,
            "total_score": self.total_score,
            "scoring_factors": self.scoring_factors.to_dict(),
            "factor_weights": {
                "base_weight": self.factor_weights.base_weight,
                "complexity_weight": self.factor_weights.complexity_weight,
                "call_density_weight": self.factor_weights.call_density_weight,
                "guard_weight": self.factor_weights.guard_weight,
                "state_impact_weight": self.factor_weights.state_impact_weight,
                "cluster_weight": self.factor_weights.cluster_weight,
                "diversity_weight": self.factor_weights.diversity_weight,
                "pattern_weight": self.factor_weights.pattern_weight,
                "symbolic_weight": self.factor_weights.symbolic_weight,
                "path_weight": self.factor_weights.path_weight,
                "reentrancy_weight": self.factor_weights.reentrancy_weight
            },
            "adjustment_rationale": self.adjustment_rationale,
            "key_factors": self.key_factors
        }


class ScoringEngine:
    """
    Phase 4 scoring engine with transparent factor weights and sub-factor contribution export.
    """
    
    def __init__(self, weights: Optional[ScoringWeights] = None):
        self.weights = weights or ScoringWeights()
        
        # Validate weights
        if not self.weights.validate():
            print("Warning: Scoring weights do not sum to 1.0")
    
    def score_finding(self, finding: Finding, context: Optional[Dict[str, Any]] = None) -> ScoringResult:
        """
        Score an individual finding with detailed factor breakdown.
        
        Args:
            finding: The finding to score
            context: Additional context (path slices, symbolic traces, etc.)
            
        Returns:
            ScoringResult with detailed breakdown
        """
        context = context or {}
        
        # Initialize scoring factors
        factors = ScoringFactors()
        
        # Calculate base factors
        factors.base_severity = finding.severity.score / 10.0
        factors.base_confidence = finding.confidence
        
        # Calculate context factors
        factors.function_complexity = self._calculate_function_complexity(finding, context)
        factors.external_call_density = self._calculate_call_density(finding, context)
        factors.guard_presence = self._calculate_guard_presence(finding, context)
        factors.state_variable_impact = self._calculate_state_impact(finding, context)
        
        # Calculate proxy/upgrade factors
        factors.proxy_exposure = self._calculate_proxy_exposure(finding, context)
        factors.upgrade_slot_risk = self._calculate_upgrade_slot_risk(finding, context)
        
        # Calculate evidence factors
        factors.symbolic_confirmation = self._calculate_symbolic_confirmation(finding, context)
        factors.path_complexity = self._calculate_path_complexity(finding, context)
        factors.reentrancy_risk = self._calculate_reentrancy_risk(finding, context)
        
        # Calculate weighted score
        total_score = self._calculate_total_score(factors)
        
        # Determine adjustments
        severity_adjustment = self._calculate_severity_adjustment(factors, total_score)
        confidence_adjustment = self._calculate_confidence_adjustment(factors, total_score)
        
        # Apply adjustments
        adjusted_severity = self._adjust_severity(finding.severity, severity_adjustment)
        adjusted_confidence = min(1.0, max(0.0, finding.confidence + confidence_adjustment))
        
        # Generate rationale
        rationale, key_factors = self._generate_rationale(factors, severity_adjustment, confidence_adjustment)
        
        return ScoringResult(
            original_severity=finding.severity,
            adjusted_severity=adjusted_severity,
            original_confidence=finding.confidence,
            adjusted_confidence=adjusted_confidence,
            scoring_factors=factors,
            factor_weights=self.weights,
            severity_adjustment=severity_adjustment,
            confidence_adjustment=confidence_adjustment,
            total_score=total_score,
            adjustment_rationale=rationale,
            key_factors=key_factors
        )
    
    def score_correlated_finding(self, corr_finding: CorrelatedFinding, context: Optional[Dict[str, Any]] = None) -> ScoringResult:
        """
        Score a correlated finding with cluster-specific factors.
        
        Args:
            corr_finding: The correlated finding to score
            context: Additional context
            
        Returns:
            ScoringResult with cluster-enhanced scoring
        """
        context = context or {}
        
        # Start with primary finding score
        result = self.score_finding(corr_finding.primary_finding, context)
        
        # Add cluster-specific factors
        result.scoring_factors.cluster_size = self._calculate_cluster_size_factor(corr_finding)
        result.scoring_factors.detector_diversity = self._calculate_detector_diversity(corr_finding)
        result.scoring_factors.pattern_significance = self._calculate_pattern_significance_factor(corr_finding)
        
        # Recalculate with cluster factors
        total_score = self._calculate_total_score(result.scoring_factors)
        result.total_score = total_score
        
        # Recalculate adjustments
        severity_adjustment = self._calculate_severity_adjustment(result.scoring_factors, total_score)
        confidence_adjustment = self._calculate_confidence_adjustment(result.scoring_factors, total_score)
        
        result.severity_adjustment = severity_adjustment
        result.confidence_adjustment = confidence_adjustment
        
        # Apply cluster-enhanced adjustments
        result.adjusted_severity = self._adjust_severity(corr_finding.primary_finding.severity, severity_adjustment)
        result.adjusted_confidence = min(1.0, max(0.0, corr_finding.primary_finding.confidence + confidence_adjustment))
        
        # Update rationale with cluster information
        rationale, key_factors = self._generate_cluster_rationale(result.scoring_factors, corr_finding, severity_adjustment, confidence_adjustment)
        result.adjustment_rationale = rationale
        result.key_factors = key_factors
        
        return result
    
    def _calculate_function_complexity(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate function complexity factor"""
        complexity = 0.0
        
        # Base complexity from code length
        code_length = len(finding.code)
        complexity += min(1.0, code_length / 1000)  # Normalize to 1000 chars
        
        # Path slice complexity
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                node_count = len(slice_info.get("node_sequence", []))
                complexity += min(0.5, node_count / 20)  # Normalize to 20 nodes
        
        return min(1.0, complexity)
    
    def _calculate_call_density(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate external call density factor"""
        call_density = 0.0
        
        # Count external calls in code
        code_lower = finding.code.lower()
        call_patterns = ["call(", ".call", "delegatecall", "staticcall", "send(", "transfer("]
        call_count = sum(1 for pattern in call_patterns if pattern in code_lower)
        
        call_density = min(1.0, call_count / 5)  # Normalize to 5 calls
        
        # Path slice external calls
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                external_calls = slice_info.get("external_calls", [])
                call_density += min(0.3, len(external_calls) / 3)
        
        return min(1.0, call_density)
    
    def _calculate_guard_presence(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate guard presence factor (higher = more secure = lower risk)"""
        guard_factor = 0.0
        
        # Check for common guard patterns
        code_lower = finding.code.lower()
        guard_patterns = ["require(", "assert(", "revert(", "modifier", "onlyowner", "nonreentrant"]
        
        for pattern in guard_patterns:
            if pattern in code_lower:
                guard_factor += 0.15
        
        # Path slice guard information
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                if slice_info.get("has_reentrancy_guard", False):
                    guard_factor += 0.3
                
                # Count guard nodes
                node_sequence = slice_info.get("node_sequence", [])
                guard_nodes = [node for node in node_sequence if node.startswith("GUARD_")]
                guard_factor += min(0.2, len(guard_nodes) / 3)
        
        return min(1.0, guard_factor)
    
    def _calculate_state_impact(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate state variable impact factor"""
        impact = 0.0
        
        # High-impact state variables
        high_impact_vars = ["balance", "owner", "admin", "paused", "price", "reserve", "total"]
        code_lower = finding.code.lower()
        
        for var in high_impact_vars:
            if var in code_lower:
                impact += 0.2
        
        # Path slice state modifications
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                state_mods = slice_info.get("state_modifications", [])
                impact += min(0.4, len(state_mods) / 3)
        
        return min(1.0, impact)
    
    def _calculate_proxy_exposure(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate proxy/delegatecall exposure factor"""
        exposure = 0.0
        
        # Check for proxy patterns
        code_lower = finding.code.lower()
        proxy_patterns = ["delegatecall", "proxy", "implementation", "upgrade"]
        
        for pattern in proxy_patterns:
            if pattern in code_lower:
                exposure += 0.25
        
        # Check for storage slot conflicts
        if "storage" in code_lower and ("slot" in code_lower or "position" in code_lower):
            exposure += 0.3
        
        return min(1.0, exposure)
    
    def _calculate_upgrade_slot_risk(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate upgrade slot detector influence on exposure factor"""
        risk = 0.0
        
        # Check if this is an upgrade-related finding
        if finding.detector in ["upgrade_slot_detector", "storage_collision_detector"]:
            risk += 0.6
        
        # Check for upgrade-related patterns
        code_lower = finding.code.lower()
        upgrade_patterns = ["upgrade", "initialize", "slot", "storage", "collision"]
        
        for pattern in upgrade_patterns:
            if pattern in code_lower:
                risk += 0.1
        
        return min(1.0, risk)
    
    def _calculate_symbolic_confirmation(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate symbolic execution confirmation factor"""
        confirmation = 0.0
        
        # Check for symbolic traces
        symbolic_traces = context.get("symbolic_traces", [])
        if symbolic_traces:
            for trace in symbolic_traces:
                # High exploitability score increases confirmation
                exploitability = trace.get("exploitability_score", 0.0)
                confirmation += exploitability * 0.3
                
                # Matching vulnerability type
                trace_type = trace.get("vulnerability_type", "").lower()
                finding_category = finding.category.lower()
                if trace_type in finding_category or finding_category in trace_type:
                    confirmation += 0.4
        
        return min(1.0, confirmation)
    
    def _calculate_path_complexity(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate path complexity factor from path slices"""
        complexity = 0.0
        
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                # Path length complexity
                node_count = len(slice_info.get("node_sequence", []))
                complexity += min(0.3, node_count / 30)
                
                # Cross-contract hop complexity
                hop_count = slice_info.get("hop_count", 0)
                complexity += min(0.2, hop_count / 2)
                
                # Termination reason impact
                termination = slice_info.get("termination_reason", "")
                if termination == "loop_detected":
                    complexity += 0.2
                elif termination == "max_nodes":
                    complexity += 0.1
        
        return min(1.0, complexity)
    
    def _calculate_reentrancy_risk(self, finding: Finding, context: Dict[str, Any]) -> float:
        """Calculate reentrancy-specific risk factor"""
        risk = 0.0
        
        # Base reentrancy detection
        if "reentrancy" in finding.category.lower() or "reentrancy" in finding.detector.lower():
            risk += 0.5
        
        # Check for external calls without guards
        path_slices = context.get("path_slices", [])
        if path_slices:
            for slice_info in path_slices:
                external_calls = slice_info.get("external_calls", [])
                has_guard = slice_info.get("has_reentrancy_guard", False)
                
                if external_calls and not has_guard:
                    risk += 0.3
                
                # State changes after external calls
                state_mods = slice_info.get("state_modifications", [])
                if external_calls and state_mods:
                    risk += 0.2
        
        return min(1.0, risk)
    
    def _calculate_cluster_size_factor(self, corr_finding: CorrelatedFinding) -> float:
        """Calculate cluster size factor"""
        cluster_size = len(corr_finding.all_findings)
        return min(1.0, cluster_size / 5)  # Normalize to 5 findings
    
    def _calculate_detector_diversity(self, corr_finding: CorrelatedFinding) -> float:
        """Calculate detector diversity factor"""
        detectors = set(f.detector for f in corr_finding.all_findings)
        return min(1.0, len(detectors) / 3)  # Normalize to 3 different detectors
    
    def _calculate_pattern_significance_factor(self, corr_finding: CorrelatedFinding) -> float:
        """Calculate pattern significance factor"""
        if hasattr(corr_finding, 'significance'):
            return corr_finding.significance
        return 0.0
    
    def _calculate_total_score(self, factors: ScoringFactors) -> float:
        """Calculate weighted total score from all factors"""
        score = (
            factors.base_severity * self.weights.base_weight +
            factors.function_complexity * self.weights.complexity_weight +
            factors.external_call_density * self.weights.call_density_weight +
            (1.0 - factors.guard_presence) * self.weights.guard_weight +  # Inverted: less guards = higher risk
            factors.state_variable_impact * self.weights.state_impact_weight +
            factors.cluster_size * self.weights.cluster_weight +
            factors.detector_diversity * self.weights.diversity_weight +
            factors.pattern_significance * self.weights.pattern_weight +
            factors.symbolic_confirmation * self.weights.symbolic_weight +
            factors.path_complexity * self.weights.path_weight +
            factors.reentrancy_risk * self.weights.reentrancy_weight
            # Note: proxy and upgrade factors are still calculated but not weighted in total score
            # This keeps the scoring system flexible while maintaining deterministic weight validation
        )
        
        return min(1.0, max(0.0, score))
    
    def _calculate_severity_adjustment(self, factors: ScoringFactors, total_score: float) -> float:
        """Calculate severity adjustment based on total score"""
        # Threshold-based adjustment
        if total_score >= 0.8:
            return 2.0  # Increase by 2 levels
        elif total_score >= 0.7:
            return 1.0  # Increase by 1 level
        elif total_score >= 0.6:
            return 0.5  # Increase by half level
        elif total_score <= 0.3:
            return -1.0  # Decrease by 1 level
        else:
            return 0.0  # No change
    
    def _calculate_confidence_adjustment(self, factors: ScoringFactors, total_score: float) -> float:
        """Calculate confidence adjustment based on factors"""
        adjustment = 0.0
        
        # Symbolic confirmation boost
        adjustment += factors.symbolic_confirmation * 0.2
        
        # Cluster evidence boost
        adjustment += factors.cluster_size * 0.1
        adjustment += factors.detector_diversity * 0.1
        
        # Guard presence reduces confidence (fewer guards = higher confidence in vulnerability)
        adjustment += (1.0 - factors.guard_presence) * 0.15
        
        # High-impact state variables increase confidence
        adjustment += factors.state_variable_impact * 0.1
        
        return adjustment
    
    def _adjust_severity(self, original: Severity, adjustment: float) -> Severity:
        """Apply severity adjustment"""
        if adjustment >= 2.0:
            if original == Severity.MEDIUM:
                return Severity.CRITICAL
            elif original == Severity.LOW:
                return Severity.HIGH
            elif original == Severity.INFO:
                return Severity.MEDIUM
        elif adjustment >= 1.0:
            if original == Severity.HIGH:
                return Severity.CRITICAL
            elif original == Severity.MEDIUM:
                return Severity.HIGH
            elif original == Severity.LOW:
                return Severity.MEDIUM
            elif original == Severity.INFO:
                return Severity.LOW
        elif adjustment >= 0.5:
            if original == Severity.LOW:
                return Severity.MEDIUM
            elif original == Severity.INFO:
                return Severity.LOW
        elif adjustment <= -1.0:
            if original == Severity.CRITICAL:
                return Severity.HIGH
            elif original == Severity.HIGH:
                return Severity.MEDIUM
            elif original == Severity.MEDIUM:
                return Severity.LOW
            elif original == Severity.LOW:
                return Severity.INFO
        
        return original
    
    def _generate_rationale(self, factors: ScoringFactors, sev_adj: float, conf_adj: float) -> Tuple[str, List[str]]:
        """Generate human-readable rationale for scoring adjustments"""
        key_factors = []
        rationale_parts = []
        
        # Severity adjustments
        if sev_adj > 0:
            rationale_parts.append(f"Severity increased by {sev_adj}")
            if factors.external_call_density > 0.5:
                key_factors.append("High external call density")
            if factors.state_variable_impact > 0.5:
                key_factors.append("High-impact state variables")
            if factors.guard_presence < 0.3:
                key_factors.append("Insufficient guard protections")
        elif sev_adj < 0:
            rationale_parts.append(f"Severity decreased by {abs(sev_adj)}")
            if factors.guard_presence > 0.7:
                key_factors.append("Strong guard protections")
        
        # Confidence adjustments
        if conf_adj > 0.1:
            rationale_parts.append(f"Confidence increased by {conf_adj:.2f}")
            if factors.symbolic_confirmation > 0.5:
                key_factors.append("Symbolic execution confirmation")
            if factors.cluster_size > 0.5:
                key_factors.append("Large vulnerability cluster")
        
        # Special factors
        if factors.proxy_exposure > 0.5:
            key_factors.append("Proxy/upgrade risk exposure")
        if factors.reentrancy_risk > 0.5:
            key_factors.append("Reentrancy attack vector")
        
        rationale = "; ".join(rationale_parts) if rationale_parts else "No significant adjustments"
        return rationale, key_factors
    
    def _generate_cluster_rationale(self, factors: ScoringFactors, corr_finding: CorrelatedFinding, sev_adj: float, conf_adj: float) -> Tuple[str, List[str]]:
        """Generate rationale for cluster-enhanced scoring"""
        rationale, key_factors = self._generate_rationale(factors, sev_adj, conf_adj)
        
        # Add cluster-specific factors
        cluster_parts = []
        if factors.cluster_size > 0.3:
            cluster_parts.append(f"Cluster of {len(corr_finding.all_findings)} related findings")
        if factors.detector_diversity > 0.5:
            detectors = set(f.detector for f in corr_finding.all_findings)
            cluster_parts.append(f"Confirmed by {len(detectors)} different detectors")
        if factors.pattern_significance > 0.7:
            cluster_parts.append("High pattern significance")
        
        if cluster_parts:
            rationale += "; " + "; ".join(cluster_parts)
            key_factors.extend(["Correlated vulnerability cluster", "Multi-detector confirmation"])
        
        return rationale, key_factors