"""
Enhanced correlation engine with runtime-loaded taxonomy and deterministic clustering.
Phase 4 implementation with pattern-based clustering and sophisticated scoring.
"""
from __future__ import annotations

import hashlib
import yaml
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import re

from ..core.models import Finding, CorrelatedFinding, Severity


@dataclass
class CorrelationPattern:
    """Schema for correlation patterns loaded from patterns.yml"""
    name: str
    kind: str
    member_detectors: List[str]
    join_keys: List[str]
    min_members: int
    weights: Dict[str, float]
    notes: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CorrelationPattern:
        """Create pattern from YAML data"""
        return cls(
            name=data["name"],
            kind=data["kind"],
            member_detectors=data["member_detectors"],
            join_keys=data["join_keys"],
            min_members=data["min_members"],
            weights=data["weights"],
            notes=data["notes"]
        )


@dataclass
class ClusterMetadata:
    """Enhanced metadata for deterministic clusters"""
    cluster_id: str
    kind: str
    member_ids: List[str]
    pattern_name: Optional[str] = None
    significance: float = 0.0
    deterministic_fingerprint: str = ""
    created_timestamp: Optional[float] = None


@dataclass
class EvidenceBundle:
    """Evidence bundle with deterministic ID and comprehensive metadata"""
    evidence_id: str
    finding_id: str
    path_slices: List[Dict[str, Any]] = field(default_factory=list)
    symbolic_traces: List[Dict[str, Any]] = field(default_factory=list)
    variables_of_interest: List[str] = field(default_factory=list)
    mini_repro_sources: List[str] = field(default_factory=list)
    rationale: str = ""
    compiler_context: Dict[str, Any] = field(default_factory=dict)
    timing_metrics: Dict[str, float] = field(default_factory=dict)
    budget_consumption: Dict[str, Any] = field(default_factory=dict)


class EnhancedCorrelationEngine:
    """
    Phase 4 enhanced correlation engine with runtime-loaded patterns and deterministic IDs.
    """
    
    def __init__(self, patterns_path: Optional[Path] = None):
        self.patterns_path = patterns_path or Path(__file__).parent / "patterns.yml"
        self.patterns: List[CorrelationPattern] = []
        self.unknown_detectors: Set[str] = set()
        
        # Configuration for correlation thresholds
        self.location_proximity_lines = 10
        self.title_similarity_threshold = 0.7
        self.confidence_boost_multi_source = 0.2
        self.severity_elevation_threshold = 3
        
        # Load patterns at initialization
        self._load_patterns()
    
    def _load_patterns(self):
        """Load correlation patterns from patterns.yml"""
        try:
            if self.patterns_path.exists():
                with open(self.patterns_path, 'r') as f:
                    data = yaml.safe_load(f)
                    
                if data and 'patterns' in data:
                    for pattern_data in data['patterns']:
                        pattern = CorrelationPattern.from_dict(pattern_data)
                        self.patterns.append(pattern)
                        
        except Exception as e:
            # Non-fatal warning for pattern loading failure
            print(f"Warning: Failed to load correlation patterns: {e}")
    
    def correlate_findings(self, findings: List[Finding]) -> Tuple[List[CorrelatedFinding], List[str]]:
        """
        Enhanced correlation with pattern-based clustering and deterministic IDs.
        
        Returns:
            Tuple of (correlated_findings, warnings)
        """
        if not findings:
            return [], []
        
        warnings = []
        
        # Reset unknown detectors tracking
        self.unknown_detectors.clear()
        
        # Cluster findings using multiple strategies
        clusters = self._cluster_findings_enhanced(findings)
        correlated = []
        
        # Process each cluster with enhanced metadata
        for cluster_key, cluster_data in clusters.items():
            cluster_findings = cluster_data["findings"]
            cluster_metadata = cluster_data["metadata"]
            
            if len(cluster_findings) == 1:
                # Single finding - create minimal correlated finding
                primary = cluster_findings[0]
                correlated_finding = CorrelatedFinding(
                    primary_finding=primary,
                    correlation_type="singleton"
                )
                # Add evidence bundle
                evidence_bundle = self._create_evidence_bundle(primary)
                correlated_finding.evidence_bundle = evidence_bundle
                correlated.append(correlated_finding)
            else:
                # Multiple findings - create enhanced correlation
                correlated_finding = self._create_enhanced_correlated_finding(
                    cluster_findings, cluster_metadata
                )
                correlated.append(correlated_finding)
        
        # Generate warnings for unknown detectors
        if self.unknown_detectors:
            for detector in self.unknown_detectors:
                warnings.append(f"Unknown detector '{detector}' referenced in patterns")
        
        return correlated, warnings
    
    def _cluster_findings_enhanced(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """
        Enhanced clustering with pattern-based approach and deterministic IDs.
        """
        clusters = {}
        processed_findings = set()
        
        # Strategy 1: Pattern-based clustering using loaded taxonomy
        pattern_clusters = self._cluster_by_patterns(findings)
        for cluster_key, cluster_data in pattern_clusters.items():
            clusters[cluster_key] = cluster_data
            processed_findings.update(id(f) for f in cluster_data["findings"])
        
        # Strategy 2: Legacy clustering for unmatched findings
        remaining_findings = [f for f in findings if id(f) not in processed_findings]
        
        # Category + File clustering
        category_clusters = self._cluster_by_category_and_file(remaining_findings)
        for cluster_key, cluster_findings in category_clusters.items():
            if len(cluster_findings) > 1:
                cluster_id = self._generate_cluster_id("category_file", cluster_findings)
                clusters[f"category_file_{cluster_key}"] = {
                    "findings": cluster_findings,
                    "metadata": ClusterMetadata(
                        cluster_id=cluster_id,
                        kind="category_file",
                        member_ids=[self._generate_finding_id(f) for f in cluster_findings]
                    )
                }
                processed_findings.update(id(f) for f in cluster_findings)
        
        # Location proximity clustering
        remaining_findings = [f for f in findings if id(f) not in processed_findings]
        location_clusters = self._cluster_by_location_proximity(remaining_findings)
        for cluster_key, cluster_findings in location_clusters.items():
            if len(cluster_findings) > 1:
                cluster_id = self._generate_cluster_id("location", cluster_findings)
                clusters[f"location_{cluster_key}"] = {
                    "findings": cluster_findings,
                    "metadata": ClusterMetadata(
                        cluster_id=cluster_id,
                        kind="location",
                        member_ids=[self._generate_finding_id(f) for f in cluster_findings]
                    )
                }
                processed_findings.update(id(f) for f in cluster_findings)
        
        # Add remaining findings as singletons
        remaining_findings = [f for f in findings if id(f) not in processed_findings]
        for i, finding in enumerate(remaining_findings):
            finding_id = self._generate_finding_id(finding)
            clusters[f"singleton_{i}"] = {
                "findings": [finding],
                "metadata": ClusterMetadata(
                    cluster_id=f"singleton_{finding_id}",
                    kind="singleton",
                    member_ids=[finding_id]
                )
            }
        
        return clusters
    
    def _cluster_by_patterns(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Cluster findings using loaded correlation patterns"""
        clusters = {}
        
        for pattern in self.patterns:
            # Find findings that match this pattern's detectors
            matching_findings = []
            for finding in findings:
                if finding.detector in pattern.member_detectors:
                    matching_findings.append(finding)
                elif finding.detector not in pattern.member_detectors:
                    # Track unknown detectors for warnings
                    for detector in pattern.member_detectors:
                        all_detector_names = {f.detector for f in findings}
                        if detector not in all_detector_names:
                            self.unknown_detectors.add(detector)
            
            # Check if we have enough members and join key overlap
            if len(matching_findings) >= pattern.min_members:
                # Group by join key overlaps
                join_groups = self._group_by_join_keys(matching_findings, pattern.join_keys)
                
                for group_key, group_findings in join_groups.items():
                    if len(group_findings) >= pattern.min_members:
                        # Create deterministic cluster ID
                        cluster_id = self._generate_cluster_id(pattern.kind, group_findings)
                        
                        # Calculate significance score
                        significance = self._calculate_pattern_significance(
                            group_findings, pattern
                        )
                        
                        clusters[f"pattern_{pattern.name}_{group_key}"] = {
                            "findings": group_findings,
                            "metadata": ClusterMetadata(
                                cluster_id=cluster_id,
                                kind=pattern.kind,
                                member_ids=[self._generate_finding_id(f) for f in group_findings],
                                pattern_name=pattern.name,
                                significance=significance
                            )
                        }
        
        return clusters
    
    def _group_by_join_keys(self, findings: List[Finding], join_keys: List[str]) -> Dict[str, List[Finding]]:
        """Group findings by join key overlaps"""
        groups = defaultdict(list)
        
        for finding in findings:
            # Extract join key values from finding
            join_values = []
            for join_key in join_keys:
                value = self._extract_join_key_value(finding, join_key)
                if value:
                    join_values.append(value)
            
            # Create group key from sorted join values
            if join_values:
                group_key = "|".join(sorted(join_values))
                groups[group_key].append(finding)
            else:
                # Default group for findings without join key matches
                groups["default"].append(finding)
        
        return dict(groups)
    
    def _extract_join_key_value(self, finding: Finding, join_key: str) -> Optional[str]:
        """Extract join key value from finding based on attribute selector"""
        
        # Simple extraction based on common patterns
        if join_key.startswith("state_vars."):
            var_name = join_key.split(".", 1)[1]
            # Look for variable patterns in code or description
            if var_name in finding.code.lower() or (finding.description and var_name in finding.description.lower()):
                return var_name
        
        elif join_key.startswith("function_name"):
            return finding.function_name
        
        elif join_key.startswith("external_calls."):
            call_type = join_key.split(".", 1)[1]
            # Look for call patterns in code
            if call_type in finding.code.lower():
                return call_type
        
        elif join_key.startswith("modifier_patterns."):
            modifier = join_key.split(".", 1)[1]
            # Look for modifier patterns
            if modifier in finding.code.lower():
                return modifier
        
        return None
    
    def _calculate_pattern_significance(self, findings: List[Finding], pattern: CorrelationPattern) -> float:
        """Calculate significance score for pattern-matched cluster"""
        base_score = pattern.weights.get("base", 0.5)
        
        # Calculate various factors
        severity_factor = max(f.severity.score for f in findings) / 10.0
        confidence_factor = sum(f.confidence for f in findings) / len(findings)
        detector_diversity = len(set(f.detector for f in findings)) / len(pattern.member_detectors)
        
        # Combine factors
        significance = (
            base_score * 0.4 +
            severity_factor * 0.3 +
            confidence_factor * 0.2 +
            detector_diversity * 0.1
        )
        
        return min(1.0, significance)
    
    def _generate_cluster_id(self, kind: str, findings: List[Finding]) -> str:
        """Generate deterministic cluster ID using sha256"""
        member_ids = sorted([self._generate_finding_id(f) for f in findings])
        cluster_data = f"cluster:{kind}:{','.join(member_ids)}"
        return hashlib.sha256(cluster_data.encode('utf-8')).hexdigest()
    
    def _generate_finding_id(self, finding: Finding) -> str:
        """Generate deterministic finding ID"""
        finding_data = f"{finding.detector}:{finding.file}:{finding.line}:{finding.title}"
        return hashlib.sha256(finding_data.encode('utf-8')).hexdigest()[:16]
    
    def _create_evidence_bundle(self, finding: Finding) -> EvidenceBundle:
        """Create evidence bundle for a finding with deterministic ID"""
        finding_id = self._generate_finding_id(finding)
        evidence_id = hashlib.sha256(f"evidence:{finding_id}".encode('utf-8')).hexdigest()
        
        return EvidenceBundle(
            evidence_id=evidence_id,
            finding_id=finding_id,
            variables_of_interest=self._extract_variables_of_interest(finding),
            rationale=self._generate_evidence_rationale(finding)
        )
    
    def _extract_variables_of_interest(self, finding: Finding) -> List[str]:
        """Extract variables of interest from finding"""
        variables = []
        
        # Simple regex-based extraction of variable names
        var_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        matches = re.findall(var_pattern, finding.code)
        
        # Filter out common keywords and keep likely variable names
        keywords = {'function', 'contract', 'if', 'else', 'return', 'require', 'assert', 'msg', 'block', 'tx'}
        for match in matches:
            if match.lower() not in keywords and len(match) > 2:
                variables.append(match)
        
        return list(set(variables))[:10]  # Limit to 10 most relevant
    
    def _generate_evidence_rationale(self, finding: Finding) -> str:
        """Generate human-readable rationale for evidence"""
        return f"Evidence for {finding.detector} vulnerability in {finding.function_name or 'unknown function'}: {finding.title}"
    
    def _cluster_by_category_and_file(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Legacy clustering by category and file"""
        clusters = defaultdict(list)
        
        for finding in findings:
            key = f"{finding.category}_{finding.file}"
            clusters[key].append(finding)
        
        return dict(clusters)
    
    def _cluster_by_location_proximity(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Legacy clustering by location proximity"""
        clusters = defaultdict(list)
        
        # Group by file first
        file_groups = defaultdict(list)
        for finding in findings:
            file_groups[finding.file].append(finding)
        
        for file_path, file_findings in file_groups.items():
            # Sort by line number
            file_findings.sort(key=lambda f: f.line)
            
            cluster_id = 0
            current_cluster = []
            
            for finding in file_findings:
                if not current_cluster:
                    current_cluster.append(finding)
                else:
                    # Check if this finding is close to the last one in current cluster
                    last_line = current_cluster[-1].line
                    if abs(finding.line - last_line) <= self.location_proximity_lines:
                        current_cluster.append(finding)
                    else:
                        # Start new cluster
                        if len(current_cluster) > 1:
                            clusters[f"{file_path}_proximity_{cluster_id}"] = current_cluster
                        cluster_id += 1
                        current_cluster = [finding]
            
            # Add final cluster if it has multiple findings
            if len(current_cluster) > 1:
                clusters[f"{file_path}_proximity_{cluster_id}"] = current_cluster
        
        return dict(clusters)
    
    def _create_enhanced_correlated_finding(self, findings: List[Finding], metadata: ClusterMetadata) -> CorrelatedFinding:
        """Create enhanced correlated finding with metadata and evidence"""
        # Choose primary finding (highest severity, then highest confidence)
        primary = max(findings, key=lambda f: (f.severity.score, f.confidence))
        related = [f for f in findings if f != primary]
        
        # Calculate severity elevation
        elevated_severity = None
        if len(findings) >= self.severity_elevation_threshold:
            elevated_severity = self._calculate_elevated_severity(findings)
        
        # Enhanced confidence boost calculation
        confidence_boost = self._calculate_enhanced_confidence_boost(findings, metadata)
        
        # Generate enhanced analysis
        pattern_description = self._generate_enhanced_pattern_description(findings, metadata)
        attack_vector = self._generate_enhanced_attack_vector(findings, metadata)
        impact_analysis = self._generate_enhanced_impact_analysis(findings, metadata)
        
        # Create evidence bundle for primary finding
        evidence_bundle = self._create_evidence_bundle(primary)
        
        correlated_finding = CorrelatedFinding(
            primary_finding=primary,
            related_findings=related,
            correlation_type=metadata.kind,
            elevated_severity=elevated_severity,
            confidence_boost=confidence_boost,
            pattern_description=pattern_description,
            attack_vector=attack_vector,
            impact_analysis=impact_analysis,
        )
        
        # Add enhanced metadata
        correlated_finding.cluster_metadata = metadata
        correlated_finding.evidence_bundle = evidence_bundle
        correlated_finding.significance = metadata.significance
        
        return correlated_finding
    
    def _calculate_enhanced_confidence_boost(self, findings: List[Finding], metadata: ClusterMetadata) -> float:
        """Enhanced confidence boost calculation with pattern weights"""
        base_boost = 0.0
        
        # Multi-source boost
        detectors = set(f.detector for f in findings)
        if len(detectors) > 1:
            base_boost += self.confidence_boost_multi_source
        
        # Pattern-specific boost
        if metadata.pattern_name:
            # Find pattern weights
            for pattern in self.patterns:
                if pattern.name == metadata.pattern_name:
                    base_boost += pattern.weights.get("base", 0.0) * 0.2
                    break
        
        # Significance boost
        if hasattr(metadata, 'significance'):
            base_boost += metadata.significance * 0.1
        
        # Cluster type specific boosts (legacy)
        if "category_file" in metadata.kind:
            base_boost += 0.15
        elif "location" in metadata.kind:
            base_boost += 0.1
        
        return min(0.5, base_boost)  # Cap at 0.5
    
    def _calculate_elevated_severity(self, findings: List[Finding]) -> Severity:
        """Calculate elevated severity based on multiple related findings"""
        max_severity = max(f.severity for f in findings)
        
        # Elevate severity if we have multiple high-confidence findings
        high_confidence_count = sum(1 for f in findings if f.confidence > 0.7)
        
        if high_confidence_count >= 3:
            if max_severity == Severity.HIGH:
                return Severity.CRITICAL
            elif max_severity == Severity.MEDIUM:
                return Severity.HIGH
            elif max_severity == Severity.LOW:
                return Severity.MEDIUM
        
        return max_severity
    
    def _generate_enhanced_pattern_description(self, findings: List[Finding], metadata: ClusterMetadata) -> str:
        """Generate enhanced pattern description"""
        if metadata.pattern_name:
            # Find pattern notes
            for pattern in self.patterns:
                if pattern.name == metadata.pattern_name:
                    return f"Pattern '{pattern.name}': {pattern.notes} ({len(findings)} findings)"
            
        # Fallback to legacy descriptions
        if "category_file" in metadata.kind:
            category = findings[0].category
            file_name = findings[0].file.split('/')[-1]
            return f"Multiple {category} vulnerabilities detected in {file_name}"
        
        elif "location" in metadata.kind:
            lines = [f.line for f in findings]
            min_line, max_line = min(lines), max(lines)
            file_name = findings[0].file.split('/')[-1]
            return f"Cluster of vulnerabilities in {file_name} lines {min_line}-{max_line}"
        
        return f"Correlated vulnerabilities ({len(findings)} findings)"
    
    def _generate_enhanced_attack_vector(self, findings: List[Finding], metadata: ClusterMetadata) -> str:
        """Generate enhanced attack vector analysis"""
        if metadata.pattern_name:
            # Pattern-specific attack vectors
            if "oracle-manipulation" in metadata.pattern_name:
                return "Oracle manipulation attack vector with price feed tampering and flash loan arbitrage"
            elif "privilege-escalation" in metadata.pattern_name:
                return "Privilege escalation attack vector through access control bypass and administrative function abuse"
            elif "flashloan" in metadata.pattern_name:
                return "Flash loan attack vector with atomicity abuse and invariant violations"
        
        # Fallback to category-based analysis
        categories = set(f.category for f in findings)
        
        if "reentrancy" in [cat.lower() for cat in categories]:
            return "Potential for reentrancy-based fund drainage through external call exploitation"
        elif "oracle" in [cat.lower() for cat in categories]:
            return "Oracle manipulation attack vector through price feed tampering"
        elif "flashloan" in [cat.lower() for cat in categories]:
            return "Flash loan attack vector with atomicity abuse for profit extraction"
        
        return "Compound vulnerability allowing escalated exploitation"
    
    def _generate_enhanced_impact_analysis(self, findings: List[Finding], metadata: ClusterMetadata) -> str:
        """Generate enhanced impact analysis"""
        severities = [f.severity for f in findings]
        critical_count = sum(1 for s in severities if s == Severity.CRITICAL)
        high_count = sum(1 for s in severities if s == Severity.HIGH)
        
        # Factor in significance score
        significance_bonus = ""
        if hasattr(metadata, 'significance') and metadata.significance > 0.8:
            significance_bonus = " with high correlation significance"
        
        if critical_count > 0:
            return f"Critical impact: Potential for complete contract compromise and fund loss{significance_bonus}"
        elif high_count >= 2:
            return f"High impact: Multiple attack vectors allowing significant asset drainage{significance_bonus}"
        else:
            return f"Moderate impact: Combined vulnerabilities increase overall risk profile{significance_bonus}"