"""
Correlation engine for clustering related findings and elevating severity/confidence.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple
import re

from .models import Finding, CorrelatedFinding, Severity


class CorrelationEngine:
    """
    Engine for analyzing relationships between findings and creating correlated groups.
    """
    
    def __init__(self):
        # Configuration for correlation thresholds
        self.location_proximity_lines = 10
        self.title_similarity_threshold = 0.7
        self.confidence_boost_multi_source = 0.2
        self.severity_elevation_threshold = 3  # Number of related findings needed
    
    def correlate_findings(self, findings: List[Finding]) -> List[CorrelatedFinding]:
        """
        Analyze findings and group related ones into correlated findings.
        
        Args:
            findings: List of raw findings to correlate
            
        Returns:
            List of CorrelatedFinding objects with elevated metadata
        """
        if not findings:
            return []
        
        # Group findings by various correlation strategies
        clusters = self._cluster_findings(findings)
        correlated = []
        
        # Process each cluster
        for cluster_type, cluster_findings in clusters.items():
            if len(cluster_findings) == 1:
                # Single finding - create minimal correlated finding
                primary = cluster_findings[0]
                correlated.append(CorrelatedFinding(
                    primary_finding=primary,
                    correlation_type="singleton"
                ))
            else:
                # Multiple findings - create enhanced correlation
                correlated_finding = self._create_correlated_finding(
                    cluster_findings, cluster_type
                )
                correlated.append(correlated_finding)
        
        return correlated
    
    def _cluster_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """
        Cluster findings using multiple strategies.
        
        Returns:
            Dictionary mapping cluster keys to lists of findings
        """
        clusters = {}
        processed_findings = set()
        
        # Strategy 1: Category + File clustering
        category_clusters = self._cluster_by_category_and_file(findings)
        for cluster_key, cluster_findings in category_clusters.items():
            if len(cluster_findings) > 1:
                clusters[f"category_file_{cluster_key}"] = cluster_findings
                processed_findings.update(id(f) for f in cluster_findings)
        
        # Strategy 2: Location proximity clustering
        location_clusters = self._cluster_by_location_proximity(
            [f for f in findings if id(f) not in processed_findings]
        )
        for cluster_key, cluster_findings in location_clusters.items():
            if len(cluster_findings) > 1:
                clusters[f"location_{cluster_key}"] = cluster_findings
                processed_findings.update(id(f) for f in cluster_findings)
        
        # Strategy 3: Title pattern clustering
        title_clusters = self._cluster_by_title_pattern(
            [f for f in findings if id(f) not in processed_findings]
        )
        for cluster_key, cluster_findings in title_clusters.items():
            if len(cluster_findings) > 1:
                clusters[f"title_pattern_{cluster_key}"] = cluster_findings
                processed_findings.update(id(f) for f in cluster_findings)
        
        # Add remaining findings as singletons
        remaining_findings = [f for f in findings if id(f) not in processed_findings]
        for i, finding in enumerate(remaining_findings):
            clusters[f"singleton_{i}"] = [finding]
        
        return clusters
    
    def _cluster_by_category_and_file(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Cluster findings by category and file."""
        clusters = defaultdict(list)
        
        for finding in findings:
            key = f"{finding.category}_{finding.file}"
            clusters[key].append(finding)
        
        return dict(clusters)
    
    def _cluster_by_location_proximity(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Cluster findings that are close in location within the same file."""
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
    
    def _cluster_by_title_pattern(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Cluster findings with similar title patterns."""
        clusters = defaultdict(list)
        
        # Simple pattern-based clustering
        for finding in findings:
            # Extract pattern from title (remove specific details)
            pattern = self._extract_title_pattern(finding.title)
            clusters[pattern].append(finding)
        
        # Only return clusters with multiple findings
        return {k: v for k, v in clusters.items() if len(v) > 1}
    
    def _extract_title_pattern(self, title: str) -> str:
        """Extract a general pattern from a specific title."""
        # Remove specific variable names, numbers, addresses
        pattern = re.sub(r'\b[a-fA-F0-9]{40}\b', 'ADDRESS', title)  # Ethereum addresses
        pattern = re.sub(r'\b\d+\b', 'NUMBER', pattern)  # Numbers
        pattern = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', 'IDENTIFIER', pattern)  # Identifiers
        
        return pattern.lower().strip()
    
    def _create_correlated_finding(self, findings: List[Finding], cluster_type: str) -> CorrelatedFinding:
        """
        Create a CorrelatedFinding from a cluster of related findings.
        """
        # Choose primary finding (highest severity, then highest confidence)
        primary = max(findings, key=lambda f: (f.severity.score, f.confidence))
        related = [f for f in findings if f != primary]
        
        # Calculate severity elevation
        elevated_severity = None
        if len(findings) >= self.severity_elevation_threshold:
            elevated_severity = self._calculate_elevated_severity(findings)
        
        # Calculate confidence boost
        confidence_boost = self._calculate_confidence_boost(findings, cluster_type)
        
        # Generate analysis
        pattern_description = self._generate_pattern_description(findings, cluster_type)
        attack_vector = self._generate_attack_vector(findings)
        impact_analysis = self._generate_impact_analysis(findings)
        
        return CorrelatedFinding(
            primary_finding=primary,
            related_findings=related,
            correlation_type=cluster_type,
            elevated_severity=elevated_severity,
            confidence_boost=confidence_boost,
            pattern_description=pattern_description,
            attack_vector=attack_vector,
            impact_analysis=impact_analysis,
        )
    
    def _calculate_elevated_severity(self, findings: List[Finding]) -> Severity:
        """Calculate elevated severity based on multiple related findings."""
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
    
    def _calculate_confidence_boost(self, findings: List[Finding], cluster_type: str) -> float:
        """Calculate confidence boost based on correlation strength."""
        base_boost = 0.0
        
        # Multi-source boost
        detectors = set(f.detector for f in findings)
        if len(detectors) > 1:
            base_boost += self.confidence_boost_multi_source
        
        # Cluster type specific boosts
        if "category_file" in cluster_type:
            base_boost += 0.15  # Same category and file is strong correlation
        elif "location" in cluster_type:
            base_boost += 0.1   # Location proximity is moderate correlation
        elif "title_pattern" in cluster_type:
            base_boost += 0.05  # Title similarity is weak correlation
        
        return min(0.4, base_boost)  # Cap at 0.4 to avoid over-confidence
    
    def _generate_pattern_description(self, findings: List[Finding], cluster_type: str) -> str:
        """Generate human-readable description of the correlation pattern."""
        if "category_file" in cluster_type:
            category = findings[0].category
            file_name = findings[0].file.split('/')[-1]
            return f"Multiple {category} vulnerabilities detected in {file_name}"
        
        elif "location" in cluster_type:
            lines = [f.line for f in findings]
            min_line, max_line = min(lines), max(lines)
            file_name = findings[0].file.split('/')[-1]
            return f"Cluster of vulnerabilities in {file_name} lines {min_line}-{max_line}"
        
        elif "title_pattern" in cluster_type:
            return f"Pattern of similar vulnerabilities: {findings[0].title[:50]}..."
        
        return f"Correlated vulnerabilities ({len(findings)} findings)"
    
    def _generate_attack_vector(self, findings: List[Finding]) -> str:
        """Generate potential attack vector analysis."""
        categories = set(f.category for f in findings)
        
        if "reentrancy" in [cat.lower() for cat in categories]:
            return "Potential for reentrancy-based fund drainage through external call exploitation"
        elif "oracle" in [cat.lower() for cat in categories]:
            return "Oracle manipulation attack vector through price feed tampering"
        elif "flashloan" in [cat.lower() for cat in categories]:
            return "Flash loan attack vector with atomicity abuse for profit extraction"
        
        return "Compound vulnerability allowing escalated exploitation"
    
    def _generate_impact_analysis(self, findings: List[Finding]) -> str:
        """Generate impact analysis for the correlated findings."""
        severities = [f.severity for f in findings]
        critical_count = sum(1 for s in severities if s == Severity.CRITICAL)
        high_count = sum(1 for s in severities if s == Severity.HIGH)
        
        if critical_count > 0:
            return "Critical impact: Potential for complete contract compromise and fund loss"
        elif high_count >= 2:
            return "High impact: Multiple attack vectors allowing significant asset drainage"
        else:
            return "Moderate impact: Combined vulnerabilities increase overall risk profile"