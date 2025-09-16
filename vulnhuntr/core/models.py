"""
Core data models for vulnhuntr2 - unified finding, context, and severity models.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


class Severity(Enum):
    """Vulnerability severity levels with standardized scoring."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def score(self) -> int:
        """Return numeric score for severity comparison."""
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 6,
            Severity.LOW: 4,
            Severity.INFO: 2,
        }[self]
    
    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Create severity from string, case-insensitive."""
        return cls(value.upper())
    
    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.score < other.score
        return NotImplemented
    
    def __le__(self, other):
        if isinstance(other, Severity):
            return self.score <= other.score
        return NotImplemented
    
    def __gt__(self, other):
        if isinstance(other, Severity):
            return self.score > other.score
        return NotImplemented
    
    def __ge__(self, other):
        if isinstance(other, Severity):
            return self.score >= other.score
        return NotImplemented


@dataclass
class ContractFunction:
    """Represents a parsed smart contract function."""
    
    name: str
    signature: str
    visibility: str
    state_mutability: str
    modifiers: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    returns: List[Dict[str, Any]] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0


@dataclass 
class ContractInfo:
    """Represents a parsed smart contract."""
    
    name: str
    file_path: str
    inheritance: List[str] = field(default_factory=list)
    functions: List[ContractFunction] = field(default_factory=list)
    state_variables: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    modifiers: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanContext:
    """Analysis context containing parsed contracts and configuration."""
    
    target_path: Path
    contracts: List[ContractInfo] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    tool_artifacts: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis options
    enable_llm: bool = False
    enable_correlation: bool = True
    enable_poc_generation: bool = False
    
    def get_contract_by_name(self, name: str) -> Optional[ContractInfo]:
        """Find contract by name."""
        for contract in self.contracts:
            if contract.name == name:
                return contract
        return None
    
    def get_functions_by_name(self, func_name: str) -> List[ContractFunction]:
        """Find all functions with given name across contracts."""
        functions = []
        for contract in self.contracts:
            for func in contract.functions:
                if func.name == func_name:
                    functions.append(func)
        return functions


@dataclass
class Finding:
    """Enhanced finding with rich metadata and context."""
    
    # Core identification
    detector: str
    title: str
    file: str
    line: int
    severity: Severity
    code: str
    
    # Enhanced metadata
    description: Optional[str] = None
    confidence: float = 0.5  # 0.0 to 1.0
    category: str = "unknown"
    cwe_id: Optional[str] = None
    
    # Code context
    function_name: Optional[str] = None
    contract_name: Optional[str] = None
    end_line: Optional[int] = None
    
    # Analysis metadata
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    
    # LLM-enhanced fields
    invariant_suggestion: Optional[str] = None
    poc_code: Optional[str] = None
    
    # Phase 6: Multi-chain context
    multi_chain: Optional[Dict[str, Any]] = None  # chains, cross_domain_paths
    
    # Phase 6: Economic simulation
    economic: Optional[Dict[str, Any]] = None  # capital_required_estimate, payoff_bounds, feasibility
    
    # Phase 6: Invariants
    invariants: List[Dict[str, Any]] = field(default_factory=list)  # name, status, method, category, etc.
    
    # Phase 6: Risk model
    risk_model: Optional[Dict[str, Any]] = None  # p_exploit, expected_loss_estimate, modeling_version
    
    # Phase 6: Policy compliance
    policy: Optional[Dict[str, Any]] = None  # violations, compliant
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "detector": self.detector,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value,
            "code": self.code,
            "description": self.description,
            "confidence": self.confidence,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "function_name": self.function_name,
            "contract_name": self.contract_name,
            "end_line": self.end_line,
            "remediation": self.remediation,
            "references": self.references,
            "tags": list(self.tags),
            "invariant_suggestion": self.invariant_suggestion,
            "poc_code": self.poc_code,
            "multi_chain": self.multi_chain,
            "economic": self.economic,
            "invariants": self.invariants,
            "risk_model": self.risk_model,
            "policy": self.policy,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Create Finding from dictionary."""
        # Convert severity string back to enum
        severity = Severity.from_string(data["severity"])
        tags = set(data.get("tags", []))
        
        return cls(
            detector=data["detector"],
            title=data["title"],
            file=data["file"],
            line=data["line"],
            severity=severity,
            code=data["code"],
            description=data.get("description"),
            confidence=data.get("confidence", 0.5),
            category=data.get("category", "unknown"),
            cwe_id=data.get("cwe_id"),
            function_name=data.get("function_name"),
            contract_name=data.get("contract_name"),
            end_line=data.get("end_line"),
            remediation=data.get("remediation"),
            references=data.get("references", []),
            tags=tags,
            invariant_suggestion=data.get("invariant_suggestion"),
            poc_code=data.get("poc_code"),
            multi_chain=data.get("multi_chain"),
            economic=data.get("economic"),
            invariants=data.get("invariants", []),
            risk_model=data.get("risk_model"),
            policy=data.get("policy"),
        )


@dataclass
class CorrelatedFinding:
    """A group of related findings with elevated metadata and evidence bundles."""
    
    primary_finding: Finding
    related_findings: List[Finding] = field(default_factory=list)
    
    # Correlation metadata
    correlation_type: str = "unknown"  # e.g., "category_cluster", "location_cluster"
    elevated_severity: Optional[Severity] = None
    confidence_boost: float = 0.0
    
    # Analysis results
    pattern_description: Optional[str] = None
    attack_vector: Optional[str] = None
    impact_analysis: Optional[str] = None
    
    # Phase 4 enhancements
    cluster_metadata: Optional[Any] = None  # ClusterMetadata from correlation
    evidence_bundle: Optional[Any] = None   # EvidenceBundle from correlation
    significance: float = 0.0               # Pattern significance score
    deterministic_id: Optional[str] = None  # Deterministic cluster ID
    
    @property
    def effective_severity(self) -> Severity:
        """Get the effective severity (elevated if available)."""
        return self.elevated_severity or self.primary_finding.severity
    
    @property
    def effective_confidence(self) -> float:
        """Get boosted confidence score."""
        base_confidence = self.primary_finding.confidence
        return min(1.0, base_confidence + self.confidence_boost)
    
    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings including primary."""
        return [self.primary_finding] + self.related_findings
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "primary_finding": self.primary_finding.to_dict(),
            "related_findings": [f.to_dict() for f in self.related_findings],
            "correlation_type": self.correlation_type,
            "elevated_severity": self.elevated_severity.value if self.elevated_severity else None,
            "confidence_boost": self.confidence_boost,
            "pattern_description": self.pattern_description,
            "attack_vector": self.attack_vector,
            "impact_analysis": self.impact_analysis,
        }
        
        # Phase 4 enhancements
        if self.significance > 0:
            result["significance"] = self.significance
        if self.deterministic_id:
            result["deterministic_id"] = self.deterministic_id
        if self.cluster_metadata:
            result["cluster_metadata"] = {
                "cluster_id": getattr(self.cluster_metadata, 'cluster_id', ''),
                "kind": getattr(self.cluster_metadata, 'kind', ''),
                "pattern_name": getattr(self.cluster_metadata, 'pattern_name', None),
                "significance": getattr(self.cluster_metadata, 'significance', 0.0)
            }
        if self.evidence_bundle:
            result["evidence_bundle"] = {
                "evidence_id": getattr(self.evidence_bundle, 'evidence_id', ''),
                "finding_id": getattr(self.evidence_bundle, 'finding_id', ''),
                "variables_of_interest": getattr(self.evidence_bundle, 'variables_of_interest', []),
                "rationale": getattr(self.evidence_bundle, 'rationale', ''),
                "path_slices": getattr(self.evidence_bundle, 'path_slices', []),
                "symbolic_traces": getattr(self.evidence_bundle, 'symbolic_traces', [])
            }
        
        return result