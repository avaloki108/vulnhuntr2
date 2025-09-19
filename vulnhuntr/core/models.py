"""Core data models for vulnerability analysis."""

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Dict, List, Optional, Any, Union
from pathlib import Path


class Severity(IntEnum):
    """Severity levels for findings with deterministic ordering and scores."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def score(self) -> int:
        """Numeric score used for comparisons and gating."""
        return int(self)

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        name = (value or "").upper()
        if name in cls.__members__:
            return cls[name]
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        return self.name


@dataclass
class Variable:
    """Contract state variable."""
    name: str
    type: str
    visibility: str
    line: int
    is_constant: bool = False
    is_immutable: bool = False


@dataclass
class Function:
    """Contract function."""
    name: str
    signature: str
    contract_name: str
    visibility: str
    state_mutability: str
    line_start: int
    line_end: int
    file_path: str
    external_calls: List[str] = field(default_factory=list)
    state_vars_written: List[str] = field(default_factory=list)
    state_vars_read: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False


@dataclass
class Contract:
    """Solidity contract representation."""
    name: str
    file_path: str
    line_start: int
    line_end: int
    variables: List[Variable] = field(default_factory=list)
    is_abstract: bool = False
    inherits_from: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class SlitherResult:
    """Result from Slither analysis."""
    contracts: List[Contract]
    functions: List[Function]
    raw_data: Dict[str, Any]


@dataclass
class Finding:
    """Security finding/vulnerability."""
    detector: str
    title: str
    file: str
    line: int
    severity: Union[Severity, str]
    code: str
    description: str = ""
    recommendation: str = ""
    remediation: str = ""
    confidence: float = 1.0
    gas_impact: Optional[str] = None
    contract_name: Optional[str] = None
    function_name: Optional[str] = None
    end_line: Optional[int] = None
    category: str = "generic"
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Normalize severity to enum if provided as string."""
        if isinstance(self.severity, str):
            try:
                self.severity = Severity.from_string(self.severity)
            except ValueError:
                self.severity = Severity.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Render severity as string for JSON
        sev = d.get("severity")
        if isinstance(sev, Severity):
            d["severity"] = sev.name
        return d


@dataclass
class CorrelatedFinding:
    """Correlated finding cluster representation used by reporting/correlation."""
    primary_finding: Finding
    related_findings: List[Finding] = field(default_factory=list)
    correlation_type: str = "singleton"
    elevated_severity: Optional[Severity] = None
    confidence_boost: float = 0.0
    pattern_description: Optional[str] = None
    attack_vector: Optional[str] = None
    impact_analysis: Optional[str] = None
    # Enhanced metadata (optional)
    cluster_metadata: Optional[Any] = None
    evidence_bundle: Optional[Any] = None
    significance: Optional[float] = None

    @property
    def all_findings(self) -> List[Finding]:
        return [self.primary_finding] + list(self.related_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_finding": self.primary_finding.to_dict(),
            "related_findings": [f.to_dict() for f in self.related_findings],
            "correlation_type": self.correlation_type,
            "elevated_severity": self.elevated_severity.name if isinstance(self.elevated_severity, Severity) else self.elevated_severity,
            "confidence_boost": self.confidence_boost,
            "pattern_description": self.pattern_description,
            "attack_vector": self.attack_vector,
            "impact_analysis": self.impact_analysis,
        }


@dataclass
class ScanContext:
    """Context for the analysis scan."""
    target_path: Union[str, "Path"]
    contracts: List[Contract] = field(default_factory=list)
    functions: List[Function] = field(default_factory=list)
    tool_artifacts: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
