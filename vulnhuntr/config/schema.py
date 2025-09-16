"""
Configuration schema for vulnhuntr2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from pathlib import Path

from ..core.models import Severity


@dataclass
class DetectorSelection:
    """Configuration for detector selection and filtering."""
    
    enabled: List[str] = field(default_factory=list)
    disabled: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    min_confidence: float = 0.0
    max_confidence: float = 1.0


@dataclass
class LLMConfig:
    """Configuration for LLM integration."""
    
    enabled: bool = False
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 30


@dataclass
class OutputConfig:
    """Configuration for output formatting and destinations."""
    
    format: str = "table"  # table, json, sarif
    json_file: Optional[Path] = None
    correlated_json_file: Optional[Path] = None
    sarif_file: Optional[Path] = None  # Phase 5: SARIF export
    min_severity: str = "INFO"
    show_code: bool = True
    show_references: bool = True


@dataclass
class ReportingConfig:
    """Configuration for reporting and CI integration."""
    
    fail_on_findings: bool = False
    fail_on_severity: Optional[str] = None
    fail_on_confidence: Optional[float] = None
    fail_on_finding_count: Optional[int] = None
    
    # Phase 5 enhancements
    sarif: bool = False  # Generate SARIF output
    github_code_scanning: bool = False  # GitHub Advanced Security integration
    markdown_summary: bool = False


@dataclass
class PluginConfig:
    """Configuration for plugin system (Phase 5)."""
    
    # Plugin system control
    enable_plugins: bool = False  # Disabled by default
    plugin_dirs: List[Path] = field(default_factory=list)
    
    # Time budgets (ms)
    detector_init_timeout: int = 750
    enrich_timeout: int = 1500
    postprocess_timeout: int = 1500
    
    # Memory guards (MB)
    memory_guard_threshold_mb: int = 100
    
    # Plugin selection
    enabled_plugins: List[str] = field(default_factory=list)
    disabled_plugins: List[str] = field(default_factory=list)


@dataclass
class TriageConfig:
    """Configuration for AI/LLM triage layer (Phase 5)."""
    
    # Triage control (disabled by default)
    enable: bool = False
    
    # Candidate selection
    max_findings: int = 10
    min_severity: str = "MEDIUM"
    
    # Model configuration
    provider: str = "openai"
    model: str = "gpt-4"
    temperature: float = 0.3
    max_tokens: int = 1000
    timeout: int = 30
    
    # Caching
    enable_cache: bool = True
    cache_dir: Optional[Path] = None
    
    # Redaction
    redact_addresses: bool = True
    redact_secrets: bool = True


@dataclass
class AnalysisConfig:
    """Configuration for analysis features."""
    
    enable_correlation: bool = True
    enable_poc_generation: bool = False
    poc_output_dir: Optional[Path] = None
    use_slither: bool = False
    slither_json_file: Optional[Path] = None
    
    # Phase 4 enhancements
    enable_path_slicing: bool = True
    enable_symbolic_exploration: bool = False
    enable_scoring: bool = True
    enable_evidence_bundles: bool = True
    
    # Phase 5 enhancements
    enable_incremental: bool = False  # Disabled by default
    diff_base: Optional[str] = None   # Git ref for diff-based scanning
    
    # Path slicing configuration
    path_slicing_max_nodes: int = 80
    path_slicing_cache_dir: Optional[Path] = None
    
    # Symbolic exploration configuration
    symbolic_engine: str = "mythril"
    symbolic_max_time_per_function: int = 60
    symbolic_max_total_time: int = 300
    symbolic_max_paths: int = 10
    symbolic_max_functions: int = 5
    symbolic_trigger_min_severity: str = "MEDIUM"
    symbolic_trigger_min_cluster_size: int = 2
    symbolic_trigger_min_significance: float = 0.55
    
    # Correlation configuration
    correlation_patterns_file: Optional[Path] = None
    correlation_location_proximity_lines: int = 10
    correlation_confidence_boost_multi_source: float = 0.2
    correlation_severity_elevation_threshold: int = 3
    
    # Scoring configuration
    scoring_enable_transparent_weights: bool = True
    scoring_export_sub_factors: bool = True
    scoring_proxy_awareness: bool = True
    scoring_upgrade_slot_influence: bool = True


@dataclass
class RunConfig:
    """Complete runtime configuration."""
    
    # Core analysis settings
    target_path: Optional[Path] = None
    detectors: DetectorSelection = field(default_factory=DetectorSelection)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    
    # Phase 5 new systems (disabled by default)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    triage: TriageConfig = field(default_factory=TriageConfig)
    
    # Config management
    config_file: Optional[Path] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        from dataclasses import asdict
        result = asdict(self)
        
        # Convert Path objects to strings
        def convert_paths(obj):
            if isinstance(obj, dict):
                return {k: convert_paths(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_paths(item) for item in obj]
            elif isinstance(obj, Path):
                return str(obj)
            else:
                return obj
                
        return convert_paths(result)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RunConfig:
        """Create RunConfig from dictionary."""
        # Convert string paths back to Path objects
        def convert_paths(obj, path_fields: Set[str]):
            if isinstance(obj, dict):
                result = {}
                for k, v in obj.items():
                    if k in path_fields and v is not None:
                        result[k] = Path(v)
                    elif isinstance(v, dict):
                        # Recursively handle nested dicts
                        nested_path_fields = {
                            'json_file', 'correlated_json_file', 'poc_output_dir', 
                            'slither_json_file', 'config_file', 'target_path'
                        }
                        result[k] = convert_paths(v, nested_path_fields)
                    else:
                        result[k] = v
                return result
            else:
                return obj
        
        path_fields = {
            'target_path', 'config_file', 'json_file', 'correlated_json_file',
            'poc_output_dir', 'slither_json_file'
        }
        
        converted_data = convert_paths(data, path_fields)
        
        # Create nested dataclass objects
        config = cls()
        
        if 'detectors' in converted_data:
            config.detectors = DetectorSelection(**converted_data['detectors'])
        if 'analysis' in converted_data:
            config.analysis = AnalysisConfig(**converted_data['analysis'])
        if 'llm' in converted_data:
            config.llm = LLMConfig(**converted_data['llm'])
        if 'output' in converted_data:
            config.output = OutputConfig(**converted_data['output'])
        if 'reporting' in converted_data:
            config.reporting = ReportingConfig(**converted_data['reporting'])
            
        # Set top-level fields
        for field_name in ['target_path', 'config_file']:
            if field_name in converted_data:
                setattr(config, field_name, converted_data[field_name])
        
        return config


@dataclass
class DetectorMeta:
    """Enhanced metadata for detectors."""
    
    name: str
    category: str
    stability: str = "experimental"  # experimental, stable, legacy
    maturity: str = "alpha"  # alpha, beta, stable
    requires_slither: bool = False
    supports_llm_enrichment: bool = False
    enabled_by_default: bool = True