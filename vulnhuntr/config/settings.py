"""
Configuration settings manager for vulnhuntr2.
Handles loading and validating configuration from files and environment variables.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union, cast
try:
    import tomllib as tomli  # Python 3.11+
except Exception:
    import tomli  # type: ignore

from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

class DetectorConfig(BaseModel):
    """Configuration for detector selection."""
    enabled: List[str] = Field(default_factory=list)
    disabled: List[str] = Field(default_factory=list)
    categories: Optional[List[str]] = None
    min_confidence: float = 0.0
    max_confidence: float = 1.0

class LLMConfig(BaseModel):
    """Configuration for LLM integration."""
    enabled: bool = False
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 30

class AnalysisConfig(BaseModel):
    """Configuration for analysis behavior."""
    enable_correlation: bool = False
    enable_poc_generation: bool = False
    poc_output_dir: Optional[str] = None
    use_slither: bool = False
    slither_json_file: Optional[str] = None
    enable_path_slicing: bool = False
    enable_symbolic_exploration: bool = False
    enable_scoring: bool = False
    enable_evidence_bundles: bool = False
    path_slicing_max_nodes: int = 80
    path_slicing_cache_dir: Optional[str] = None
    symbolic_engine: str = "mythril"
    symbolic_max_time_per_function: int = 60
    symbolic_max_total_time: int = 300
    symbolic_max_paths: int = 10
    symbolic_max_functions: int = 5
    symbolic_trigger_min_severity: str = "MEDIUM"
    symbolic_trigger_min_cluster_size: int = 2
    symbolic_trigger_min_significance: float = 0.55
    correlation_location_proximity_lines: int = 10
    correlation_confidence_boost_multi_source: float = 0.2
    correlation_severity_elevation_threshold: int = 3
    scoring_enable_transparent_weights: bool = False
    scoring_export_sub_factors: bool = False
    scoring_proxy_awareness: bool = False
    scoring_upgrade_slot_influence: bool = False

class OutputConfig(BaseModel):
    """Configuration for output formatting."""
    format: str = "table"
    json_file: Optional[str] = None
    correlated_json_file: Optional[str] = None
    min_severity: str = "INFO"
    show_code: bool = True
    show_references: bool = True

class ReportingConfig(BaseModel):
    """Configuration for reporting and CI integration."""
    fail_on_findings: bool = False
    fail_on_severity: Optional[str] = None
    fail_on_confidence: Optional[float] = None
    fail_on_finding_count: Optional[int] = None
    sarif: bool = False
    markdown_summary: bool = False

class IgnoreRulesConfig(BaseModel):
    """Configuration for ignore rules."""
    patterns: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    directories: List[str] = Field(default_factory=list)

class Settings(BaseModel):
    """Main configuration settings."""
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    ignore: IgnoreRulesConfig = Field(default_factory=IgnoreRulesConfig)
    
    @model_validator(mode="after")
    def validate_settings(self) -> 'Settings':
        """Validate settings consistency."""
        # Validate severity values
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        
        if self.reporting.fail_on_severity and self.reporting.fail_on_severity not in valid_severities:
            self.reporting.fail_on_severity = "HIGH"
            logger.warning(f"Invalid fail_on_severity value. Using default: HIGH")
            
        if self.output.min_severity not in valid_severities:
            self.output.min_severity = "INFO"
            logger.warning(f"Invalid min_severity value. Using default: INFO")
            
        # Validate analysis settings
        if self.analysis.enable_symbolic_exploration and self.analysis.symbolic_engine not in ["mythril"]:
            self.analysis.symbolic_engine = "mythril"
            logger.warning(f"Invalid symbolic engine. Using default: mythril")
            
        # Validate output format
        valid_formats = {"table", "json", "sarif"}
        if self.output.format not in valid_formats:
            self.output.format = "table"
            logger.warning(f"Invalid output format. Using default: table")
            
        return self

class ConfigManager:
    """Manages configuration loading and environment overrides."""
    
    def __init__(self):
        self._config: Optional[Settings] = None
        self._loaded_from: Optional[str] = None
        
    @property
    def config(self) -> Settings:
        """Get current configuration, loading default if not loaded."""
        if self._config is None:
            self._load_default()
        return cast(Settings, self._config)
    
    def _load_default(self) -> None:
        """Load default configuration."""
        self._config = Settings()
        self._loaded_from = "defaults"
        
    def _load_from_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Load configuration from a TOML file."""
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"Configuration file not found: {path}")
            return {}
            
        try:
            with open(path, "rb") as f:
                return tomli.load(f)
        except Exception as e:
            logger.error(f"Error loading configuration from {path}: {e}")
            return {}
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        env_prefix = "VULNHUNTR_"
        
        # Define mappings from env vars to config attributes
        mappings = {
            "LLM_ENABLED": ("llm", "enabled", lambda v: v.lower() == "true"),
            "LLM_API_KEY": ("llm", "api_key", lambda v: v),
            "LLM_MODEL": ("llm", "model", lambda v: v),
            "ANALYSIS_ENABLE_CORRELATION": ("analysis", "enable_correlation", lambda v: v.lower() == "true"),
            "ANALYSIS_USE_SLITHER": ("analysis", "use_slither", lambda v: v.lower() == "true"),
            "FAIL_ON_FINDINGS": ("reporting", "fail_on_findings", lambda v: v.lower() == "true"),
            "FAIL_ON_SEVERITY": ("reporting", "fail_on_severity", lambda v: v.upper()),
            "OUTPUT_FORMAT": ("output", "format", lambda v: v.lower()),
            "OUTPUT_JSON_FILE": ("output", "json_file", lambda v: v),
        }
        
        for env_key, (section, key, transform) in mappings.items():
            env_var = f"{env_prefix}{env_key}"
            if env_var in os.environ:
                value = transform(os.environ[env_var])
                logger.debug(f"Applying environment override: {env_var}={value}")
                
                if hasattr(self._config, section):
                    section_obj = getattr(self._config, section)
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)
        
        # Handle special cases for detectors enabled/disabled lists
        if f"{env_prefix}DETECTORS_ENABLED" in os.environ:
            self._config.detectors.enabled = [
                x.strip() for x in os.environ[f"{env_prefix}DETECTORS_ENABLED"].split(",")
            ]
            
        if f"{env_prefix}DETECTORS_DISABLED" in os.environ:
            self._config.detectors.disabled = [
                x.strip() for x in os.environ[f"{env_prefix}DETECTORS_DISABLED"].split(",")
            ]
    
    def load(self, config_path: Optional[Union[str, Path]] = None) -> Settings:
        """
        Load configuration from a file with environment overrides.
        
        Args:
            config_path: Path to configuration file (optional)
            
        Returns:
            Loaded configuration
        """
        # First load default config
        self._load_default()
        
        # Try standard locations if config_path not specified
        if not config_path:
            # Look for config in current directory
            if Path("./vulnhuntr.toml").exists():
                config_path = "./vulnhuntr.toml"
            # Look for config in user home directory
            elif Path.home().joinpath(".config/vulnhuntr.toml").exists():
                config_path = Path.home().joinpath(".config/vulnhuntr.toml")
        
        # Load from file if specified or found
        if config_path:
            config_dict = self._load_from_file(config_path)
            if config_dict:
                try:
                    self._config = Settings.model_validate(config_dict)
                    self._loaded_from = str(config_path)
                except Exception as e:
                    logger.error(f"Error validating configuration: {e}")
                    self._load_default()
        
        # Apply environment overrides
        self._apply_env_overrides()
        
        return self.config
    
    def is_file_ignored(self, file_path: Union[str, Path]) -> bool:
        """
        Check if a file should be ignored based on ignore rules.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file should be ignored, False otherwise
        """
        path = Path(file_path)
        
        # Check ignored directories
        for dir_pattern in self.config.ignore.directories:
            if any(parent.name == dir_pattern for parent in path.parents):
                return True
        
        # Check ignored files
        for file_pattern in self.config.ignore.files:
            if path.name == file_pattern:
                return True
        
        # Check ignored patterns (glob-style)
        import fnmatch
        for pattern in self.config.ignore.patterns:
            if fnmatch.fnmatch(str(path), pattern):
                return True
        
        return False