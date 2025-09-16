"""
Configuration loading with precedence support.
"""
import os
import json
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from .schema import RunConfig, DetectorSelection, LLMConfig, OutputConfig, ReportingConfig, AnalysisConfig


class ConfigLoader:
    """Handles configuration loading with proper precedence."""
    
    ENV_PREFIX = "VULNHUNTR_"
    DEFAULT_CONFIG_FILES = [
        "vulnhuntr.toml",
        ".vulnhuntr.toml",
        "pyproject.toml",  # Look for [tool.vulnhuntr] section
    ]
    
    def __init__(self):
        self.warnings: List[str] = []
    
    def load_config(self, explicit_path: Optional[Path] = None) -> Tuple[RunConfig, List[str]]:
        """
        Load configuration with precedence: CLI > Env > TOML > defaults.
        
        Args:
            explicit_path: Explicit config file path (highest precedence)
            
        Returns:
            Tuple of (config, warnings)
        """
        self.warnings = []
        
        # Start with defaults
        config = RunConfig()
        
        # 1. Load from TOML file (lowest precedence for files)
        toml_config = self._load_toml_config(explicit_path)
        if toml_config:
            config = self._merge_configs(config, toml_config)
        
        # 2. Override with environment variables
        env_config = self._load_env_config()
        if env_config:
            config = self._merge_configs(config, env_config)
        
        # 3. CLI overrides happen in CLI parsing
        
        # Validate configuration
        config, validation_warnings = self.validate_config(config)
        self.warnings.extend(validation_warnings)
        
        return config, self.warnings
    
    def _load_toml_config(self, explicit_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Load configuration from TOML file."""
        config_files = []
        
        if explicit_path:
            config_files = [explicit_path]
        else:
            # Look for default config files in current directory
            config_files = [Path(name) for name in self.DEFAULT_CONFIG_FILES]
        
        for config_file in config_files:
            if not config_file.exists():
                continue
                
            try:
                with open(config_file, 'rb') as f:
                    data = tomllib.load(f)
                
                # For pyproject.toml, look for [tool.vulnhuntr] section
                if config_file.name == "pyproject.toml":
                    data = data.get("tool", {}).get("vulnhuntr", {})
                
                if data:  # Only use if there's actual config
                    return data
                    
            except Exception as e:
                self.warnings.append(f"Failed to load config from {config_file}: {e}")
        
        return None
    
    def _load_env_config(self) -> Optional[Dict[str, Any]]:
        """Load configuration from environment variables."""
        env_config = {}
        
        # Define environment variable mappings
        env_mappings = {
            # Core settings
            f"{self.ENV_PREFIX}CONFIG_FILE": ("config_file", str),
            
            # Detector settings
            f"{self.ENV_PREFIX}DETECTORS_ENABLED": ("detectors.enabled", self._parse_list),
            f"{self.ENV_PREFIX}DETECTORS_DISABLED": ("detectors.disabled", self._parse_list),
            f"{self.ENV_PREFIX}DETECTORS_CATEGORIES": ("detectors.categories", self._parse_list),
            f"{self.ENV_PREFIX}DETECTORS_MIN_CONFIDENCE": ("detectors.min_confidence", float),
            f"{self.ENV_PREFIX}DETECTORS_MAX_CONFIDENCE": ("detectors.max_confidence", float),
            
            # LLM settings
            f"{self.ENV_PREFIX}LLM_ENABLED": ("llm.enabled", self._parse_bool),
            f"{self.ENV_PREFIX}LLM_PROVIDER": ("llm.provider", str),
            f"{self.ENV_PREFIX}LLM_MODEL": ("llm.model", str),
            f"{self.ENV_PREFIX}LLM_API_KEY": ("llm.api_key", str),
            f"{self.ENV_PREFIX}LLM_TEMPERATURE": ("llm.temperature", float),
            f"{self.ENV_PREFIX}LLM_MAX_TOKENS": ("llm.max_tokens", int),
            f"{self.ENV_PREFIX}LLM_TIMEOUT": ("llm.timeout", int),
            
            # Analysis settings
            f"{self.ENV_PREFIX}ENABLE_CORRELATION": ("analysis.enable_correlation", self._parse_bool),
            f"{self.ENV_PREFIX}ENABLE_POC_GENERATION": ("analysis.enable_poc_generation", self._parse_bool),
            f"{self.ENV_PREFIX}POC_OUTPUT_DIR": ("analysis.poc_output_dir", str),
            f"{self.ENV_PREFIX}USE_SLITHER": ("analysis.use_slither", self._parse_bool),
            f"{self.ENV_PREFIX}SLITHER_JSON_FILE": ("analysis.slither_json_file", str),
            
            # Output settings
            f"{self.ENV_PREFIX}OUTPUT_FORMAT": ("output.format", str),
            f"{self.ENV_PREFIX}OUTPUT_JSON_FILE": ("output.json_file", str),
            f"{self.ENV_PREFIX}OUTPUT_CORRELATED_JSON_FILE": ("output.correlated_json_file", str),
            f"{self.ENV_PREFIX}OUTPUT_MIN_SEVERITY": ("output.min_severity", str),
            f"{self.ENV_PREFIX}OUTPUT_SHOW_CODE": ("output.show_code", self._parse_bool),
            f"{self.ENV_PREFIX}OUTPUT_SHOW_REFERENCES": ("output.show_references", self._parse_bool),
            
            # Reporting settings
            f"{self.ENV_PREFIX}FAIL_ON_FINDINGS": ("reporting.fail_on_findings", self._parse_bool),
            f"{self.ENV_PREFIX}FAIL_ON_SEVERITY": ("reporting.fail_on_severity", str),
            f"{self.ENV_PREFIX}FAIL_ON_CONFIDENCE": ("reporting.fail_on_confidence", float),
            f"{self.ENV_PREFIX}FAIL_ON_FINDING_COUNT": ("reporting.fail_on_finding_count", int),
            f"{self.ENV_PREFIX}SARIF": ("reporting.sarif", self._parse_bool),
            f"{self.ENV_PREFIX}MARKDOWN_SUMMARY": ("reporting.markdown_summary", self._parse_bool),
        }
        
        for env_var, (config_path, parser) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    parsed_value = parser(value) if callable(parser) else parser(value)
                    self._set_nested_value(env_config, config_path, parsed_value)
                except (ValueError, TypeError) as e:
                    self.warnings.append(f"Invalid environment variable {env_var}={value}: {e}")
        
        return env_config if env_config else None
    
    def _parse_bool(self, value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ('true', '1', 'yes', 'on', 'enabled')
    
    def _parse_list(self, value: str) -> List[str]:
        """Parse list from comma-separated string."""
        return [item.strip() for item in value.split(',') if item.strip()]
    
    def _set_nested_value(self, config: Dict[str, Any], path: str, value: Any) -> None:
        """Set a nested configuration value using dot notation."""
        keys = path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _merge_configs(self, base: RunConfig, override: Dict[str, Any]) -> RunConfig:
        """Merge configuration dictionaries with proper precedence."""
        # Convert base config to dict for easier merging
        base_dict = base.to_dict()
        
        # Deep merge the override
        merged_dict = self._deep_merge(base_dict, override)
        
        # Convert back to RunConfig
        return RunConfig.from_dict(merged_dict)
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def validate_config(self, config: RunConfig) -> Tuple[RunConfig, List[str]]:
        """
        Validate configuration and collect warnings.
        
        Returns:
            Tuple of (validated_config, warnings)
        """
        warnings = []
        
        # Validate severity strings
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        
        if config.output.min_severity not in valid_severities:
            warnings.append(f"Invalid min_severity '{config.output.min_severity}', using 'INFO'")
            config.output.min_severity = "INFO"
        
        if config.reporting.fail_on_severity and config.reporting.fail_on_severity not in valid_severities:
            warnings.append(f"Invalid fail_on_severity '{config.reporting.fail_on_severity}'")
            config.reporting.fail_on_severity = None
        
        # Validate confidence ranges
        if not (0.0 <= config.detectors.min_confidence <= 1.0):
            warnings.append(f"Invalid min_confidence {config.detectors.min_confidence}, using 0.0")
            config.detectors.min_confidence = 0.0
        
        if not (0.0 <= config.detectors.max_confidence <= 1.0):
            warnings.append(f"Invalid max_confidence {config.detectors.max_confidence}, using 1.0")
            config.detectors.max_confidence = 1.0
        
        if config.detectors.min_confidence > config.detectors.max_confidence:
            warnings.append("min_confidence > max_confidence, swapping values")
            config.detectors.min_confidence, config.detectors.max_confidence = \
                config.detectors.max_confidence, config.detectors.min_confidence
        
        # Validate LLM configuration
        if config.llm.enabled and not config.llm.api_key:
            warnings.append("LLM enabled but no API key provided")
        
        if not (0.0 <= config.llm.temperature <= 2.0):
            warnings.append(f"Invalid LLM temperature {config.llm.temperature}, using 0.7")
            config.llm.temperature = 0.7
        
        # Validate paths
        if config.target_path and not config.target_path.exists():
            warnings.append(f"Target path does not exist: {config.target_path}")
        
        return config, warnings
    
    def dump_config(self, config: RunConfig) -> str:
        """Dump configuration as JSON."""
        return json.dumps(config.to_dict(), indent=2, default=str)
    
    def write_config(self, config: RunConfig, path: Path) -> None:
        """Write configuration to TOML file."""
        try:
            import tomli_w
        except ImportError:
            raise ImportError("tomli_w package required for writing TOML files. Install with: pip install tomli_w")
        
        config_dict = config.to_dict()
        
        # Convert Path objects to strings for TOML serialization
        def convert_paths(obj):
            if isinstance(obj, dict):
                return {k: convert_paths(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_paths(item) for item in obj]
            elif hasattr(obj, '__fspath__'):  # Path objects
                return str(obj)
            else:
                return obj
        
        config_dict = convert_paths(config_dict)
        
        with open(path, 'wb') as f:
            tomli_w.dump(config_dict, f)
    
    def compute_config_hash(self, config: RunConfig) -> str:
        """Compute stable hash of configuration."""
        from ..core.util.hash import compute_config_hash as hash_util
        return hash_util(config)


# Convenience functions
def load_config(explicit_path: Optional[Path] = None) -> Tuple[RunConfig, List[str]]:
    """Load configuration with default loader."""
    loader = ConfigLoader()
    return loader.load_config(explicit_path)


def validate_config(config: RunConfig) -> Tuple[RunConfig, List[str]]:
    """Validate configuration with default loader."""
    loader = ConfigLoader()
    return loader.validate_config(config)


def dump_config(config: RunConfig) -> str:
    """Dump configuration as JSON."""
    loader = ConfigLoader()
    return loader.dump_config(config)


def write_config(config: RunConfig, path: Path) -> None:
    """Write configuration to file."""
    loader = ConfigLoader()
    return loader.write_config(config, path)


def compute_config_hash(config: RunConfig) -> str:
    """Compute config hash."""
    loader = ConfigLoader()
    return loader.compute_config_hash(config)