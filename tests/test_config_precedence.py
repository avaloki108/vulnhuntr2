"""
Tests for configuration precedence and loading.
"""
import os
import tempfile
from pathlib import Path

from vulnhuntr.config.loader import ConfigLoader
from vulnhuntr.config.schema import RunConfig


def test_config_precedence_env_over_defaults():
    """Test that environment variables override defaults."""
    # Set environment variable
    os.environ["VULNHUNTR_LLM_ENABLED"] = "true"
    os.environ["VULNHUNTR_OUTPUT_MIN_SEVERITY"] = "HIGH"
    
    try:
        loader = ConfigLoader()
        config, warnings = loader.load_config()
        
        assert config.llm.enabled is True
        assert config.output.min_severity == "HIGH"
        # Warning expected for LLM enabled without API key
        assert any("LLM enabled but no API key" in warning for warning in warnings)
        
    finally:
        # Clean up environment
        os.environ.pop("VULNHUNTR_LLM_ENABLED", None)
        os.environ.pop("VULNHUNTR_OUTPUT_MIN_SEVERITY", None)


def test_config_precedence_toml_over_defaults():
    """Test that TOML config overrides defaults."""
    toml_content = """
[llm]
enabled = true
model = "gpt-3.5-turbo"

[output]
min_severity = "MEDIUM"
format = "json"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(toml_content)
        toml_path = Path(f.name)
    
    try:
        loader = ConfigLoader()
        config, warnings = loader.load_config(toml_path)
        
        assert config.llm.enabled is True
        assert config.llm.model == "gpt-3.5-turbo"
        assert config.output.min_severity == "MEDIUM"
        assert config.output.format == "json"
        
    finally:
        toml_path.unlink()


def test_config_validation_warnings():
    """Test that config validation produces appropriate warnings."""
    # Set invalid environment variables
    os.environ["VULNHUNTR_OUTPUT_MIN_SEVERITY"] = "INVALID"
    os.environ["VULNHUNTR_DETECTORS_MIN_CONFIDENCE"] = "1.5"
    
    try:
        loader = ConfigLoader()
        config, warnings = loader.load_config()
        
        # Check that invalid values were corrected
        assert config.output.min_severity == "INFO"  # Reset to default
        assert config.detectors.min_confidence == 0.0  # Reset to valid range
        
        # Check that warnings were generated
        assert len(warnings) >= 2
        assert any("Invalid min_severity" in warning for warning in warnings)
        assert any("Invalid min_confidence" in warning for warning in warnings)
        
    finally:
        os.environ.pop("VULNHUNTR_OUTPUT_MIN_SEVERITY", None)
        os.environ.pop("VULNHUNTR_DETECTORS_MIN_CONFIDENCE", None)


def test_config_hash_stability():
    """Test that config hash is stable and order-independent."""
    loader = ConfigLoader()
    
    # Create two identical configs
    config1 = RunConfig()
    config1.llm.enabled = True
    config1.output.min_severity = "HIGH"
    
    config2 = RunConfig()
    config2.output.min_severity = "HIGH"
    config2.llm.enabled = True
    
    hash1 = loader.compute_config_hash(config1)
    hash2 = loader.compute_config_hash(config2)
    
    # Hashes should be identical despite different assignment order
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex string


def test_config_hash_changes_with_content():
    """Test that config hash changes when config content changes."""
    loader = ConfigLoader()
    
    config1 = RunConfig()
    config1.llm.enabled = True
    
    config2 = RunConfig()
    config2.llm.enabled = False
    
    hash1 = loader.compute_config_hash(config1)
    hash2 = loader.compute_config_hash(config2)
    
    assert hash1 != hash2