"""
Utility functions for computing stable configuration hashes.
"""
import hashlib
import json
from typing import Any, Dict


def compute_config_hash(config: Any) -> str:
    """
    Compute a stable SHA256 hash of the configuration.
    
    The hash is computed over a normalized JSON representation,
    excluding runtime ephemeral fields and ensuring deterministic ordering.
    
    Args:
        config: Configuration dictionary or RunConfig object
        
    Returns:
        SHA256 hash as hexadecimal string
    """
    # Convert to dict if it's a RunConfig object
    if hasattr(config, 'to_dict'):
        config_dict = config.to_dict()
    else:
        config_dict = config
    
    # Create a normalized copy excluding ephemeral fields
    normalized = normalize_config_for_hash(config_dict)
    
    # Convert to canonical JSON (sorted keys, no whitespace)
    canonical_json = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    
    # Compute SHA256
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def normalize_config_for_hash(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize configuration for stable hashing.
    
    Excludes ephemeral runtime fields and ensures consistent structure.
    """
    # Fields to exclude from hashing (runtime/ephemeral)
    excluded_fields = {
        'target_path',  # Runtime target
        'config_file',  # Config source path
        'json_file',    # Output paths
        'correlated_json_file',
        'poc_output_dir',
        'slither_json_file',
        'api_key',      # Sensitive data
    }
    
    def clean_dict(obj: Any) -> Any:
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key not in excluded_fields:
                    cleaned_value = clean_dict(value)
                    if cleaned_value is not None:  # Exclude None values
                        result[key] = cleaned_value
            return result  # Return empty dict as-is, don't convert to None
        elif isinstance(obj, list):
            cleaned_list = [clean_dict(item) for item in obj if clean_dict(item) is not None]
            return cleaned_list if cleaned_list else None
        else:
            return obj
    
    return clean_dict(config) or {}