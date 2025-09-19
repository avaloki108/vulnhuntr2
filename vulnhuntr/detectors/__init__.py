"""
Enhanced detector package with selector support and configuration management.
"""
import importlib
import pkgutil
import fnmatch
from pathlib import Path
from typing import List, Dict, Set, Tuple, Any

from ..core.registry import get_registered_detectors
from ..config.schema import RunConfig


# Import existing detectors to maintain backward compatibility  
from . import sample_reentrancy  # noqa: F401


def _discover_and_register_detectors():
    """Automatically discover and register all detector classes."""
    
    current_dir = Path(__file__).parent
    
    # Import all Python files in the detectors directory
    for module_info in pkgutil.iter_modules([str(current_dir)]):
        module_name = module_info.name
        
        # Skip __init__, base, and existing modules
        if module_name.startswith('_') or module_name in ['base', 'sample_reentrancy']:
            continue
        
        try:
            # Import the module
            importlib.import_module(f'.{module_name}', __package__)
                    
        except ImportError as e:
            # Skip modules that can't be imported
            pass


def load_detectors(config: RunConfig) -> Tuple[List[Any], List[str], Dict[str, Any]]:
    """
    Load detectors based on configuration with selector support.
    
    Args:
        config: Runtime configuration
        
    Returns:
        Tuple of (enabled_detectors, warnings, explanation_map)
    """
    all_detectors = get_registered_detectors()
    warnings = []
    explanation_map = {}
    
    # Start with default enabled detectors
    enabled_set = set()
    disabled_set = set()
    
    # Apply default enabled state
    for detector in all_detectors:
        if getattr(detector, 'enabled_by_default', True):
            enabled_set.add(detector.name)
    
    # Process enabled selectors (additive)
    for selector in config.detectors.enabled:
        matched_detectors = match_detectors(all_detectors, selector)
        if not matched_detectors:
            warnings.append(f"Enabled selector '{selector}' matches no detectors")
        else:
            for detector in matched_detectors:
                enabled_set.add(detector.name)
            explanation_map[selector] = [d.name for d in matched_detectors]
    
    # Process disabled selectors (subtractive, higher precedence)
    for selector in config.detectors.disabled:
        matched_detectors = match_detectors(all_detectors, selector)
        if not matched_detectors:
            warnings.append(f"Disabled selector '{selector}' matches no detectors")
        else:
            for detector in matched_detectors:
                disabled_set.add(detector.name)
            explanation_map[selector] = [d.name for d in matched_detectors]
    
    # Apply conflict resolution: explicit disable > explicit enable > default
    final_enabled = enabled_set - disabled_set
    
    # Filter detectors by confidence range
    enabled_detectors = []
    for detector in all_detectors:
        if detector.name in final_enabled:
            detector_confidence = getattr(detector, 'confidence', 0.5)
            # Validate that confidence is a float in [0.0, 1.0]
            try:
                detector_confidence_val = float(detector_confidence)
                if not (0.0 <= detector_confidence_val <= 1.0):
                    raise ValueError
            except (TypeError, ValueError):
                warnings.append(
                    f"Detector '{detector.name}' has invalid confidence value '{detector_confidence}', using default 0.5"
                )
                detector_confidence_val = 0.5
            if config.detectors.min_confidence <= detector_confidence_val <= config.detectors.max_confidence:
                enabled_detectors.append(detector)
            else:
                warnings.append(f"Detector '{detector.name}' excluded due to confidence filter")
    
    # Filter by categories if specified
    if config.detectors.categories:
        category_filtered = []
        for detector in enabled_detectors:
            detector_category = getattr(detector, 'category', 'unknown')
            if any(fnmatch.fnmatch(detector_category, pattern) for pattern in config.detectors.categories):
                category_filtered.append(detector)
            else:
                warnings.append(f"Detector '{detector.name}' excluded due to category filter")
        enabled_detectors = category_filtered
    
    # Check for dependency warnings
    for detector in enabled_detectors:
        if getattr(detector, 'requires_slither', False) and not config.analysis.use_slither:
            warnings.append(f"Detector '{detector.name}' requires Slither but --use-slither not enabled")
    
    return enabled_detectors, warnings, explanation_map


def match_detectors(all_detectors: List[Any], selector: str) -> List[Any]:
    """
    Match detectors against a selector.
    
    Supports:
    - Exact name match: "detector_name"
    - Glob patterns: "detector_*", "*_reentrancy"
    - Category patterns: "category:access_control", "category:*"
    """
    matched = []
    
    for detector in all_detectors:
        # Prefer detector-provided matcher; else use fallback
        matcher = getattr(detector, 'matches_selector', None)
        if callable(matcher):
            if matcher(selector):
                matched.append(detector)
        else:
            name = getattr(detector, 'name', '')
            category = getattr(detector, 'category', '')
            if selector.startswith("category:"):
                pattern = selector.split(":", 1)[1]
                if pattern == "*" or fnmatch.fnmatch(category, pattern):
                    matched.append(detector)
            elif name == selector or fnmatch.fnmatch(name, selector):
                matched.append(detector)
    
    return matched


def explain_selector(selector: str) -> Dict[str, Any]:
    """
    Explain which detectors match a selector and why.
    
    Returns:
        Dictionary with match details
    """
    all_detectors = get_registered_detectors()
    matched_detectors = match_detectors(all_detectors, selector)
    
    explanation = {
        "selector": selector,
        "match_type": _determine_match_type(selector),
        "matched_count": len(matched_detectors),
        "matched_detectors": [
            {
                "name": detector.name,
                "category": getattr(detector, 'category', 'unknown'),
                "description": getattr(detector, 'description', ''),
            }
            for detector in matched_detectors
        ]
    }
    
    return explanation


def _determine_match_type(selector: str) -> str:
    """Determine the type of selector for explanation."""
    if selector.startswith("category:"):
        return "category"
    elif "*" in selector or "?" in selector or "[" in selector:
        return "glob"
    else:
        return "exact"


# Perform auto-discovery on import
_discover_and_register_detectors()
