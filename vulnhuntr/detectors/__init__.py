"""
Detector package initializer.
Auto-discovery and registration of all detector modules.
"""
import importlib
import pkgutil
from pathlib import Path

from ..core.registry import register

# Import existing detectors to maintain backward compatibility
from . import sample_reentrancy  # noqa: F401

# Auto-discover and import all detector modules
def _discover_and_register_detectors():
    """Automatically discover and register all detector classes."""
    
    current_dir = Path(__file__).parent
    
    # Import all Python files in the detectors directory
    for module_info in pkgutil.iter_modules([str(current_dir)]):
        module_name = module_info.name
        
        # Skip __init__ and non-detector modules
        if module_name.startswith('_') or module_name == 'base':
            continue
        
        try:
            # Import the module
            module = importlib.import_module(f'.{module_name}', __package__)
            
            # Look for detector classes that inherit from BaseDetector
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                # Check if it's a detector class (has analyze method and proper attributes)
                if (hasattr(attr, 'analyze') and 
                    hasattr(attr, 'name') and 
                    hasattr(attr, 'description') and
                    callable(getattr(attr, 'analyze', None))):
                    
                    # Register the detector class
                    register(attr)
                    
        except ImportError as e:
            # Skip modules that can't be imported
            pass

# Perform auto-discovery on import
_discover_and_register_detectors()
