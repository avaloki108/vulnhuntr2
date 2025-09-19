"""Registry for vulnerability detectors."""

import importlib
import inspect
import logging
import pkgutil
from typing import Any, Callable, Dict, List, Set, Type

from vulnhuntr.core.models import Finding, ScanContext

logger = logging.getLogger(__name__)

_DETECTOR_REGISTRY: Dict[str, Type] = {}


def register(cls: Type) -> Type:
    """Decorator to register a detector class."""
    if not hasattr(cls, 'name') or not cls.name:
        cls.name = cls.__name__.lower()
        
    if cls.name in _DETECTOR_REGISTRY:
        logger.warning(f"Detector {cls.name} is already registered. Overriding.")
        
    if not hasattr(cls, 'analyze') or not callable(cls.analyze):
        logger.error(f"Detector {cls.name} must implement 'analyze' method.")
        return cls
        
    _DETECTOR_REGISTRY[cls.name] = cls
    logger.debug(f"Registered detector: {cls.name}")
    return cls


def get_detector(name: str) -> Type:
    """Get a detector by name."""
    return _DETECTOR_REGISTRY.get(name)


def get_all_detectors() -> Dict[str, Type]:
    """Get all registered detectors."""
    return _DETECTOR_REGISTRY


def get_registered_detectors() -> List[Type]:
    """Get all registered detector classes."""
    return list(_DETECTOR_REGISTRY.values())


def discover_detectors(package_name: str = "vulnhuntr.detectors") -> None:
    """Discover and import all detector modules to register them."""
    logger.debug(f"Discovering detectors in {package_name}")
    try:
        package = importlib.import_module(package_name)
        
        # Walk through all modules in the detectors package
        for _, name, is_pkg in pkgutil.walk_packages(
            package.__path__, package.__name__ + "."
        ):
            if not is_pkg:  # Only process modules, not sub-packages
                try:
                    importlib.import_module(name)
                    logger.debug(f"Imported detector module: {name}")
                except Exception as e:
                    logger.error(f"Failed to import detector module {name}: {e}")
    except ImportError as e:
        logger.error(f"Failed to import detector package {package_name}: {e}")


class DetectorOrchestrator:
    """Orchestrates the execution of detectors on the target code."""
    
    def __init__(self, detectors: List[Type] = None):
        """
        Initialize with specific detectors or use all registered ones.
        
        Args:
            detectors: Optional list of detector classes to use
        """
        if detectors is None:
            self.detectors = list(_DETECTOR_REGISTRY.values())
        else:
            self.detectors = detectors
            
    def run_detectors(self, scan_context: ScanContext) -> List[Finding]:
        """
        Run all detectors on the scan context.
        
        Args:
            scan_context: Context containing code and analysis data
            
        Returns:
            List of findings from all detectors
        """
        all_findings = []
        for detector_cls in self.detectors:
            try:
                detector = detector_cls()
                logger.debug(f"Running detector: {detector.name}")
                
                # Check if the detector supports the new scan_context parameter
                sig = inspect.signature(detector.analyze)
                if "scan_context" in sig.parameters:
                    findings = detector.analyze(scan_context)
                else:
                    # Fallback to older detectors that expect path and content
                    logger.warning(f"Detector {detector.name} uses legacy interface")
                    for contract in scan_context.contracts:
                        findings = detector.analyze(contract.file_path, contract.source)
                        all_findings.extend(findings)
                    continue
                    
                if findings:
                    all_findings.extend(findings)
                    logger.info(f"Detector {detector.name} found {len(findings)} issues")
                    
            except Exception as e:
                logger.error(f"Error running detector {detector_cls.name}: {e}", exc_info=True)
                
        return all_findings


class DetectorRegistry:
    """Simple registry object for backward compatibility."""
    
    def __init__(self):
        self.detectors = _DETECTOR_REGISTRY


# Create global registry instance
registry = DetectorRegistry()