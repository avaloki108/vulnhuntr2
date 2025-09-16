"""
Plugin system for vulnhuntr2 Phase 5.
Provides extensible interface for detectors, enrichers, and postprocessors.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Protocol, runtime_checkable
from dataclasses import dataclass, field
from pathlib import Path
import time
import importlib.util
import sys
import logging
from abc import ABC, abstractmethod

from ..core.models import Finding, ScanContext


@dataclass 
class PluginInfo:
    """Plugin manifest information."""
    name: str
    version: str
    api_version: str
    capabilities: List[str] = field(default_factory=list)
    min_core_version: str = "0.1.0"
    config_schema: Optional[Dict[str, Any]] = None
    entry_point: str = ""
    description: str = ""
    author: str = ""


@dataclass
class PluginLoadStatus:
    """Status of plugin loading operation."""
    name: str
    loaded: bool
    load_time_ms: float
    error: Optional[str] = None
    warning: Optional[str] = None


@runtime_checkable
class DetectorPlugin(Protocol):
    """Protocol for detector plugins."""
    
    def analyze(self, context: ScanContext) -> List[Finding]:
        """Analyze scan context and return findings."""
        ...


@runtime_checkable  
class EnricherPlugin(Protocol):
    """Protocol for enricher plugins."""
    
    def enrich(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        """Enrich findings with additional metadata."""
        ...


@runtime_checkable
class PostprocessorPlugin(Protocol):
    """Protocol for postprocessor plugins."""
    
    def postprocess(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        """Post-process findings after analysis."""
        ...


class PluginManager:
    """
    Plugin manager with time budgets, memory guards, and fault isolation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.loaded_plugins: Dict[str, Any] = {}
        self.load_statuses: List[PluginLoadStatus] = []
        self.logger = logging.getLogger(__name__)
        
        # Time budgets (configurable, soft limits)
        self.detector_init_timeout = self.config.get('detector_init_timeout', 750)  # ms
        self.enrich_timeout = self.config.get('enrich_timeout', 1500)  # ms  
        self.postprocess_timeout = self.config.get('postprocess_timeout', 1500)  # ms
        
        # Memory guard threshold (soft limit)
        self.memory_guard_threshold_mb = self.config.get('memory_guard_threshold_mb', 100)
        
    def discover_plugins(self, plugin_dirs: List[Path]) -> List[PluginInfo]:
        """
        Discover plugins from specified directories.
        
        Args:
            plugin_dirs: List of directories to search for plugins
            
        Returns:
            List of discovered plugin information
        """
        discovered = []
        
        for plugin_dir in plugin_dirs:
            if not plugin_dir.exists():
                continue
                
            # Look for plugin.toml files
            for toml_file in plugin_dir.glob("**/plugin.toml"):
                try:
                    plugin_info = self._parse_plugin_toml(toml_file)
                    discovered.append(plugin_info)
                except Exception as e:
                    self.logger.warning(f"Failed to parse plugin manifest {toml_file}: {e}")
                    
        # Sort alphabetically by name for deterministic loading order
        discovered.sort(key=lambda p: p.name)
        return discovered
        
    def load_plugin(self, plugin_info: PluginInfo, plugin_path: Path) -> Optional[Any]:
        """
        Load a single plugin with fault isolation.
        
        Args:
            plugin_info: Plugin manifest information
            plugin_path: Path to the plugin module
            
        Returns:
            Loaded plugin instance or None if failed
        """
        start_time = time.perf_counter()
        
        try:
            # Load module
            spec = importlib.util.spec_from_file_location(plugin_info.name, plugin_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not load spec for {plugin_info.name}")
                
            module = importlib.util.module_from_spec(spec)
            
            # Execute with timeout (soft)
            load_start = time.time()
            spec.loader.exec_module(module)
            load_time = (time.time() - load_start) * 1000
            
            if load_time > self.detector_init_timeout:
                self.logger.warning(
                    f"Plugin {plugin_info.name} init took {load_time:.1f}ms "
                    f"(exceeds soft limit of {self.detector_init_timeout}ms)"
                )
            
            # Get plugin instance
            plugin_instance = getattr(module, plugin_info.entry_point, None)
            if plugin_instance is None:
                raise AttributeError(f"Entry point {plugin_info.entry_point} not found")
                
            # Validate plugin interface
            self._validate_plugin_interface(plugin_instance, plugin_info)
            
            # Record successful load
            load_time_ms = (time.perf_counter() - start_time) * 1000
            self.load_statuses.append(PluginLoadStatus(
                name=plugin_info.name,
                loaded=True,
                load_time_ms=load_time_ms
            ))
            
            self.loaded_plugins[plugin_info.name] = plugin_instance
            return plugin_instance
            
        except Exception as e:
            # Fault isolation - capture error but continue
            load_time_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"Failed to load plugin {plugin_info.name}: {e}"
            
            self.logger.error(error_msg)
            self.load_statuses.append(PluginLoadStatus(
                name=plugin_info.name,
                loaded=False,
                load_time_ms=load_time_ms,
                error=str(e)
            ))
            
            return None
    
    def execute_detector_plugin(self, plugin: DetectorPlugin, context: ScanContext) -> List[Finding]:
        """Execute detector plugin with guards and fault isolation."""
        return self._execute_with_guards(
            plugin.analyze, 
            [context], 
            self.detector_init_timeout,
            f"detector {getattr(plugin, 'name', 'unknown')}"
        )
    
    def execute_enricher_plugin(self, plugin: EnricherPlugin, findings: List[Finding], context: ScanContext) -> List[Finding]:
        """Execute enricher plugin with guards and fault isolation.""" 
        return self._execute_with_guards(
            plugin.enrich,
            [findings, context],
            self.enrich_timeout,
            f"enricher {getattr(plugin, 'name', 'unknown')}"
        )
    
    def execute_postprocessor_plugin(self, plugin: PostprocessorPlugin, findings: List[Finding], context: ScanContext) -> List[Finding]:
        """Execute postprocessor plugin with guards and fault isolation."""
        return self._execute_with_guards(
            plugin.postprocess,
            [findings, context], 
            self.postprocess_timeout,
            f"postprocessor {getattr(plugin, 'name', 'unknown')}"
        )
    
    def _execute_with_guards(self, func, args, timeout_ms: int, plugin_name: str) -> List[Finding]:
        """Execute plugin function with time and memory guards."""
        try:
            import psutil
            import os
            
            start_time = time.time()
            initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
            
            result = func(*args)
            
            # Check execution time (soft limit)
            exec_time_ms = (time.time() - start_time) * 1000
            if exec_time_ms > timeout_ms:
                self.logger.warning(
                    f"Plugin {plugin_name} execution took {exec_time_ms:.1f}ms "
                    f"(exceeds soft limit of {timeout_ms}ms)"
                )
            
            # Check memory usage (soft limit)
            final_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
            memory_delta = final_memory - initial_memory
            
            if memory_delta > self.memory_guard_threshold_mb:
                self.logger.warning(
                    f"Plugin {plugin_name} consumed {memory_delta:.1f}MB "
                    f"(exceeds soft threshold of {self.memory_guard_threshold_mb}MB)"
                )
            
            return result if isinstance(result, list) else []
            
        except ImportError:
            # psutil not available, run without memory monitoring
            try:
                start_time = time.time()
                result = func(*args)
                
                exec_time_ms = (time.time() - start_time) * 1000
                if exec_time_ms > timeout_ms:
                    self.logger.warning(
                        f"Plugin {plugin_name} execution took {exec_time_ms:.1f}ms "
                        f"(exceeds soft limit of {timeout_ms}ms)"
                    )
                
                return result if isinstance(result, list) else []
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
                return []
        except Exception as e:
            # Fault isolation - log error and return empty list
            self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
            return []
    
    def _parse_plugin_toml(self, toml_path: Path) -> PluginInfo:
        """Parse plugin.toml manifest file."""
        # Simple TOML parser for basic use case (avoiding external dependency)
        content = toml_path.read_text()
        lines = content.split('\n')
        
        plugin_data = {}
        in_plugin_section = False
        
        for line in lines:
            line = line.strip()
            if line == '[plugin]':
                in_plugin_section = True
                continue
            elif line.startswith('[') and line != '[plugin]':
                in_plugin_section = False
                continue
                
            if in_plugin_section and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                
                # Handle arrays 
                if value.startswith('[') and value.endswith(']'):
                    value = [item.strip().strip('"\'') for item in value[1:-1].split(',') if item.strip()]
                
                plugin_data[key] = value
        
        return PluginInfo(
            name=plugin_data.get('name', ''),
            version=plugin_data.get('version', '0.1.0'),
            api_version=plugin_data.get('api_version', '1.0.0'),
            capabilities=plugin_data.get('capabilities', []),
            min_core_version=plugin_data.get('min_core_version', '0.1.0'),
            config_schema=None,  # Could be extended
            entry_point=plugin_data.get('entry_point', 'plugin'),
            description=plugin_data.get('description', ''),
            author=plugin_data.get('author', '')
        )
    
    def _validate_plugin_interface(self, plugin_instance: Any, plugin_info: PluginInfo) -> None:
        """Validate plugin implements required interface."""
        capabilities = plugin_info.capabilities
        
        if 'detector' in capabilities:
            if not hasattr(plugin_instance, 'analyze'):
                raise TypeError(f"Plugin {plugin_info.name} claims detector capability but doesn't have analyze method")
        
        if 'enricher' in capabilities:
            if not hasattr(plugin_instance, 'enrich'):
                raise TypeError(f"Plugin {plugin_info.name} claims enricher capability but doesn't have enrich method")
            
        if 'postprocessor' in capabilities:
            if not hasattr(plugin_instance, 'postprocess'):
                raise TypeError(f"Plugin {plugin_info.name} claims postprocessor capability but doesn't have postprocess method")


# Export main classes
__all__ = [
    'PluginInfo',
    'PluginLoadStatus', 
    'DetectorPlugin',
    'EnricherPlugin',
    'PostprocessorPlugin',
    'PluginManager'
]