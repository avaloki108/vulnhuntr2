"""
Plugin Attestation (SEC) for Phase 6.

Hash-based plugin verification with plugins.lock file management
and attestation commands for security assurance.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
import importlib.util
import sys


@dataclass
class PluginAttestation:
    """Attestation record for a plugin."""
    
    name: str
    version: str
    file_hash: str
    api_version: str
    
    # Optional metadata
    description: Optional[str] = None
    author: Optional[str] = None
    attestation_date: Optional[str] = None
    file_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "file_hash": self.file_hash,
            "api_version": self.api_version,
            "description": self.description,
            "author": self.author,
            "attestation_date": self.attestation_date,
            "file_path": self.file_path
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PluginAttestation:
        return cls(
            name=data["name"],
            version=data["version"],
            file_hash=data["file_hash"],
            api_version=data["api_version"],
            description=data.get("description"),
            author=data.get("author"),
            attestation_date=data.get("attestation_date"),
            file_path=data.get("file_path")
        )


@dataclass
class AttestationResult:
    """Result of plugin attestation verification."""
    
    plugin_name: str
    status: str  # "verified", "hash_mismatch", "missing", "error"
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "status": self.status,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "error_message": self.error_message
        }


class HashCalculator:
    """Calculates file hashes for plugin attestation."""
    
    @staticmethod
    def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate hash of a file."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hasher = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    @staticmethod
    def calculate_directory_hash(dir_path: Path, algorithm: str = "sha256") -> str:
        """Calculate combined hash of all Python files in a directory."""
        if not dir_path.exists() or not dir_path.is_dir():
            raise ValueError(f"Directory not found: {dir_path}")
        
        hasher = hashlib.new(algorithm)
        
        # Get all Python files sorted for consistent hashing
        python_files = sorted(dir_path.glob("**/*.py"))
        
        for py_file in python_files:
            # Include relative path in hash for uniqueness
            rel_path = py_file.relative_to(dir_path)
            hasher.update(str(rel_path).encode('utf-8'))
            
            # Include file content
            with open(py_file, 'rb') as f:
                hasher.update(f.read())
        
        return hasher.hexdigest()
    
    @staticmethod
    def calculate_package_hash(package_path: Path, algorithm: str = "sha256") -> str:
        """Calculate hash for a Python package (file or directory)."""
        if package_path.is_file():
            return HashCalculator.calculate_file_hash(package_path, algorithm)
        elif package_path.is_dir():
            return HashCalculator.calculate_directory_hash(package_path, algorithm)
        else:
            raise ValueError(f"Package path must be file or directory: {package_path}")


class PluginLoader:
    """Loads and inspects plugins for attestation."""
    
    def __init__(self):
        self.loaded_plugins: Dict[str, Any] = {}
    
    def inspect_plugin(self, plugin_path: Path) -> Dict[str, Any]:
        """Inspect a plugin to extract metadata."""
        try:
            if plugin_path.is_file() and plugin_path.suffix == '.py':
                return self._inspect_file_plugin(plugin_path)
            elif plugin_path.is_dir() and (plugin_path / "__init__.py").exists():
                return self._inspect_package_plugin(plugin_path)
            else:
                raise ValueError(f"Invalid plugin path: {plugin_path}")
        
        except Exception as e:
            return {
                "name": plugin_path.name,
                "version": "unknown",
                "api_version": "unknown",
                "error": str(e)
            }
    
    def _inspect_file_plugin(self, file_path: Path) -> Dict[str, Any]:
        """Inspect a single file plugin."""
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if not spec or not spec.loader:
            raise ImportError(f"Cannot load plugin from {file_path}")
        
        # Load module without executing (safer)
        module = importlib.util.module_from_spec(spec)
        
        # Try to get metadata without full execution
        metadata = {
            "name": file_path.stem,
            "version": "1.0.0",  # Default
            "api_version": "1.0",  # Default
            "type": "file"
        }
        
        # Read file content to extract metadata comments
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Look for metadata in comments or docstrings
            lines = content.split('\n')
            for line in lines[:20]:  # Check first 20 lines
                line = line.strip()
                if line.startswith('# Version:'):
                    metadata["version"] = line.split(':', 1)[1].strip()
                elif line.startswith('# API Version:'):
                    metadata["api_version"] = line.split(':', 1)[1].strip()
                elif line.startswith('# Name:'):
                    metadata["name"] = line.split(':', 1)[1].strip()
                elif line.startswith('# Description:'):
                    metadata["description"] = line.split(':', 1)[1].strip()
                elif line.startswith('# Author:'):
                    metadata["author"] = line.split(':', 1)[1].strip()
                    
        except Exception:
            pass  # Use defaults
        
        return metadata
    
    def _inspect_package_plugin(self, package_path: Path) -> Dict[str, Any]:
        """Inspect a package plugin."""
        init_file = package_path / "__init__.py"
        
        metadata = {
            "name": package_path.name,
            "version": "1.0.0",  # Default
            "api_version": "1.0",  # Default
            "type": "package"
        }
        
        # Check for __version__ and other metadata in __init__.py
        try:
            with open(init_file, 'r') as f:
                content = f.read()
            
            # Look for common metadata patterns
            if '__version__' in content:
                # Extract version using simple regex-like approach
                for line in content.split('\n'):
                    if '__version__' in line and '=' in line:
                        try:
                            version_part = line.split('=')[1].strip().strip('\'"')
                            metadata["version"] = version_part
                        except:
                            pass
            
            # Look for other metadata
            for line in content.split('\n')[:30]:
                line = line.strip()
                if line.startswith('__author__'):
                    try:
                        author = line.split('=')[1].strip().strip('\'"')
                        metadata["author"] = author
                    except:
                        pass
                elif line.startswith('__description__'):
                    try:
                        desc = line.split('=')[1].strip().strip('\'"')
                        metadata["description"] = desc
                    except:
                        pass
        
        except Exception:
            pass  # Use defaults
        
        return metadata


class PluginAttestationManager:
    """Manages plugin attestations and lock file."""
    
    def __init__(self, lock_file_path: Path = Path("plugins.lock")):
        self.lock_file_path = lock_file_path
        self.attestations: Dict[str, PluginAttestation] = {}
        self.hash_calculator = HashCalculator()
        self.plugin_loader = PluginLoader()
        
        # Load existing attestations
        self._load_lock_file()
    
    def _load_lock_file(self) -> None:
        """Load attestations from lock file."""
        if not self.lock_file_path.exists():
            return
        
        try:
            with open(self.lock_file_path, 'r') as f:
                data = json.load(f)
            
            for plugin_data in data.get("plugins", []):
                attestation = PluginAttestation.from_dict(plugin_data)
                self.attestations[attestation.name] = attestation
                
        except Exception as e:
            print(f"Warning: Failed to load plugin lock file: {e}")
    
    def save_lock_file(self) -> None:
        """Save attestations to lock file."""
        try:
            lock_data = {
                "version": "1.0",
                "plugins": [att.to_dict() for att in self.attestations.values()]
            }
            
            with open(self.lock_file_path, 'w') as f:
                json.dump(lock_data, f, indent=2)
                
        except Exception as e:
            raise RuntimeError(f"Failed to save plugin lock file: {e}")
    
    def attest_plugin(self, plugin_path: Path, force: bool = False) -> PluginAttestation:
        """Attest a plugin and add to lock file."""
        if not plugin_path.exists():
            raise FileNotFoundError(f"Plugin not found: {plugin_path}")
        
        # Inspect plugin for metadata
        metadata = self.plugin_loader.inspect_plugin(plugin_path)
        
        if "error" in metadata:
            raise RuntimeError(f"Failed to inspect plugin: {metadata['error']}")
        
        plugin_name = metadata["name"]
        
        # Check if already attested
        if plugin_name in self.attestations and not force:
            existing = self.attestations[plugin_name]
            print(f"Plugin {plugin_name} already attested (hash: {existing.file_hash[:16]}...)")
            return existing
        
        # Calculate hash
        try:
            file_hash = self.hash_calculator.calculate_package_hash(plugin_path)
        except Exception as e:
            raise RuntimeError(f"Failed to calculate plugin hash: {e}")
        
        # Create attestation
        from datetime import datetime
        attestation = PluginAttestation(
            name=plugin_name,
            version=metadata.get("version", "1.0.0"),
            file_hash=file_hash,
            api_version=metadata.get("api_version", "1.0"),
            description=metadata.get("description"),
            author=metadata.get("author"),
            attestation_date=datetime.now().isoformat(),
            file_path=str(plugin_path)
        )
        
        # Store attestation
        self.attestations[plugin_name] = attestation
        
        return attestation
    
    def verify_plugin(self, plugin_path: Path, plugin_name: Optional[str] = None) -> AttestationResult:
        """Verify a plugin against its attestation."""
        if not plugin_path.exists():
            return AttestationResult(
                plugin_name=plugin_name or "unknown",
                status="missing",
                error_message=f"Plugin file not found: {plugin_path}"
            )
        
        # Determine plugin name
        if not plugin_name:
            try:
                metadata = self.plugin_loader.inspect_plugin(plugin_path)
                plugin_name = metadata.get("name", plugin_path.name)
            except Exception as e:
                return AttestationResult(
                    plugin_name=plugin_path.name,
                    status="error",
                    error_message=f"Failed to inspect plugin: {e}"
                )
        
        # Check if attestation exists
        if plugin_name not in self.attestations:
            return AttestationResult(
                plugin_name=plugin_name,
                status="missing",
                error_message=f"No attestation found for plugin: {plugin_name}"
            )
        
        attestation = self.attestations[plugin_name]
        
        # Calculate current hash
        try:
            current_hash = self.hash_calculator.calculate_package_hash(plugin_path)
        except Exception as e:
            return AttestationResult(
                plugin_name=plugin_name,
                status="error",
                error_message=f"Failed to calculate plugin hash: {e}"
            )
        
        # Compare hashes
        if current_hash == attestation.file_hash:
            return AttestationResult(
                plugin_name=plugin_name,
                status="verified",
                expected_hash=attestation.file_hash,
                actual_hash=current_hash
            )
        else:
            return AttestationResult(
                plugin_name=plugin_name,
                status="hash_mismatch",
                expected_hash=attestation.file_hash,
                actual_hash=current_hash,
                error_message="Plugin has been modified since attestation"
            )
    
    def verify_all_plugins(self, plugin_dirs: List[Path]) -> List[AttestationResult]:
        """Verify all plugins in specified directories."""
        results = []
        
        for plugin_dir in plugin_dirs:
            if not plugin_dir.exists():
                continue
            
            # Find all plugins in directory
            plugin_files = list(plugin_dir.glob("*.py"))
            plugin_packages = [d for d in plugin_dir.iterdir() 
                             if d.is_dir() and (d / "__init__.py").exists()]
            
            all_plugins = plugin_files + plugin_packages
            
            for plugin_path in all_plugins:
                result = self.verify_plugin(plugin_path)
                results.append(result)
        
        return results
    
    def remove_attestation(self, plugin_name: str) -> bool:
        """Remove attestation for a plugin."""
        if plugin_name in self.attestations:
            del self.attestations[plugin_name]
            return True
        return False
    
    def list_attestations(self) -> List[PluginAttestation]:
        """List all plugin attestations."""
        return list(self.attestations.values())
    
    def get_attestation_summary(self) -> Dict[str, Any]:
        """Get summary of attestation status."""
        return {
            "total_plugins": len(self.attestations),
            "lock_file_path": str(self.lock_file_path),
            "lock_file_exists": self.lock_file_path.exists(),
            "plugins": [
                {
                    "name": att.name,
                    "version": att.version,
                    "hash_preview": att.file_hash[:16] + "...",
                    "attestation_date": att.attestation_date
                }
                for att in self.attestations.values()
            ]
        }


# CLI utility functions
def create_sample_plugins_lock() -> Dict[str, Any]:
    """Create sample plugins.lock structure."""
    return {
        "version": "1.0",
        "plugins": [
            {
                "name": "example_detector",
                "version": "1.0.0",
                "file_hash": "sha256:abcd1234...",
                "api_version": "1.0",
                "description": "Example vulnerability detector",
                "author": "Security Team",
                "attestation_date": "2024-01-01T00:00:00",
                "file_path": "./plugins/example_detector.py"
            }
        ]
    }


def get_plugin_attestation_config() -> Dict[str, Any]:
    """Get plugin attestation configuration."""
    return {
        "enable": False,
        "lock_file": "plugins.lock",
        "fail_on_mismatch": False,
        "hash_algorithm": "sha256",
        "auto_attest_new": False,
        "plugin_dirs": ["./plugins", "./custom_detectors"]
    }