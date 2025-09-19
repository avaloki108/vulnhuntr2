"""
Incremental and diff-based scanning for vulnhuntr2 Phase 5.
Provides function-level granularity for efficient scanning of changes.
"""
from __future__ import annotations

from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import logging
import re

from ..core.models import ScanContext, Contract, Function


@dataclass
class DiffChange:
    """Represents a change in a diff."""
    file_path: str
    change_type: str  # added, modified, deleted
    line_start: int
    line_end: int
    function_name: Optional[str] = None
    contract_name: Optional[str] = None


@dataclass
class IncrementalScanContext:
    """Extended scan context for incremental scanning."""
    base_context: ScanContext
    changed_files: Set[str] = field(default_factory=set)
    changed_functions: Set[Tuple[str, str]] = field(default_factory=set)  # (file, function)
    diff_changes: List[DiffChange] = field(default_factory=list)
    base_ref: Optional[str] = None


class IncrementalScanner:
    """
    Incremental scanner with function-level granularity.
    """
    
    def __init__(self, base_ref: Optional[str] = None):
        self.base_ref = base_ref
        self.logger = logging.getLogger(__name__)
    
    def create_incremental_context(self, context: ScanContext) -> IncrementalScanContext:
        """
        Create incremental scan context with diff analysis.
        
        Args:
            context: Base scan context
            
        Returns:
            Incremental scan context with change information
        """
        incremental_context = IncrementalScanContext(base_context=context, base_ref=self.base_ref)
        
        if self.base_ref:
            # Analyze git diff
            diff_changes = self._analyze_git_diff(context.target_path, self.base_ref)
            incremental_context.diff_changes = diff_changes
            
            # Extract changed files and functions
            incremental_context.changed_files = set(change.file_path for change in diff_changes)
            incremental_context.changed_functions = set(
                (change.file_path, change.function_name)
                for change in diff_changes
                if change.function_name
            )
        
        return incremental_context
    
    def should_scan_file(self, file_path: str, incremental_context: IncrementalScanContext) -> bool:
        """
        Determine if a file should be scanned based on changes.
        
        Args:
            file_path: Path to the file
            incremental_context: Incremental scan context
            
        Returns:
            True if file should be scanned
        """
        if not incremental_context.base_ref:
            # No base ref, scan all files
            return True
        
        # Check if file has changes
        relative_path = self._get_relative_path(file_path, incremental_context.base_context.target_path)
        return relative_path in incremental_context.changed_files
    
    def should_scan_function(self, file_path: str, function_name: str, incremental_context: IncrementalScanContext) -> bool:
        """
        Determine if a function should be scanned based on changes.
        
        Args:
            file_path: Path to the file
            function_name: Name of the function
            incremental_context: Incremental scan context
            
        Returns:
            True if function should be scanned
        """
        if not incremental_context.base_ref:
            # No base ref, scan all functions
            return True
        
        relative_path = self._get_relative_path(file_path, incremental_context.base_context.target_path)
        return (relative_path, function_name) in incremental_context.changed_functions
    
    def filter_contracts_for_incremental(self, contracts: List[Contract], incremental_context: IncrementalScanContext) -> List[Contract]:
        """
        Filter contracts to only include those with changes.
        
        Args:
            contracts: List of all contracts
            incremental_context: Incremental scan context
            
        Returns:
            Filtered list of contracts with changes
        """
        if not incremental_context.base_ref:
            return contracts
        
        filtered_contracts = []
        for contract in contracts:
            relative_path = self._get_relative_path(str(contract.file_path), incremental_context.base_context.target_path)
            
            if relative_path in incremental_context.changed_files:
                # Filter functions within the contract
                if hasattr(contract, 'functions'):
                    filtered_functions = []
                    for func in contract.functions:
                        if (relative_path, func.name) in incremental_context.changed_functions:
                            filtered_functions.append(func)
                    
                    # Create new contract with filtered functions
                    filtered_contract = Contract(
                        name=contract.name,
                        file_path=contract.file_path,
                        functions=filtered_functions
                    )
                    filtered_contracts.append(filtered_contract)
                else:
                    filtered_contracts.append(contract)
        
        return filtered_contracts
    
    def _analyze_git_diff(self, target_path: Path, base_ref: str) -> List[DiffChange]:
        """
        Analyze git diff to identify changes.
        
        Args:
            target_path: Target directory path
            base_ref: Base git reference for comparison
            
        Returns:
            List of diff changes
        """
        try:
            # Get diff with function context
            result = subprocess.run(
                ["git", "diff", "--unified=5", f"{base_ref}..HEAD", "*.sol"],
                cwd=target_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            return self._parse_git_diff(result.stdout)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git diff failed: {e}")
            return []
        except FileNotFoundError:
            self.logger.warning("Git not available, skipping diff analysis")
            return []
    
    def _parse_git_diff(self, diff_output: str) -> List[DiffChange]:
        """
        Parse git diff output to extract changes.
        
        Args:
            diff_output: Git diff output
            
        Returns:
            List of parsed diff changes
        """
        changes = []
        current_file = None
        current_function = None
        
        lines = diff_output.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # File header
            if line.startswith('diff --git'):
                current_file = None
                current_function = None
            elif line.startswith('+++'):
                # Extract file path
                file_path = line[4:].strip()
                if file_path.startswith('b/'):
                    file_path = file_path[2:]
                current_file = file_path
            
            # Hunk header with function context
            elif line.startswith('@@') and current_file:
                # Extract line numbers
                match = re.search(r'@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@\s*(.*)', line)
                if match:
                    old_start = int(match.group(1))
                    old_count = int(match.group(2)) if match.group(2) else 1
                    new_start = int(match.group(3))
                    new_count = int(match.group(4)) if match.group(4) else 1
                    context = match.group(5) if match.group(5) else ""
                    
                    # Extract function name from context
                    function_name = self._extract_function_name(context)
                    if function_name:
                        current_function = function_name
                    
                    # Determine change type by analyzing the hunk
                    change_type = "modified"  # Default
                    if old_count == 0:
                        change_type = "added"
                    elif new_count == 0:
                        change_type = "deleted"
                    
                    # Extract contract name if possible
                    contract_name = self._extract_contract_name_from_file(current_file)
                    
                    change = DiffChange(
                        file_path=current_file,
                        change_type=change_type,
                        line_start=new_start,
                        line_end=new_start + new_count - 1,
                        function_name=current_function,
                        contract_name=contract_name
                    )
                    changes.append(change)
            
            # Look for function definitions in added/modified lines
            elif line.startswith('+') and not line.startswith('+++') and current_file:
                function_match = re.search(r'function\s+(\w+)\s*\(', line)
                if function_match:
                    current_function = function_match.group(1)
            
            i += 1
        
        return changes
    
    def _extract_function_name(self, context: str) -> Optional[str]:
        """
        Extract function name from git diff context.
        
        Args:
            context: Context line from git diff
            
        Returns:
            Function name if found
        """
        # Look for function definition patterns
        patterns = [
            r'function\s+(\w+)\s*\(',
            r'(\w+)\s*\([^)]*\)\s*{',
            r'(\w+)\s*\([^)]*\)\s*(public|private|internal|external)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, context)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_contract_name_from_file(self, file_path: str) -> Optional[str]:
        """
        Extract contract name from file path.
        
        Args:
            file_path: Path to the contract file
            
        Returns:
            Contract name if extractable
        """
        # Simple heuristic: use filename without extension
        path = Path(file_path)
        if path.suffix == '.sol':
            return path.stem
        
        return None
    
    def _get_relative_path(self, file_path: str, target_path: Path) -> str:
        """
        Get relative path from target directory.
        
        Args:
            file_path: Absolute or relative file path
            target_path: Target directory path
            
        Returns:
            Relative path string
        """
        try:
            return str(Path(file_path).relative_to(target_path))
        except ValueError:
            # If file_path is not relative to target_path, return as-is
            return file_path
    
    def get_incremental_summary(self, incremental_context: IncrementalScanContext) -> Dict[str, Any]:
        """
        Get summary of incremental scan context.
        
        Args:
            incremental_context: Incremental scan context
            
        Returns:
            Summary dictionary
        """
        return {
            "base_ref": incremental_context.base_ref,
            "changed_files_count": len(incremental_context.changed_files),
            "changed_functions_count": len(incremental_context.changed_functions),
            "diff_changes_count": len(incremental_context.diff_changes),
            "changed_files": list(incremental_context.changed_files)[:10],  # Limit for readability
            "change_types": {
                change_type: len([c for c in incremental_context.diff_changes if c.change_type == change_type])
                for change_type in ["added", "modified", "deleted"]
            }
        }


# Export main classes
__all__ = ['DiffChange', 'IncrementalScanContext', 'IncrementalScanner']