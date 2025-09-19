"""
Mutation framework for smart contract security analysis.
This module provides functionality to generate mutations of contract code
to test detection capabilities and evaluate security properties.
"""

from typing import Dict, List, Optional, Tuple, Any, Set, Callable
import random
import re
from pathlib import Path
import copy

from .parser import SolidityParser

class MutationOperator:
    """Base class for mutation operators."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def mutate(self, content: str) -> List[Tuple[str, str]]:
        """
        Apply mutation to code content.
        
        Args:
            content: Original source code
            
        Returns:
            List of (mutated_content, mutation_description) tuples
        """
        raise NotImplementedError("Mutation operators must implement mutate()")

class FunctionVisibilityMutator(MutationOperator):
    """Mutate function visibility modifiers."""
    
    def __init__(self):
        super().__init__(
            name="function_visibility",
            description="Changes function visibility modifiers (public, private, external, internal)"
        )
        # Delay parser creation to runtime to avoid hard dependency during import
        self._parser_created = False
        self._parser = None
    
    def _ensure_parser(self) -> None:
        if not self._parser_created:
            try:
                self._parser = SolidityParser()
            except Exception:
                self._parser = None
            self._parser_created = True
    
    def mutate(self, content: str) -> List[Tuple[str, str]]:
        """Change function visibility modifiers."""
        results = []
        self._ensure_parser()  # best-effort; regex fallback regardless
        
        # Simple regex-based approach for prototype
        # In production, tree-sitter would be more robust
        visibility_patterns = [
            (r'function\s+(\w+)\s*\([^)]*\)\s*public', 'external'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*external', 'public'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*private', 'internal'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*internal', 'private'),
        ]
        
        for pattern, replacement in visibility_patterns:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                func_name = match.group(1)
                mutated = content[:match.start()] + content[match.start():].replace(
                    match.group(0),
                    match.group(0).replace(match.group(0).split(')')[-1].strip(), replacement),
                    1
                )
                
                description = f"Changed function '{func_name}' visibility to '{replacement}'"
                results.append((mutated, description))
        
        return results

class AccessControlRemovalMutator(MutationOperator):
    """Remove access control checks."""
    
    def __init__(self):
        super().__init__(
            name="access_control_removal",
            description="Removes access control modifiers or statements"
        )
    
    def mutate(self, content: str) -> List[Tuple[str, str]]:
        """Remove access control checks."""
        results = []
        
        # Pattern for require statements with common access control checks
        patterns = [
            (r'require\(\s*(msg\.sender\s*==\s*owner|isOwner\(\)|onlyOwner|msg\.sender\s*==\s*\w+)\s*\)[^;]*;', 
             'Removed ownership check'),
            (r'require\(\s*(hasRole|hasAccess|isAdmin|isAuthorized)\(\s*[^)]*\)\s*\)[^;]*;', 
             'Removed role-based access check'),
        ]
        
        for pattern, desc_base in patterns:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                check_code = match.group(0)
                check_condition = match.group(1)
                
                # Replace the entire require statement with a comment
                mutated = content[:match.start()] + f"// Mutated: removed {check_condition}\n" + content[match.end():]
                description = f"{desc_base}: {check_condition}"
                
                results.append((mutated, description))
        
        return results

class ReentrancyMutator(MutationOperator):
    """Introduce reentrancy vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="reentrancy",
            description="Reorders operations to introduce potential reentrancy vulnerabilities"
        )
    
    def mutate(self, content: str) -> List[Tuple[str, str]]:
        """Reorder external calls and state changes."""
        results = []
        
        # Pattern for detecting external calls followed by state changes
        # This is simplified; a real implementation would use the parser
        transfer_patterns = [
            (r'(\s*)([^;]*\.(transfer|send|call)\s*\([^;]*\);)(\s*)([^;]*\w+\s*=\s*[^;]*;)',
             lambda m: f"{m.group(1)}{m.group(5)}{m.group(4)}{m.group(2)}",
             "Moved state change before external call"),
        ]
        
        for pattern, replacement_func, desc in transfer_patterns:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                replacement = replacement_func(match)
                mutated = content[:match.start()] + replacement + content[match.end():]
                results.append((mutated, desc))
        
        return results

class MutationEngine:
    """Engine for applying mutations to smart contracts."""
    
    def __init__(self):
        self.operators: List[MutationOperator] = []
    
    def register_operator(self, operator: MutationOperator) -> None:
        """Register a mutation operator."""
        self.operators.append(operator)
    
    def generate_mutations(self, file_path: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Generate mutations of a Solidity file.
        
        Args:
            file_path: Path to Solidity file
            output_dir: Directory to write mutated files (if None, files are not written)
            
        Returns:
            List of mutation details including description and path to mutated file
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        content = path.read_text(encoding="utf-8")
        result = []
        
        for operator in self.operators:
            mutations = operator.mutate(content)
            
            for idx, (mutated_content, description) in enumerate(mutations):
                mutation_info = {
                    "original_file": str(path),
                    "operator_name": operator.name,
                    "description": description,
                    "mutation_id": f"{path.stem}_{operator.name}_{idx}",
                    "content": mutated_content,
                }
                
                if output_dir:
                    output_path = Path(output_dir) / f"{mutation_info['mutation_id']}.sol"
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(mutated_content, encoding="utf-8")
                    mutation_info["path"] = str(output_path)
                
                result.append(mutation_info)
        
        return result

# Initialize default mutation operators
def create_default_engine() -> MutationEngine:
    """Create a mutation engine with default operators."""
    engine = MutationEngine()
    engine.register_operator(FunctionVisibilityMutator())
    engine.register_operator(AccessControlRemovalMutator())
    engine.register_operator(ReentrancyMutator())
    return engine