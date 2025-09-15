"""
Slither integration adapter for static analysis.

This module provides integration with Slither static analyzer to extract
structured metadata from Solidity contracts including contracts, functions,
state variables, events, and inheritance information.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from slither import Slither
    from slither.core.declarations import Contract, Function, StateVariable
    from slither.core.variables.event_variable import EventVariable
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False


@dataclass
class StateVarInfo:
    """Information about a state variable."""
    name: str
    type: str
    visibility: str
    line: int


@dataclass
class FunctionInfo:
    """Information about a contract function."""
    name: str
    visibility: str
    mutability: str
    payable: bool
    line_start: int
    line_end: int
    modifiers: List[str] = field(default_factory=list)
    events_emitted: List[str] = field(default_factory=list)


@dataclass
class ContractInfo:
    """Information about a contract."""
    name: str
    file: str
    line_start: int
    inherits: List[str] = field(default_factory=list)
    state_vars: List[StateVarInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)


@dataclass
class SlitherAnalysisResult:
    """Result of Slither analysis."""
    contracts: List[ContractInfo] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        result = {
            "contracts": [asdict(contract) for contract in self.contracts]
        }
        if self.raw:
            result["raw"] = self.raw
        return result


def run_slither(path: Path, include_external: bool = False) -> Optional[SlitherAnalysisResult]:
    """
    Run Slither analysis on the target path.
    
    Args:
        path: Path to analyze (file or directory)
        include_external: Whether to include external contracts in analysis
        
    Returns:
        SlitherAnalysisResult or None if Slither is not available
        
    Raises:
        ImportError: If Slither is not installed
        Exception: If analysis fails
    """
    if not SLITHER_AVAILABLE:
        return None
    
    try:
        # Initialize Slither
        slither = Slither(str(path))
        
        # Extract contract information
        contracts = []
        raw_data = {"compilation_units": [], "contracts": []}
        
        for compilation_unit in slither.compilation_units:
            cu_data = {
                "source_units": [str(su) for su in compilation_unit.source_units],
                "contracts": []
            }
            
            for contract in compilation_unit.contracts:
                # Skip external contracts if not requested
                if not include_external and contract.is_from_dependency():
                    continue
                
                contract_info = _extract_contract_info(contract)
                contracts.append(contract_info)
                
                # Store raw contract data for debugging
                cu_data["contracts"].append({
                    "name": contract.name,
                    "file": str(contract.source_mapping.filename),
                    "is_interface": contract.is_interface,
                    "is_library": contract.is_library,
                    "inheritance": [str(base) for base in contract.inheritance],
                })
            
            raw_data["compilation_units"].append(cu_data)
        
        return SlitherAnalysisResult(contracts=contracts, raw=raw_data)
        
    except Exception as e:
        # Log the error but don't crash the entire analysis
        print(f"Warning: Slither analysis failed: {e}")
        return None


def _extract_contract_info(contract: "Contract") -> ContractInfo:
    """Extract contract information from Slither contract object."""
    # Get source mapping for line numbers
    source_mapping = contract.source_mapping
    line_start = source_mapping.lines[0] if source_mapping.lines else 0
    
    # Extract inheritance
    inherits = [str(base.name) for base in contract.inheritance if base != contract]
    
    # Extract state variables
    state_vars = []
    for var in contract.state_variables_declared:
        if hasattr(var, 'source_mapping') and var.source_mapping:
            var_line = var.source_mapping.lines[0] if var.source_mapping.lines else 0
        else:
            var_line = 0
            
        state_vars.append(StateVarInfo(
            name=var.name,
            type=str(var.type),
            visibility=str(var.visibility),
            line=var_line
        ))
    
    # Extract functions
    functions = []
    for func in contract.functions_declared:
        func_info = _extract_function_info(func)
        functions.append(func_info)
    
    return ContractInfo(
        name=contract.name,
        file=str(contract.source_mapping.filename),
        line_start=line_start,
        inherits=inherits,
        state_vars=state_vars,
        functions=functions
    )


def _extract_function_info(func: "Function") -> FunctionInfo:
    """Extract function information from Slither function object."""
    # Get source mapping for line numbers
    source_mapping = func.source_mapping
    line_start = source_mapping.lines[0] if source_mapping and source_mapping.lines else 0
    line_end = source_mapping.lines[-1] if source_mapping and source_mapping.lines else line_start
    
    # Extract modifiers
    modifiers = [str(mod) for mod in func.modifiers]
    
    # Extract events emitted (simplified - just event names)
    events_emitted = []
    try:
        for node in func.nodes:
            for ir in node.irs:
                if hasattr(ir, 'function') and hasattr(ir.function, 'name'):
                    if 'emit' in str(ir):
                        # This is a simplified extraction - in real usage you'd parse more carefully
                        events_emitted.append(str(ir))
    except:
        # If extraction fails, continue without events
        pass
    
    return FunctionInfo(
        name=func.name,
        visibility=str(func.visibility),
        mutability=str(func.state_mutability),
        payable=func.payable,
        line_start=line_start,
        line_end=line_end,
        modifiers=modifiers,
        events_emitted=events_emitted
    )