"""
Slither integration adapter for vulnhuntr2.
This module handles running Slither and extracting useful information.
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Optional as Opt

from vulnhuntr.core.models import Contract, Function, Variable, SlitherResult

logger = logging.getLogger(__name__)

# Detect whether slither is available on PATH at import time
try:
    subprocess.run(["slither", "--version"], capture_output=True, text=True, check=False)
    SLITHER_AVAILABLE = True
except Exception:
    SLITHER_AVAILABLE = False


@dataclass
class SlitherFunctionInfo:
    name: str
    visibility: str
    state_mutability: str
    modifiers: List[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    file: str = ""


@dataclass
class SlitherVariableInfo:
    name: str
    type: str
    visibility: str
    is_constant: bool = False
    is_immutable: bool = False
    line: int = 0


@dataclass
class SlitherContractInfo:
    name: str
    file: str
    line_start: int
    line_end: int
    functions: List[SlitherFunctionInfo] = field(default_factory=list)
    state_vars: List[SlitherVariableInfo] = field(default_factory=list)


@dataclass
class SlitherAnalysisResult:
    contracts: List[SlitherContractInfo]
    raw_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SlitherAdapter:
    """
    Adapter for running Slither and extracting relevant information.
    """
    
    def __init__(self, solc_version: Optional[str] = None):
        self.solc_version = solc_version
    
    def run_slither(self, target_path: str, output_file: Optional[str] = None) -> Optional[SlitherResult]:
        """
        Run Slither on the target path and return the parsed results.
        """
        logger.info(f"Running Slither on {target_path}")

        if not SLITHER_AVAILABLE:
            logger.warning("Slither not available; skipping analysis")
            return None

        if not Path(target_path).exists():
            logger.warning("Target path does not exist: %s", target_path)
            return None
        
        # Create a temporary file for Slither output if none provided
        temp_output = output_file is None
        if temp_output:
            fd, output_file = tempfile.mkstemp(suffix=".json", prefix="vulnhuntr_slither_")
            os.close(fd)
        
        try:
            cmd = ["slither", target_path, "--json", output_file]
            if self.solc_version:
                cmd.extend(["--solc-solcs-select", self.solc_version])
            
            # Run Slither
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Don't raise on non-zero exit - Slither may have findings but still output JSON
            )
            
            if result.returncode != 0:
                logger.warning(f"Slither exited with code {result.returncode}")
                logger.debug(f"Slither stderr: {result.stderr}")
            
            # Parse the JSON output
            with open(output_file, "r") as f:
                slither_data = json.load(f)
            
            # Process the Slither output into our data model
            contracts, functions = self._parse_slither_output(slither_data)
            
            return SlitherResult(
                contracts=contracts,
                functions=functions,
                raw_data=slither_data
            )
        except Exception as e:
            logger.error("Failed to run slither: %s", e)
            return None
        finally:
            # Clean up temp file if we created one
            if temp_output and output_file:
                try:
                    os.unlink(output_file)
                except Exception:
                    pass
    
    def _parse_slither_output(self, data: Dict) -> Tuple[List[Contract], List[Function]]:
        """
        Parse the Slither JSON output into our data model.
        
        Returns:
            Tuple of (contracts, functions)
        """
        contracts = []
        functions = []
        
        # Extract contracts and their details
        for contract_data in data.get("contracts", []):
            contract = self._extract_contract(contract_data)
            if contract:
                contracts.append(contract)
                
                # Extract functions from this contract
                contract_functions = self._extract_functions(contract_data, contract.name)
                functions.extend(contract_functions)
        
        return contracts, functions
    
    def _extract_contract(self, contract_data: Dict) -> Optional[Contract]:
        """Extract contract information from Slither data."""
        try:
            name = contract_data.get("name", "")
            if not name:
                return None
                
            return Contract(
                name=name,
                file_path=contract_data.get("source_mapping", {}).get("filename_absolute", ""),
                line_start=contract_data.get("source_mapping", {}).get("start", 0),
                line_end=contract_data.get("source_mapping", {}).get("start", 0) + 
                        contract_data.get("source_mapping", {}).get("length", 0),
                variables=self._extract_variables(contract_data),
                is_abstract=contract_data.get("is_abstract", False),
                inherits_from=[base.get("name", "") for base in contract_data.get("inheritance", [])],
                source=self._extract_contract_source(contract_data)
            )
        except Exception as e:
            logger.error(f"Error extracting contract: {e}")
            return None
    
    def _extract_variables(self, contract_data: Dict) -> List[Variable]:
        """Extract state variables from a contract."""
        variables = []
        
        for var_data in contract_data.get("state_variables", []):
            try:
                var = Variable(
                    name=var_data.get("name", ""),
                    type=var_data.get("type", ""),
                    visibility=var_data.get("visibility", ""),
                    line=var_data.get("source_mapping", {}).get("start_line", 0),
                    is_constant=var_data.get("is_constant", False),
                    is_immutable=var_data.get("is_immutable", False)
                )
                variables.append(var)
            except Exception as e:
                logger.warning(f"Error parsing variable: {e}")
        
        return variables
    
    def _extract_contract_source(self, contract_data: Dict) -> str:
        """Extract the contract source code."""
        source = ""
        try:
            filename = contract_data.get("source_mapping", {}).get("filename_absolute", "")
            if filename and os.path.exists(filename):
                with open(filename, 'r') as file:
                    source = file.read()
        except Exception as e:
            logger.warning(f"Could not read source: {e}")
        return source
    
    def _extract_functions(self, contract_data: Dict, contract_name: str) -> List[Function]:
        """Extract functions from a contract."""
        functions = []
        
        for func_data in contract_data.get("functions", []):
            try:
                # Extract external calls this function makes
                external_calls = []
                for call in func_data.get("external_calls", []):
                    if isinstance(call, list) and len(call) >= 2:
                        external_calls.append(call[1])  # The second element is typically the function name
                
                # Extract state variables written
                state_vars_written = [write[0] for write in func_data.get("state_variables_written", [])
                                     if isinstance(write, list) and len(write) >= 1]
                
                # Extract state variables read
                state_vars_read = [read[0] for read in func_data.get("state_variables_read", [])
                                  if isinstance(read, list) and len(read) >= 1]
                
                source_mapping = func_data.get("source_mapping", {})
                
                func = Function(
                    name=func_data.get("name", ""),
                    signature=func_data.get("signature", ""),
                    contract_name=contract_name,
                    visibility=func_data.get("visibility", ""),
                    state_mutability=func_data.get("state_mutability", ""),
                    line_start=source_mapping.get("start_line", 0),
                    line_end=source_mapping.get("end_line", 0),
                    file_path=source_mapping.get("filename_absolute", ""),
                    external_calls=external_calls,
                    state_vars_written=state_vars_written,
                    state_vars_read=state_vars_read,
                    modifiers=[mod[0] for mod in func_data.get("modifiers", [])
                              if isinstance(mod, list) and len(mod) >= 1],
                    is_constructor=func_data.get("is_constructor", False),
                    is_fallback=func_data.get("name", "") == "fallback",
                    is_receive=func_data.get("name", "") == "receive"
                )
                functions.append(func)
            except Exception as e:
                logger.warning(f"Error extracting function: {e}")
        
        return functions


def _map_to_result(result: Opt[SlitherResult]) -> Opt[SlitherAnalysisResult]:
    """Map internal SlitherResult to public SlitherAnalysisResult used by tests."""
    if result is None:
        return None
    contracts: List[SlitherContractInfo] = []
    by_contract: Dict[str, SlitherContractInfo] = {}
    for c in result.contracts:
        ci = SlitherContractInfo(
            name=c.name,
            file=c.file_path,
            line_start=c.line_start,
            line_end=c.line_end,
        )
        # variables
        for v in c.variables:
            ci.state_vars.append(
                SlitherVariableInfo(
                    name=v.name,
                    type=v.type,
                    visibility=v.visibility,
                    is_constant=v.is_constant,
                    is_immutable=v.is_immutable,
                    line=v.line,
                )
            )
        contracts.append(ci)
        by_contract[c.name] = ci
    for f in result.functions:
        fi = SlitherFunctionInfo(
            name=f.name,
            visibility=f.visibility,
            state_mutability=f.state_mutability,
            modifiers=list(f.modifiers),
            line_start=f.line_start,
            line_end=f.line_end,
            file=f.file_path,
        )
        if f.contract_name in by_contract:
            by_contract[f.contract_name].functions.append(fi)
    return SlitherAnalysisResult(contracts=contracts, raw_data=result.raw_data)


def run_slither(target_path: Path | str) -> Opt[SlitherAnalysisResult]:
    """Module-level helper to run Slither and return mapped analysis result.

    Returns None when Slither is not available or the path is invalid.
    """
    adapter = SlitherAdapter()
    internal = adapter.run_slither(str(target_path))
    return _map_to_result(internal)
