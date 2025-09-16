"""
Path slicing over Slither CFG with bounded breadth-first exploration.
Phase 4 implementation with node categorization and stable fingerprints.
"""
from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
import json


@dataclass
class NodeCategory:
    """Node category classification for path slicing"""
    CALL_STATIC = "CALL_static"
    CALL_DELEGATE = "CALL_delegate" 
    CALL_PLAIN = "CALL_plain"
    WRITE_STORAGE = "WRITE_storage"
    WRITE_SLOT = "WRITE_slot"
    READ_STORAGE = "READ_storage"
    GUARD_MODIFIER = "GUARD_modifier"
    GUARD_REQUIRE = "GUARD_require"
    XFER_NATIVE = "XFER_native"
    XFER_ERC20 = "XFER_erc20"
    XFER_ERC721 = "XFER_erc721"
    EVENT = "EVENT"
    LOOP = "LOOP"
    TRY = "TRY"
    ASM = "ASM"
    OTHER = "OTHER"


@dataclass
class PathSlice:
    """Represents a path slice through the control flow graph"""
    
    contract: str
    function: str
    start_node: Any  # Slither node
    end_node: Any    # Slither node
    node_sequence: List[str] = field(default_factory=list)  # Category sequence
    node_details: List[Dict[str, Any]] = field(default_factory=list)
    path_fingerprint: str = ""
    termination_reason: str = ""  # "complete", "max_nodes", "loop_detected", "cross_contract"
    
    # Metadata
    has_reentrancy_guard: bool = False
    external_calls: List[Dict[str, Any]] = field(default_factory=list)
    state_modifications: List[Dict[str, Any]] = field(default_factory=list)
    hop_count: int = 0  # Cross-contract hops
    
    def generate_fingerprint(self, solc_version: str = "", evm_version: str = "", optimizer: bool = False) -> str:
        """Generate stable path fingerprint using sha256"""
        # Create deterministic representation
        path_data = {
            "contract": self.contract,
            "function": self.function,
            "node_sequence": self.node_sequence,
            "solc_version": solc_version,
            "evm_version": evm_version,
            "optimizer": optimizer
        }
        
        # Serialize and hash
        canonical_json = json.dumps(path_data, sort_keys=True, separators=(',', ':'))
        file_hash = hashlib.sha256(f"{self.contract}_{self.function}".encode()).hexdigest()[:8]
        path_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
        
        self.path_fingerprint = f"path:{self.contract}:{self.function}:{path_hash}"
        return self.path_fingerprint


@dataclass
class PathSlicingConfig:
    """Configuration for path slicing analysis"""
    max_nodes: int = 80
    max_loop_iterations: int = 2
    enable_cross_contract: bool = True
    detect_reentrancy_guards: bool = True
    cache_slices: bool = True
    cache_dir: Optional[Path] = None


class PathSlicer:
    """
    Path slicing engine for extracting categorized node sequences from Slither CFG.
    """
    
    def __init__(self, config: Optional[PathSlicingConfig] = None):
        self.config = config or PathSlicingConfig()
        self.slice_cache: Dict[str, PathSlice] = {}
        
        # Reentrancy guard patterns
        self.reentrancy_guard_patterns = [
            "nonReentrant",
            "reentrancyGuard",
            "noReentrancy",
            "_mutex",
            "_status",
            "ReentrancyGuard"
        ]
    
    def extract_paths(self, slither_result: Any, target_functions: Optional[List[str]] = None) -> List[PathSlice]:
        """
        Extract path slices from Slither analysis result.
        
        Args:
            slither_result: Slither compilation result
            target_functions: Optional list of function names to analyze
            
        Returns:
            List of PathSlice objects
        """
        path_slices = []
        
        if not hasattr(slither_result, 'contracts'):
            return path_slices
        
        for contract in slither_result.contracts:
            contract_slices = self._extract_contract_paths(contract, target_functions)
            path_slices.extend(contract_slices)
        
        return path_slices
    
    def _extract_contract_paths(self, contract: Any, target_functions: Optional[List[str]]) -> List[PathSlice]:
        """Extract path slices for a specific contract"""
        contract_slices = []
        
        if not hasattr(contract, 'functions'):
            return contract_slices
        
        for function in contract.functions:
            # Filter by target functions if specified
            if target_functions and function.name not in target_functions:
                continue
            
            # Skip view/pure functions unless they have interesting patterns
            if hasattr(function, 'view') and function.view and not self._has_interesting_patterns(function):
                continue
            
            function_slices = self._extract_function_paths(contract, function)
            contract_slices.extend(function_slices)
        
        return contract_slices
    
    def _has_interesting_patterns(self, function: Any) -> bool:
        """Check if a view/pure function has interesting patterns worth analyzing"""
        # Look for external calls, assembly, or complex control flow
        if hasattr(function, 'nodes'):
            for node in function.nodes:
                if self._categorize_node(node) in [
                    NodeCategory.CALL_STATIC, NodeCategory.CALL_DELEGATE, NodeCategory.CALL_PLAIN,
                    NodeCategory.ASM, NodeCategory.TRY
                ]:
                    return True
        return False
    
    def _extract_function_paths(self, contract: Any, function: Any) -> List[PathSlice]:
        """Extract path slices for a specific function using BFS"""
        if not hasattr(function, 'nodes') or not function.nodes:
            return []
        
        # Generate cache key
        cache_key = self._generate_cache_key(contract, function)
        
        # Check cache first
        if self.config.cache_slices and cache_key in self.slice_cache:
            return [self.slice_cache[cache_key]]
        
        # Perform BFS path exploration
        entry_node = function.entry_point if hasattr(function, 'entry_point') else function.nodes[0]
        path_slice = self._bfs_explore(contract, function, entry_node)
        
        # Cache result
        if self.config.cache_slices:
            self.slice_cache[cache_key] = path_slice
        
        return [path_slice] if path_slice else []
    
    def _bfs_explore(self, contract: Any, function: Any, start_node: Any) -> Optional[PathSlice]:
        """Perform bounded BFS exploration of the function CFG"""
        
        # Initialize path slice
        path_slice = PathSlice(
            contract=contract.name,
            function=function.name,
            start_node=start_node,
            end_node=start_node
        )
        
        # BFS state
        queue = deque([(start_node, 0, set())])  # (node, depth, visited_nodes)
        loop_encounters = {}  # Track loop backedges
        visited_global = set()
        
        while queue and len(path_slice.node_sequence) < self.config.max_nodes:
            current_node, depth, path_visited = queue.popleft()
            
            if current_node in visited_global:
                continue
            visited_global.add(current_node)
            
            # Categorize and add node
            category = self._categorize_node(current_node)
            path_slice.node_sequence.append(category)
            
            # Extract node details
            node_detail = self._extract_node_details(current_node, category)
            path_slice.node_details.append(node_detail)
            
            # Update path slice metadata
            self._update_path_metadata(path_slice, current_node, category, node_detail)
            
            # Check for termination conditions
            if not hasattr(current_node, 'sons') or not current_node.sons:
                path_slice.end_node = current_node
                path_slice.termination_reason = "complete"
                break
            
            # Process successor nodes
            for successor in current_node.sons:
                # Check for loop backedge
                if successor in path_visited:
                    loop_key = (current_node, successor)
                    loop_encounters[loop_key] = loop_encounters.get(loop_key, 0) + 1
                    
                    if loop_encounters[loop_key] >= self.config.max_loop_iterations:
                        path_slice.termination_reason = "loop_detected"
                        continue
                
                # Check for cross-contract calls
                if self._is_cross_contract_call(successor):
                    path_slice.hop_count += 1
                    if self.config.enable_cross_contract:
                        # Record hop but don't inline
                        hop_detail = {
                            "type": "cross_contract_hop",
                            "target": str(successor),
                            "from_node": str(current_node)
                        }
                        path_slice.node_details.append(hop_detail)
                        path_slice.termination_reason = "cross_contract"
                    continue
                
                # Add to queue for further exploration
                new_path_visited = path_visited | {current_node}
                queue.append((successor, depth + 1, new_path_visited))
        
        # Set termination reason if max nodes reached
        if len(path_slice.node_sequence) >= self.config.max_nodes:
            path_slice.termination_reason = "max_nodes"
        
        # Generate fingerprint
        path_slice.generate_fingerprint()
        
        return path_slice
    
    def _categorize_node(self, node: Any) -> str:
        """Categorize a CFG node into predefined categories"""
        
        # Check for different node types (Slither-specific)
        node_str = str(node).lower() if node else ""
        
        # Assembly blocks
        if hasattr(node, 'irs') and any('asm' in str(ir).lower() for ir in node.irs):
            return NodeCategory.ASM
        
        # Try-catch blocks
        if 'try' in node_str or 'catch' in node_str:
            return NodeCategory.TRY
        
        # Loop constructs
        if any(keyword in node_str for keyword in ['for', 'while', 'do']):
            return NodeCategory.LOOP
        
        # Event emissions
        if 'emit' in node_str or 'event' in node_str:
            return NodeCategory.EVENT
        
        # External calls
        if hasattr(node, 'irs'):
            for ir in node.irs:
                ir_str = str(ir).lower()
                if 'call' in ir_str:
                    if 'staticcall' in ir_str:
                        return NodeCategory.CALL_STATIC
                    elif 'delegatecall' in ir_str:
                        return NodeCategory.CALL_DELEGATE
                    else:
                        return NodeCategory.CALL_PLAIN
        
        # Storage operations
        if hasattr(node, 'state_variables_written') and node.state_variables_written:
            # Check if it's a specific slot write
            if any('slot' in str(var).lower() for var in node.state_variables_written):
                return NodeCategory.WRITE_SLOT
            return NodeCategory.WRITE_STORAGE
        
        if hasattr(node, 'state_variables_read') and node.state_variables_read:
            return NodeCategory.READ_STORAGE
        
        # Guards (modifiers and requires)
        if hasattr(node, 'modifiers') and node.modifiers:
            return NodeCategory.GUARD_MODIFIER
        
        if 'require' in node_str or 'assert' in node_str or 'revert' in node_str:
            return NodeCategory.GUARD_REQUIRE
        
        # Value transfers
        if 'transfer' in node_str or 'send' in node_str or 'call{value:' in node_str:
            if 'erc20' in node_str or 'transfer(' in node_str:
                return NodeCategory.XFER_ERC20
            elif 'erc721' in node_str or 'safeTransferFrom' in node_str:
                return NodeCategory.XFER_ERC721
            else:
                return NodeCategory.XFER_NATIVE
        
        return NodeCategory.OTHER
    
    def _extract_node_details(self, node: Any, category: str) -> Dict[str, Any]:
        """Extract detailed information from a node"""
        details = {
            "category": category,
            "node_id": str(node) if node else "unknown",
            "source_mapping": {}
        }
        
        # Add source mapping if available
        if hasattr(node, 'source_mapping') and node.source_mapping:
            details["source_mapping"] = {
                "start": getattr(node.source_mapping, 'start', 0),
                "length": getattr(node.source_mapping, 'length', 0),
                "filename": getattr(node.source_mapping, 'filename', "")
            }
        
        # Category-specific details
        if category.startswith("CALL_"):
            details["call_details"] = self._extract_call_details(node)
        elif category.startswith("WRITE_") or category.startswith("READ_"):
            details["storage_details"] = self._extract_storage_details(node)
        elif category.startswith("GUARD_"):
            details["guard_details"] = self._extract_guard_details(node)
        elif category.startswith("XFER_"):
            details["transfer_details"] = self._extract_transfer_details(node)
        
        return details
    
    def _extract_call_details(self, node: Any) -> Dict[str, Any]:
        """Extract call-specific details"""
        details = {}
        
        if hasattr(node, 'irs'):
            for ir in node.irs:
                ir_str = str(ir)
                if 'call' in ir_str.lower():
                    details["call_type"] = "external"
                    details["call_target"] = self._extract_call_target(ir)
                    details["call_data"] = ir_str
                    break
        
        return details
    
    def _extract_call_target(self, ir: Any) -> str:
        """Extract call target from IR"""
        if hasattr(ir, 'destination'):
            return str(ir.destination)
        return "unknown"
    
    def _extract_storage_details(self, node: Any) -> Dict[str, Any]:
        """Extract storage operation details"""
        details = {}
        
        if hasattr(node, 'state_variables_written') and node.state_variables_written:
            details["variables_written"] = [str(var) for var in node.state_variables_written]
        
        if hasattr(node, 'state_variables_read') and node.state_variables_read:
            details["variables_read"] = [str(var) for var in node.state_variables_read]
        
        return details
    
    def _extract_guard_details(self, node: Any) -> Dict[str, Any]:
        """Extract guard-specific details"""
        details = {}
        
        node_str = str(node) if node else ""
        
        # Check for reentrancy guards
        is_reentrancy_guard = any(pattern in node_str for pattern in self.reentrancy_guard_patterns)
        details["is_reentrancy_guard"] = is_reentrancy_guard
        
        if hasattr(node, 'modifiers') and node.modifiers:
            details["modifiers"] = [str(mod) for mod in node.modifiers]
        
        # Extract require/assert conditions
        if 'require' in node_str or 'assert' in node_str:
            details["condition_type"] = "require" if 'require' in node_str else "assert"
            details["condition_text"] = node_str
        
        return details
    
    def _extract_transfer_details(self, node: Any) -> Dict[str, Any]:
        """Extract transfer-specific details"""
        details = {}
        
        node_str = str(node) if node else ""
        
        if 'value:' in node_str:
            details["has_value"] = True
        
        if 'erc20' in node_str.lower() or 'transfer(' in node_str:
            details["token_standard"] = "ERC20"
        elif 'erc721' in node_str.lower():
            details["token_standard"] = "ERC721"
        else:
            details["token_standard"] = "native"
        
        return details
    
    def _update_path_metadata(self, path_slice: PathSlice, node: Any, category: str, node_detail: Dict[str, Any]):
        """Update path slice metadata based on current node"""
        
        # Check for reentrancy guards
        if category.startswith("GUARD_") and node_detail.get("guard_details", {}).get("is_reentrancy_guard"):
            path_slice.has_reentrancy_guard = True
        
        # Track external calls
        if category.startswith("CALL_"):
            call_info = {
                "category": category,
                "details": node_detail.get("call_details", {}),
                "node_id": str(node)
            }
            path_slice.external_calls.append(call_info)
        
        # Track state modifications
        if category.startswith("WRITE_"):
            mod_info = {
                "category": category,
                "details": node_detail.get("storage_details", {}),
                "node_id": str(node)
            }
            path_slice.state_modifications.append(mod_info)
    
    def _is_cross_contract_call(self, node: Any) -> bool:
        """Check if a node represents a cross-contract call"""
        # Simple heuristic - in a real implementation, this would check
        # if the call target is to a different contract
        node_str = str(node).lower() if node else ""
        return 'external' in node_str and 'call' in node_str
    
    def _generate_cache_key(self, contract: Any, function: Any) -> str:
        """Generate cache key for function path slice"""
        contract_name = contract.name if hasattr(contract, 'name') else str(contract)
        function_name = function.name if hasattr(function, 'name') else str(function)
        
        # Include function signature for uniqueness
        func_sig = ""
        if hasattr(function, 'signature'):
            func_sig = str(function.signature)
        
        key_data = f"{contract_name}:{function_name}:{func_sig}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def save_cache(self, cache_path: Path):
        """Save path slice cache to disk"""
        if not self.slice_cache:
            return
        
        cache_data = {}
        for key, slice_obj in self.slice_cache.items():
            # Convert to serializable format
            cache_data[key] = {
                "contract": slice_obj.contract,
                "function": slice_obj.function,
                "node_sequence": slice_obj.node_sequence,
                "path_fingerprint": slice_obj.path_fingerprint,
                "termination_reason": slice_obj.termination_reason,
                "has_reentrancy_guard": slice_obj.has_reentrancy_guard,
                "external_calls": slice_obj.external_calls,
                "state_modifications": slice_obj.state_modifications,
                "hop_count": slice_obj.hop_count
            }
        
        with open(cache_path, 'w') as f:
            json.dump(cache_data, f, indent=2)
    
    def load_cache(self, cache_path: Path):
        """Load path slice cache from disk"""
        if not cache_path.exists():
            return
        
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            
            for key, slice_data in cache_data.items():
                # Reconstruct PathSlice object (nodes will be None but fingerprint preserved)
                path_slice = PathSlice(
                    contract=slice_data["contract"],
                    function=slice_data["function"],
                    start_node=None,
                    end_node=None,
                    node_sequence=slice_data["node_sequence"],
                    path_fingerprint=slice_data["path_fingerprint"],
                    termination_reason=slice_data["termination_reason"],
                    has_reentrancy_guard=slice_data["has_reentrancy_guard"],
                    external_calls=slice_data["external_calls"],
                    state_modifications=slice_data["state_modifications"],
                    hop_count=slice_data["hop_count"]
                )
                
                self.slice_cache[key] = path_slice
        
        except Exception as e:
            print(f"Warning: Failed to load path slice cache: {e}")