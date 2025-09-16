"""
Knowledge Graph Foundation (KGX) for Phase 6.

Builds and queries a knowledge graph of contracts, functions, state variables,
roles, tokens, oracles, bridges, and invariants with relationship edges.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""
    CONTRACT = "Contract"
    FUNCTION = "Function"
    STATE_VAR = "StateVar"
    ROLE = "Role"
    TOKEN = "Token"
    ORACLE = "Oracle"
    BRIDGE = "Bridge"
    INVARIANT = "Invariant"


class EdgeType(Enum):
    """Types of relationships in the knowledge graph."""
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    GUARDS = "guards"
    DELEGATES = "delegates"
    PRICE_FEEDS = "price_feeds"
    BRIDGES_TO = "bridges_to"
    INVARIANT_DEPENDS_ON = "invariant_depends_on"
    INHERITS = "inherits"
    MODIFIES = "modifies"
    OWNS = "owns"


@dataclass
class KGNode:
    """A node in the knowledge graph."""
    
    node_id: str
    node_type: NodeType
    name: str
    
    # Metadata
    properties: Dict[str, Any] = field(default_factory=dict)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "name": self.name,
            "properties": self.properties,
            "source_file": self.source_file,
            "source_line": self.source_line
        }


@dataclass
class KGEdge:
    """An edge (relationship) in the knowledge graph."""
    
    edge_id: str
    edge_type: EdgeType
    source_node_id: str
    target_node_id: str
    
    # Metadata
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type.value,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "properties": self.properties,
            "weight": self.weight
        }


class KnowledgeGraph:
    """Main knowledge graph structure."""
    
    def __init__(self):
        self.nodes: Dict[str, KGNode] = {}
        self.edges: Dict[str, KGEdge] = {}
        self.node_edges: Dict[str, List[str]] = {}  # node_id -> list of edge_ids
        self.build_time_ms: int = 0
        
    def add_node(self, node: KGNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.node_id] = node
        if node.node_id not in self.node_edges:
            self.node_edges[node.node_id] = []
    
    def add_edge(self, edge: KGEdge) -> None:
        """Add an edge to the graph."""
        self.edges[edge.edge_id] = edge
        
        # Update node edge references
        if edge.source_node_id not in self.node_edges:
            self.node_edges[edge.source_node_id] = []
        if edge.target_node_id not in self.node_edges:
            self.node_edges[edge.target_node_id] = []
            
        self.node_edges[edge.source_node_id].append(edge.edge_id)
        self.node_edges[edge.target_node_id].append(edge.edge_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[KGNode]:
        """Get all nodes of a specific type."""
        return [node for node in self.nodes.values() if node.node_type == node_type]
    
    def get_edges_by_type(self, edge_type: EdgeType) -> List[KGEdge]:
        """Get all edges of a specific type."""
        return [edge for edge in self.edges.values() if edge.edge_type == edge_type]
    
    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[KGNode]:
        """Get neighboring nodes, optionally filtered by edge type."""
        neighbors = []
        
        for edge_id in self.node_edges.get(node_id, []):
            edge = self.edges[edge_id]
            
            if edge_type and edge.edge_type != edge_type:
                continue
                
            # Find the other node in the edge
            other_node_id = edge.target_node_id if edge.source_node_id == node_id else edge.source_node_id
            if other_node_id in self.nodes:
                neighbors.append(self.nodes[other_node_id])
        
        return neighbors
    
    def find_path(self, source_id: str, target_id: str, max_depth: int = 3) -> List[List[str]]:
        """Find paths between two nodes (BFS)."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return []
        
        queue = [(source_id, [source_id])]
        visited = set()
        paths = []
        
        while queue and len(paths) < 10:  # Limit number of paths
            current_id, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
                
            if current_id == target_id and len(path) > 1:
                paths.append(path)
                continue
            
            if current_id in visited:
                continue
            
            visited.add(current_id)
            
            # Add neighbors to queue
            for neighbor in self.get_neighbors(current_id):
                if neighbor.node_id not in path:
                    queue.append((neighbor.node_id, path + [neighbor.node_id]))
        
        return paths
    
    def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        node_type_counts = {}
        for node_type in NodeType:
            node_type_counts[node_type.value] = len(self.get_nodes_by_type(node_type))
        
        edge_type_counts = {}
        for edge_type in EdgeType:
            edge_type_counts[edge_type.value] = len(self.get_edges_by_type(edge_type))
        
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": node_type_counts,
            "edge_types": edge_type_counts,
            "build_time_ms": self.build_time_ms
        }


class KnowledgeGraphBuilder:
    """Builds knowledge graph from contract analysis."""
    
    def __init__(self):
        self.graph = KnowledgeGraph()
        self.node_counter = 0
        self.edge_counter = 0
    
    def build_from_contracts(self, contracts: List[Any], 
                           bridges: Optional[List[Any]] = None,
                           oracles: Optional[List[Any]] = None,
                           invariants: Optional[List[Any]] = None) -> KnowledgeGraph:
        """Build knowledge graph from contract information."""
        start_time = time.time()
        
        # Build contract nodes
        for contract in contracts:
            self._add_contract_nodes(contract)
        
        # Add bridge nodes
        if bridges:
            for bridge in bridges:
                self._add_bridge_node(bridge)
        
        # Add oracle nodes
        if oracles:
            for oracle in oracles:
                self._add_oracle_node(oracle)
        
        # Add invariant nodes
        if invariants:
            for invariant in invariants:
                self._add_invariant_node(invariant)
        
        # Build relationships
        self._build_relationships(contracts)
        
        self.graph.build_time_ms = int((time.time() - start_time) * 1000)
        return self.graph
    
    def _add_contract_nodes(self, contract: Any) -> str:
        """Add contract and its components as nodes."""
        contract_name = getattr(contract, 'name', 'Unknown')
        contract_id = self._generate_node_id(NodeType.CONTRACT, contract_name)
        
        # Contract node
        contract_node = KGNode(
            node_id=contract_id,
            node_type=NodeType.CONTRACT,
            name=contract_name,
            properties={
                "file_path": getattr(contract, 'file_path', ''),
                "inheritance": getattr(contract, 'inheritance', []),
                "is_library": contract_name.endswith('Lib') or 'Library' in contract_name
            },
            source_file=getattr(contract, 'file_path', None)
        )
        self.graph.add_node(contract_node)
        
        # Function nodes
        functions = getattr(contract, 'functions', [])
        for func in functions:
            func_id = self._add_function_node(func, contract_id)
            
            # Connect function to contract
            self._add_edge(
                EdgeType.MODIFIES, 
                func_id, 
                contract_id,
                {"relationship": "belongs_to"}
            )
        
        # State variable nodes
        state_vars = getattr(contract, 'state_variables', [])
        for var in state_vars:
            var_id = self._add_state_var_node(var, contract_id)
            
            # Connect state var to contract
            self._add_edge(
                EdgeType.MODIFIES,
                contract_id,
                var_id,
                {"relationship": "owns"}
            )
        
        # Role nodes (if any access control patterns detected)
        self._add_role_nodes(contract, contract_id)
        
        return contract_id
    
    def _add_function_node(self, func: Any, contract_id: str) -> str:
        """Add function node."""
        func_name = getattr(func, 'name', 'unknown')
        func_id = self._generate_node_id(NodeType.FUNCTION, f"{contract_id}_{func_name}")
        
        visibility = getattr(func, 'visibility', 'public')
        state_mutability = getattr(func, 'state_mutability', 'nonpayable')
        modifiers = getattr(func, 'modifiers', [])
        
        func_node = KGNode(
            node_id=func_id,
            node_type=NodeType.FUNCTION,
            name=func_name,
            properties={
                "visibility": visibility,
                "state_mutability": state_mutability,
                "modifiers": modifiers,
                "signature": getattr(func, 'signature', ''),
                "is_payable": state_mutability == 'payable',
                "is_view": state_mutability in ['view', 'pure']
            },
            source_line=getattr(func, 'start_line', None)
        )
        self.graph.add_node(func_node)
        
        return func_id
    
    def _add_state_var_node(self, var: Dict[str, Any], contract_id: str) -> str:
        """Add state variable node."""
        var_name = var.get('name', 'unknown')
        var_id = self._generate_node_id(NodeType.STATE_VAR, f"{contract_id}_{var_name}")
        
        var_node = KGNode(
            node_id=var_id,
            node_type=NodeType.STATE_VAR,
            name=var_name,
            properties={
                "type": var.get('type', 'unknown'),
                "visibility": var.get('visibility', 'internal'),
                "is_constant": var.get('is_constant', False),
                "is_immutable": var.get('is_immutable', False)
            }
        )
        self.graph.add_node(var_node)
        
        return var_id
    
    def _add_role_nodes(self, contract: Any, contract_id: str) -> None:
        """Add role nodes based on access control patterns."""
        contract_name = getattr(contract, 'name', '')
        functions = getattr(contract, 'functions', [])
        
        # Detect common roles
        roles_detected = set()
        
        for func in functions:
            modifiers = getattr(func, 'modifiers', [])
            for modifier in modifiers:
                modifier_str = str(modifier).lower()
                if 'onlyowner' in modifier_str:
                    roles_detected.add('owner')
                elif 'onlyadmin' in modifier_str:
                    roles_detected.add('admin')
                elif 'onlyoperator' in modifier_str:
                    roles_detected.add('operator')
        
        # Add role nodes
        for role in roles_detected:
            role_id = self._generate_node_id(NodeType.ROLE, f"{contract_id}_{role}")
            role_node = KGNode(
                node_id=role_id,
                node_type=NodeType.ROLE,
                name=role,
                properties={
                    "contract": contract_name,
                    "access_level": "high" if role == "owner" else "medium"
                }
            )
            self.graph.add_node(role_node)
            
            # Connect role to contract
            self._add_edge(
                EdgeType.GUARDS,
                role_id,
                contract_id,
                {"relationship": "controls_access"}
            )
    
    def _add_bridge_node(self, bridge: Any) -> str:
        """Add bridge node."""
        bridge_name = getattr(bridge, 'name', 'Unknown Bridge')
        bridge_id = self._generate_node_id(NodeType.BRIDGE, bridge_name)
        
        bridge_node = KGNode(
            node_id=bridge_id,
            node_type=NodeType.BRIDGE,
            name=bridge_name,
            properties={
                "source_chain_id": getattr(bridge, 'source_chain_id', 0),
                "target_chain_id": getattr(bridge, 'target_chain_id', 0),
                "delay_blocks": getattr(bridge, 'delay_blocks', 0),
                "escrow_addresses": getattr(bridge, 'escrow_addresses', {})
            }
        )
        self.graph.add_node(bridge_node)
        
        return bridge_id
    
    def _add_oracle_node(self, oracle: Any) -> str:
        """Add oracle node."""
        oracle_name = getattr(oracle, 'name', 'Unknown Oracle')
        oracle_id = self._generate_node_id(NodeType.ORACLE, oracle_name)
        
        oracle_node = KGNode(
            node_id=oracle_id,
            node_type=NodeType.ORACLE,
            name=oracle_name,
            properties={
                "feed_address": getattr(oracle, 'feed_address', ''),
                "chain_id": getattr(oracle, 'chain_id', 0),
                "asset_pair": getattr(oracle, 'asset_pair', ''),
                "heartbeat_seconds": getattr(oracle, 'heartbeat_seconds', 3600)
            }
        )
        self.graph.add_node(oracle_node)
        
        return oracle_id
    
    def _add_invariant_node(self, invariant: Any) -> str:
        """Add invariant node."""
        invariant_name = getattr(invariant, 'name', 'Unknown Invariant')
        invariant_id = self._generate_node_id(NodeType.INVARIANT, invariant_name)
        
        invariant_node = KGNode(
            node_id=invariant_id,
            node_type=NodeType.INVARIANT,
            name=invariant_name,
            properties={
                "scope": getattr(invariant, 'scope', ''),
                "category": getattr(invariant, 'category', ''),
                "expression": getattr(invariant, 'expr', ''),
                "auto_suggested": getattr(invariant, 'auto_suggested', False),
                "status": getattr(invariant, 'status', 'unknown')
            }
        )
        self.graph.add_node(invariant_node)
        
        return invariant_id
    
    def _build_relationships(self, contracts: List[Any]) -> None:
        """Build relationship edges between nodes."""
        for contract in contracts:
            contract_name = getattr(contract, 'name', 'Unknown')
            contract_nodes = [n for n in self.graph.nodes.values() 
                            if n.node_type == NodeType.CONTRACT and n.name == contract_name]
            
            if not contract_nodes:
                continue
                
            contract_node = contract_nodes[0]
            
            # Inheritance relationships
            inheritance = getattr(contract, 'inheritance', [])
            for parent_name in inheritance:
                parent_nodes = [n for n in self.graph.nodes.values() 
                              if n.node_type == NodeType.CONTRACT and n.name == parent_name]
                if parent_nodes:
                    self._add_edge(
                        EdgeType.INHERITS,
                        contract_node.node_id,
                        parent_nodes[0].node_id,
                        {"relationship": "inherits_from"}
                    )
            
            # Function call relationships (simplified heuristic)
            functions = getattr(contract, 'functions', [])
            for func in functions:
                func_name = getattr(func, 'name', '')
                func_nodes = [n for n in self.graph.nodes.values()
                            if n.node_type == NodeType.FUNCTION and func_name in n.name]
                
                if not func_nodes:
                    continue
                    
                func_node = func_nodes[0]
                
                # Look for external calls in function (heuristic)
                # In a real implementation, this would parse the function body
                if 'transfer' in func_name.lower():
                    # Likely calls token functions
                    token_nodes = self.graph.get_nodes_by_type(NodeType.TOKEN)
                    for token_node in token_nodes:
                        self._add_edge(
                            EdgeType.CALLS,
                            func_node.node_id,
                            token_node.node_id,
                            {"call_type": "token_transfer"}
                        )
                
                # State variable access relationships
                state_vars = getattr(contract, 'state_variables', [])
                for var in state_vars:
                    var_name = var.get('name', '')
                    if var_name in getattr(func, 'signature', ''):
                        var_nodes = [n for n in self.graph.nodes.values()
                                    if n.node_type == NodeType.STATE_VAR and var_name in n.name]
                        if var_nodes:
                            self._add_edge(
                                EdgeType.READS,
                                func_node.node_id,
                                var_nodes[0].node_id,
                                {"access_type": "state_access"}
                            )
    
    def _add_edge(self, edge_type: EdgeType, source_id: str, target_id: str, 
                 properties: Optional[Dict[str, Any]] = None) -> str:
        """Add an edge to the graph."""
        edge_id = self._generate_edge_id(edge_type, source_id, target_id)
        
        edge = KGEdge(
            edge_id=edge_id,
            edge_type=edge_type,
            source_node_id=source_id,
            target_node_id=target_id,
            properties=properties or {}
        )
        
        self.graph.add_edge(edge)
        return edge_id
    
    def _generate_node_id(self, node_type: NodeType, name: str) -> str:
        """Generate unique node ID."""
        self.node_counter += 1
        clean_name = "".join(c for c in name if c.isalnum() or c in ['_', '-'])
        return f"{node_type.value}_{clean_name}_{self.node_counter}"
    
    def _generate_edge_id(self, edge_type: EdgeType, source_id: str, target_id: str) -> str:
        """Generate unique edge ID."""
        self.edge_counter += 1
        return f"{edge_type.value}_{source_id}_{target_id}_{self.edge_counter}"


class KnowledgeGraphFilter:
    """Filter and query knowledge graph."""
    
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph
    
    def filter_nodes(self, node_type: Optional[NodeType] = None,
                    properties: Optional[Dict[str, Any]] = None) -> List[KGNode]:
        """Filter nodes by type and properties."""
        nodes = list(self.graph.nodes.values())
        
        if node_type:
            nodes = [n for n in nodes if n.node_type == node_type]
        
        if properties:
            filtered_nodes = []
            for node in nodes:
                match = True
                for key, value in properties.items():
                    if key not in node.properties or node.properties[key] != value:
                        match = False
                        break
                if match:
                    filtered_nodes.append(node)
            nodes = filtered_nodes
        
        return nodes
    
    def filter_edges(self, edge_type: Optional[EdgeType] = None,
                    source_node_type: Optional[NodeType] = None,
                    target_node_type: Optional[NodeType] = None) -> List[KGEdge]:
        """Filter edges by type and connected node types."""
        edges = list(self.graph.edges.values())
        
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        
        if source_node_type or target_node_type:
            filtered_edges = []
            for edge in edges:
                source_node = self.graph.nodes.get(edge.source_node_id)
                target_node = self.graph.nodes.get(edge.target_node_id)
                
                if source_node_type and (not source_node or source_node.node_type != source_node_type):
                    continue
                if target_node_type and (not target_node or target_node.node_type != target_node_type):
                    continue
                    
                filtered_edges.append(edge)
            edges = filtered_edges
        
        return edges
    
    def query_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Query graph using simple pattern language."""
        # Simple pattern parser for basic queries like:
        # "contract:Vault writes token:XYZ"
        # "contract:* delegatecalls>0" 
        
        results = []
        
        try:
            # Parse pattern (simplified implementation)
            if " writes " in pattern:
                parts = pattern.split(" writes ")
                source_filter = self._parse_node_filter(parts[0])
                target_filter = self._parse_node_filter(parts[1])
                
                write_edges = self.filter_edges(EdgeType.WRITES)
                
                for edge in write_edges:
                    source_node = self.graph.nodes.get(edge.source_node_id)
                    target_node = self.graph.nodes.get(edge.target_node_id)
                    
                    if (self._matches_filter(source_node, source_filter) and 
                        self._matches_filter(target_node, target_filter)):
                        results.append({
                            "source": source_node.to_dict() if source_node else None,
                            "target": target_node.to_dict() if target_node else None,
                            "edge": edge.to_dict()
                        })
            
            elif " calls " in pattern:
                parts = pattern.split(" calls ")
                source_filter = self._parse_node_filter(parts[0])
                target_filter = self._parse_node_filter(parts[1])
                
                call_edges = self.filter_edges(EdgeType.CALLS)
                
                for edge in call_edges:
                    source_node = self.graph.nodes.get(edge.source_node_id)
                    target_node = self.graph.nodes.get(edge.target_node_id)
                    
                    if (self._matches_filter(source_node, source_filter) and 
                        self._matches_filter(target_node, target_filter)):
                        results.append({
                            "source": source_node.to_dict() if source_node else None,
                            "target": target_node.to_dict() if target_node else None,
                            "edge": edge.to_dict()
                        })
            
            elif "delegatecalls>" in pattern:
                # Count delegatecall edges
                parts = pattern.split(" delegatecalls>")
                source_filter = self._parse_node_filter(parts[0])
                min_count = int(parts[1])
                
                delegate_edges = self.filter_edges(EdgeType.DELEGATES)
                node_counts = {}
                
                for edge in delegate_edges:
                    source_id = edge.source_node_id
                    if source_id not in node_counts:
                        node_counts[source_id] = 0
                    node_counts[source_id] += 1
                
                for node_id, count in node_counts.items():
                    if count > min_count:
                        node = self.graph.nodes.get(node_id)
                        if node and self._matches_filter(node, source_filter):
                            results.append({
                                "node": node.to_dict(),
                                "delegatecall_count": count
                            })
            
        except Exception as e:
            # Return empty results for invalid patterns
            pass
        
        return results
    
    def _parse_node_filter(self, filter_str: str) -> Dict[str, str]:
        """Parse node filter like 'contract:Vault' or 'token:*'."""
        if ":" in filter_str:
            node_type, name = filter_str.split(":", 1)
            return {"type": node_type.strip(), "name": name.strip()}
        else:
            return {"name": filter_str.strip()}
    
    def _matches_filter(self, node: Optional[KGNode], filter_dict: Dict[str, str]) -> bool:
        """Check if node matches filter criteria."""
        if not node:
            return False
        
        if "type" in filter_dict:
            expected_type = filter_dict["type"].lower()
            actual_type = node.node_type.value.lower()
            if expected_type != actual_type:
                return False
        
        if "name" in filter_dict:
            expected_name = filter_dict["name"]
            if expected_name == "*":
                return True
            elif expected_name.lower() not in node.name.lower():
                return False
        
        return True


# Utility functions for knowledge graph CLI commands
def create_sample_kg_config() -> Dict[str, Any]:
    """Create sample knowledge graph configuration."""
    return {
        "enable": False,
        "max_nodes": 1000,
        "max_edges": 5000,
        "include_heuristic_relationships": True,
        "track_state_access": True,
        "track_external_calls": True
    }