"""
Contract relationship graph for holistic vulnerability analysis.
Enables understanding of cross-contract interactions and logic flows.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class RelationType(Enum):
    """Types of relationships between contracts."""
    INHERITANCE = "inheritance"
    COMPOSITION = "composition"
    DEPENDENCY = "dependency"
    INTERFACE = "interface"
    LIBRARY = "library"
    PROXY = "proxy"
    DELEGATE_CALL = "delegatecall"
    EXTERNAL_CALL = "external_call"
    TOKEN_INTERACTION = "token_interaction"
    ORACLE_DEPENDENCY = "oracle_dependency"


@dataclass
class ContractNode:
    """Represents a contract in the dependency graph."""
    name: str
    file_path: str
    source_code: str
    functions: List[str]
    state_variables: List[str]
    modifiers: List[str]
    events: List[str]
    interfaces: List[str]
    imports: List[str]
    is_abstract: bool = False
    is_interface: bool = False
    is_library: bool = False
    is_proxy: bool = False


@dataclass
class ContractRelation:
    """Represents a relationship between two contracts."""
    from_contract: str
    to_contract: str
    relation_type: RelationType
    details: Dict[str, Any]
    confidence: float = 1.0
    line_number: Optional[int] = None


class ContractGraphBuilder:
    """Builds a comprehensive graph of contract relationships."""

    def __init__(self):
        self.contracts: Dict[str, ContractNode] = {}
        self.relations: List[ContractRelation] = {}
        self.graph = None

        if HAS_NETWORKX:
            self.graph = nx.DiGraph()

    def analyze_project(self, contract_paths: List[Path]) -> 'ContractGraph':
        """
        Analyze all contracts in a project to build the relationship graph.

        Args:
            contract_paths: List of Solidity contract file paths

        Returns:
            Complete contract graph with relationships
        """
        # First pass: Parse all contracts and extract basic info
        for path in contract_paths:
            if path.suffix == '.sol':
                self._parse_contract_file(path)

        # Second pass: Analyze relationships between contracts
        self._analyze_relationships()

        # Third pass: Build the graph structure
        if HAS_NETWORKX:
            self._build_networkx_graph()

        return ContractGraph(
            contracts=self.contracts,
            relations=self.relations,
            graph=self.graph
        )

    def _parse_contract_file(self, file_path: Path) -> None:
        """Parse a single Solidity file and extract contract information."""
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return

        # Extract contract definitions
        contract_pattern = r'(abstract\s+)?contract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        interface_pattern = r'interface\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        library_pattern = r'library\s+(\w+)\s*\{'

        # Find contracts
        for match in re.finditer(contract_pattern, content, re.MULTILINE):
            is_abstract = match.group(1) is not None
            contract_name = match.group(2)
            inheritance = match.group(3) or ""

            node = self._create_contract_node(
                contract_name, file_path, content, inheritance, is_abstract
            )
            self.contracts[contract_name] = node

        # Find interfaces
        for match in re.finditer(interface_pattern, content, re.MULTILINE):
            interface_name = match.group(1)
            inheritance = match.group(2) or ""

            node = self._create_contract_node(
                interface_name, file_path, content, inheritance,
                is_interface=True
            )
            self.contracts[interface_name] = node

        # Find libraries
        for match in re.finditer(library_pattern, content, re.MULTILINE):
            library_name = match.group(1)

            node = self._create_contract_node(
                library_name, file_path, content, "", is_library=True
            )
            self.contracts[library_name] = node

    def _create_contract_node(
        self,
        name: str,
        file_path: Path,
        content: str,
        inheritance: str,
        is_abstract: bool = False,
        is_interface: bool = False,
        is_library: bool = False
    ) -> ContractNode:
        """Create a contract node with extracted information."""

        # Extract functions
        functions = self._extract_functions(content, name)

        # Extract state variables
        state_vars = self._extract_state_variables(content, name)

        # Extract modifiers
        modifiers = self._extract_modifiers(content, name)

        # Extract events
        events = self._extract_events(content, name)

        # Extract imports
        imports = self._extract_imports(content)

        # Extract interfaces
        interfaces = [iface.strip() for iface in inheritance.split(',') if iface.strip()]

        # Detect proxy patterns
        is_proxy = self._detect_proxy_pattern(content, name)

        return ContractNode(
            name=name,
            file_path=str(file_path),
            source_code=content,
            functions=functions,
            state_variables=state_vars,
            modifiers=modifiers,
            events=events,
            interfaces=interfaces,
            imports=imports,
            is_abstract=is_abstract,
            is_interface=is_interface,
            is_library=is_library,
            is_proxy=is_proxy
        )

    def _extract_functions(self, content: str, contract_name: str) -> List[str]:
        """Extract function names from contract."""
        # Find the contract block
        contract_start = content.find(f'contract {contract_name}')
        if contract_start == -1:
            return []

        # Find functions within the contract
        function_pattern = r'function\s+(\w+)\s*\('
        functions = []

        for match in re.finditer(function_pattern, content[contract_start:]):
            functions.append(match.group(1))

        return functions

    def _extract_state_variables(self, content: str, contract_name: str) -> List[str]:
        """Extract state variable names from contract."""
        # This is a simplified extraction - could be enhanced with proper parsing
        var_pattern = r'^\s*(?:mapping|address|uint\d*|int\d*|bool|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?(\w+)'
        variables = []

        for match in re.finditer(var_pattern, content, re.MULTILINE):
            variables.append(match.group(1))

        return variables

    def _extract_modifiers(self, content: str, contract_name: str) -> List[str]:
        """Extract modifier names from contract."""
        modifier_pattern = r'modifier\s+(\w+)\s*\('
        modifiers = []

        for match in re.finditer(modifier_pattern, content):
            modifiers.append(match.group(1))

        return modifiers

    def _extract_events(self, content: str, contract_name: str) -> List[str]:
        """Extract event names from contract."""
        event_pattern = r'event\s+(\w+)\s*\('
        events = []

        for match in re.finditer(event_pattern, content):
            events.append(match.group(1))

        return events

    def _extract_imports(self, content: str) -> List[str]:
        """Extract import statements from contract."""
        import_pattern = r'import\s+["\']([^"\']+)["\']'
        imports = []

        for match in re.finditer(import_pattern, content):
            imports.append(match.group(1))

        return imports

    def _detect_proxy_pattern(self, content: str, contract_name: str) -> bool:
        """Detect if contract follows proxy patterns."""
        proxy_indicators = [
            'delegatecall',
            'implementation',
            'upgrade',
            'proxy',
            '_delegate',
            'fallback',
            'receive'
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in proxy_indicators)

    def _analyze_relationships(self) -> None:
        """Analyze relationships between parsed contracts."""
        for contract_name, contract in self.contracts.items():
            self._analyze_inheritance_relations(contract)
            self._analyze_external_calls(contract)
            self._analyze_interface_relations(contract)
            self._analyze_library_usage(contract)
            self._analyze_delegate_calls(contract)

    def _analyze_inheritance_relations(self, contract: ContractNode) -> None:
        """Analyze inheritance relationships."""
        for interface in contract.interfaces:
            if interface in self.contracts:
                relation = ContractRelation(
                    from_contract=contract.name,
                    to_contract=interface,
                    relation_type=RelationType.INHERITANCE,
                    details={"inheritance_type": "is"},
                    confidence=1.0
                )
                self.relations.append(relation)

    def _analyze_external_calls(self, contract: ContractNode) -> None:
        """Analyze external contract calls."""
        # Look for contract.function() patterns
        call_pattern = r'(\w+)\.(\w+)\('

        for match in re.finditer(call_pattern, contract.source_code):
            target_contract = match.group(1)
            function_name = match.group(2)

            # Check if target is a known contract
            if target_contract in self.contracts:
                relation = ContractRelation(
                    from_contract=contract.name,
                    to_contract=target_contract,
                    relation_type=RelationType.EXTERNAL_CALL,
                    details={"function": function_name},
                    confidence=0.8
                )
                self.relations.append(relation)

    def _analyze_interface_relations(self, contract: ContractNode) -> None:
        """Analyze interface implementations."""
        for interface_name in contract.interfaces:
            if interface_name in self.contracts:
                target_contract = self.contracts[interface_name]
                if target_contract.is_interface:
                    relation = ContractRelation(
                        from_contract=contract.name,
                        to_contract=interface_name,
                        relation_type=RelationType.INTERFACE,
                        details={"implements": True},
                        confidence=1.0
                    )
                    self.relations.append(relation)

    def _analyze_library_usage(self, contract: ContractNode) -> None:
        """Analyze library usage patterns."""
        # Look for "using LibraryName for Type" patterns
        using_pattern = r'using\s+(\w+)\s+for'

        for match in re.finditer(using_pattern, contract.source_code):
            library_name = match.group(1)

            if library_name in self.contracts:
                relation = ContractRelation(
                    from_contract=contract.name,
                    to_contract=library_name,
                    relation_type=RelationType.LIBRARY,
                    details={"usage_type": "using_for"},
                    confidence=1.0
                )
                self.relations.append(relation)

    def _analyze_delegate_calls(self, contract: ContractNode) -> None:
        """Analyze delegatecall patterns."""
        if 'delegatecall' in contract.source_code.lower():
            # Try to identify target contracts for delegatecalls
            delegatecall_pattern = r'(\w+)\.delegatecall'

            for match in re.finditer(delegatecall_pattern, contract.source_code):
                target = match.group(1)

                relation = ContractRelation(
                    from_contract=contract.name,
                    to_contract=target,
                    relation_type=RelationType.DELEGATE_CALL,
                    details={"call_type": "delegatecall"},
                    confidence=0.7
                )
                self.relations.append(relation)

    def _build_networkx_graph(self) -> None:
        """Build NetworkX graph from contracts and relations."""
        if not HAS_NETWORKX:
            return

        # Add contract nodes
        for name, contract in self.contracts.items():
            self.graph.add_node(name, **{
                'file_path': contract.file_path,
                'is_abstract': contract.is_abstract,
                'is_interface': contract.is_interface,
                'is_library': contract.is_library,
                'is_proxy': contract.is_proxy,
                'function_count': len(contract.functions),
                'state_var_count': len(contract.state_variables)
            })

        # Add relationship edges
        for relation in self.relations:
            if (relation.from_contract in self.contracts and
                relation.to_contract in self.contracts):
                self.graph.add_edge(
                    relation.from_contract,
                    relation.to_contract,
                    relation_type=relation.relation_type.value,
                    confidence=relation.confidence,
                    details=relation.details
                )


@dataclass
class ContractGraph:
    """Complete contract relationship graph."""
    contracts: Dict[str, ContractNode]
    relations: List[ContractRelation]
    graph: Optional[Any] = None  # NetworkX graph if available

    def get_dependencies(self, contract_name: str) -> List[str]:
        """Get all contracts that this contract depends on."""
        dependencies = []
        for relation in self.relations:
            if relation.from_contract == contract_name:
                dependencies.append(relation.to_contract)
        return dependencies

    def get_dependents(self, contract_name: str) -> List[str]:
        """Get all contracts that depend on this contract."""
        dependents = []
        for relation in self.relations:
            if relation.to_contract == contract_name:
                dependents.append(relation.from_contract)
        return dependents

    def get_call_chain(self, from_contract: str, to_contract: str) -> List[str]:
        """Find call chain between two contracts."""
        if not HAS_NETWORKX or not self.graph:
            return []

        try:
            path = nx.shortest_path(self.graph, from_contract, to_contract)
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_critical_contracts(self) -> List[str]:
        """Identify critical contracts with many dependencies."""
        if not HAS_NETWORKX or not self.graph:
            # Fallback: count manual dependencies
            dependency_counts = {}
            for relation in self.relations:
                target = relation.to_contract
                dependency_counts[target] = dependency_counts.get(target, 0) + 1

            # Return contracts with most dependencies
            sorted_contracts = sorted(
                dependency_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return [name for name, count in sorted_contracts[:5]]

        # Use NetworkX centrality measures
        centrality = nx.betweenness_centrality(self.graph)
        sorted_contracts = sorted(
            centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return [name for name, score in sorted_contracts[:5]]

    def analyze_proxy_patterns(self) -> Dict[str, List[str]]:
        """Analyze proxy upgrade patterns."""
        proxy_analysis = {
            'proxy_contracts': [],
            'implementation_contracts': [],
            'potential_upgrade_paths': []
        }

        for name, contract in self.contracts.items():
            if contract.is_proxy:
                proxy_analysis['proxy_contracts'].append(name)

                # Find potential implementation contracts
                for relation in self.relations:
                    if (relation.from_contract == name and
                        relation.relation_type == RelationType.DELEGATE_CALL):
                        proxy_analysis['implementation_contracts'].append(
                            relation.to_contract
                        )

        return proxy_analysis

    def get_interaction_summary(self) -> Dict[str, Any]:
        """Get comprehensive interaction summary for LLM analysis."""
        summary = {
            'total_contracts': len(self.contracts),
            'total_relations': len(self.relations),
            'relation_types': {},
            'critical_contracts': self.get_critical_contracts(),
            'proxy_analysis': self.analyze_proxy_patterns(),
            'contract_categories': {
                'interfaces': [name for name, c in self.contracts.items() if c.is_interface],
                'libraries': [name for name, c in self.contracts.items() if c.is_library],
                'proxies': [name for name, c in self.contracts.items() if c.is_proxy],
                'abstract': [name for name, c in self.contracts.items() if c.is_abstract]
            }
        }

        # Count relation types
        for relation in self.relations:
            rel_type = relation.relation_type.value
            summary['relation_types'][rel_type] = summary['relation_types'].get(rel_type, 0) + 1

        return summary