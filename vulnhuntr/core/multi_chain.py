"""
Multi-Chain Context Layer (MCX) for Phase 6.

Handles chain metadata, bridge relationships, oracle feeds, and cross-domain
correlation for multi-chain vulnerability analysis.
"""
from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from pathlib import Path


@dataclass
class ChainMetadata:
    """Metadata for a blockchain network."""
    
    chain_id: int
    name: str
    rpc_urls: List[str] = field(default_factory=list)
    block_time_ms: int = 12000  # Average block time in milliseconds
    finality_blocks: int = 12   # Blocks for finality
    native_token: str = "ETH"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "rpc_urls": self.rpc_urls,
            "block_time_ms": self.block_time_ms,
            "finality_blocks": self.finality_blocks,
            "native_token": self.native_token
        }


@dataclass
class BridgeMetadata:
    """Metadata for cross-chain bridges."""
    
    name: str
    source_chain_id: int
    target_chain_id: int
    escrow_addresses: Dict[str, str] = field(default_factory=dict)  # chainId -> address
    token_mappings: List[Dict[str, Any]] = field(default_factory=list)
    delay_blocks: int = 0  # Additional delay for cross-chain transfers
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source_chain_id": self.source_chain_id,
            "target_chain_id": self.target_chain_id,
            "escrow_addresses": self.escrow_addresses,
            "token_mappings": self.token_mappings,
            "delay_blocks": self.delay_blocks
        }


@dataclass
class OracleMetadata:
    """Metadata for oracle feeds."""
    
    name: str
    feed_address: str
    chain_id: int
    asset_pair: str  # e.g., "ETH/USD"
    heartbeat_seconds: int = 3600
    deviation_threshold: float = 0.5  # Percentage threshold for price updates
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "feed_address": self.feed_address,
            "chain_id": self.chain_id,
            "asset_pair": self.asset_pair,
            "heartbeat_seconds": self.heartbeat_seconds,
            "deviation_threshold": self.deviation_threshold
        }


@dataclass
class CrossDomainPath:
    """Represents a cross-domain asset transfer path."""
    
    source_chain: int
    target_chain: int
    asset: str
    hop_count: int = 1
    bridge_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_chain": self.source_chain,
            "target_chain": self.target_chain,
            "asset": self.asset,
            "hop_count": self.hop_count,
            "bridge_name": self.bridge_name
        }


class AddressNormalizer:
    """Utility for normalizing addresses across chains."""
    
    @staticmethod
    def normalize_address(chain_id: int, address: str) -> str:
        """Normalize address to chainId:lowercaseHex format."""
        # Remove 0x prefix if present and convert to lowercase
        clean_address = address.lower()
        if clean_address.startswith('0x'):
            clean_address = clean_address[2:]
        
        return f"{chain_id}:{clean_address}"
    
    @staticmethod
    def parse_normalized_address(normalized: str) -> tuple[int, str]:
        """Parse normalized address back to chain_id and address."""
        chain_id_str, address = normalized.split(':', 1)
        return int(chain_id_str), f"0x{address}"


class MultiChainContextLoader:
    """Loads and manages multi-chain configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path("chains.yaml")
        self.chains: Dict[int, ChainMetadata] = {}
        self.bridges: List[BridgeMetadata] = []
        self.oracles: List[OracleMetadata] = []
        
    def load_config(self) -> bool:
        """Load multi-chain configuration from YAML file."""
        if not self.config_path.exists():
            return False
            
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            # Load chains
            for chain_data in config.get('chains', []):
                chain = ChainMetadata(
                    chain_id=chain_data['chain_id'],
                    name=chain_data['name'],
                    rpc_urls=chain_data.get('rpc_urls', []),
                    block_time_ms=chain_data.get('block_time_ms', 12000),
                    finality_blocks=chain_data.get('finality_blocks', 12),
                    native_token=chain_data.get('native_token', 'ETH')
                )
                self.chains[chain.chain_id] = chain
                
            # Load bridges
            for bridge_data in config.get('bridges', []):
                bridge = BridgeMetadata(
                    name=bridge_data['name'],
                    source_chain_id=bridge_data['source_chain_id'],
                    target_chain_id=bridge_data['target_chain_id'],
                    escrow_addresses=bridge_data.get('escrow_addresses', {}),
                    token_mappings=bridge_data.get('token_mappings', []),
                    delay_blocks=bridge_data.get('delay_blocks', 0)
                )
                self.bridges.append(bridge)
                
            # Load oracles
            for oracle_data in config.get('oracles', []):
                oracle = OracleMetadata(
                    name=oracle_data['name'],
                    feed_address=oracle_data['feed_address'],
                    chain_id=oracle_data['chain_id'],
                    asset_pair=oracle_data['asset_pair'],
                    heartbeat_seconds=oracle_data.get('heartbeat_seconds', 3600),
                    deviation_threshold=oracle_data.get('deviation_threshold', 0.5)
                )
                self.oracles.append(oracle)
                
            return True
            
        except Exception as e:
            print(f"Warning: Failed to load multi-chain config: {e}")
            return False
    
    def get_cross_domain_paths(self, source_address: str, target_chain_id: int) -> List[CrossDomainPath]:
        """Find potential cross-domain paths for an asset."""
        paths = []
        
        # Simple implementation: find direct bridges
        for bridge in self.bridges:
            if bridge.target_chain_id == target_chain_id:
                for token_mapping in bridge.token_mappings:
                    if token_mapping.get('source_address', '').lower() == source_address.lower():
                        path = CrossDomainPath(
                            source_chain=bridge.source_chain_id,
                            target_chain=bridge.target_chain_id,
                            asset=token_mapping.get('symbol', 'UNKNOWN'),
                            hop_count=1,
                            bridge_name=bridge.name
                        )
                        paths.append(path)
        
        return paths
    
    def create_sample_config(self) -> None:
        """Create a sample chains.yaml configuration file."""
        sample_config = {
            'chains': [
                {
                    'chain_id': 1,
                    'name': 'Ethereum Mainnet',
                    'rpc_urls': ['https://mainnet.infura.io/v3/YOUR_KEY'],
                    'block_time_ms': 12000,
                    'finality_blocks': 12,
                    'native_token': 'ETH'
                },
                {
                    'chain_id': 137,
                    'name': 'Polygon',
                    'rpc_urls': ['https://polygon-rpc.com'],
                    'block_time_ms': 2000,
                    'finality_blocks': 128,
                    'native_token': 'MATIC'
                }
            ],
            'bridges': [
                {
                    'name': 'Polygon PoS Bridge',
                    'source_chain_id': 1,
                    'target_chain_id': 137,
                    'escrow_addresses': {
                        '1': '0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf',
                        '137': '0x0000000000000000000000000000000000001001'
                    },
                    'token_mappings': [
                        {
                            'symbol': 'USDT',
                            'source_address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                            'target_address': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F'
                        }
                    ],
                    'delay_blocks': 256
                }
            ],
            'oracles': [
                {
                    'name': 'Chainlink ETH/USD',
                    'feed_address': '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419',
                    'chain_id': 1,
                    'asset_pair': 'ETH/USD',
                    'heartbeat_seconds': 3600,
                    'deviation_threshold': 0.5
                }
            ]
        }
        
        with open(self.config_path, 'w') as f:
            yaml.dump(sample_config, f, default_flow_style=False, indent=2)


class MultiChainCorrelator:
    """Correlates findings across multiple chains."""
    
    def __init__(self, context_loader: MultiChainContextLoader):
        self.context_loader = context_loader
        
    def enhance_finding_with_multichain_context(self, finding: Any, contract_address: str, chain_id: int) -> Dict[str, Any]:
        """Enhance a finding with multi-chain context."""
        multi_chain_data = {
            "chains": [chain_id],
            "cross_domain_paths": []
        }
        
        # Find potential cross-domain paths
        for target_chain_id in self.context_loader.chains.keys():
            if target_chain_id != chain_id:
                paths = self.context_loader.get_cross_domain_paths(contract_address, target_chain_id)
                multi_chain_data["cross_domain_paths"].extend([path.to_dict() for path in paths])
        
        return multi_chain_data
    
    def correlate_cross_chain_findings(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Correlate findings that may be related across chains."""
        correlations = []
        
        # Group findings by similar patterns across chains
        pattern_groups: Dict[str, List[Any]] = {}
        
        for finding in findings:
            # Create a pattern key based on finding characteristics
            pattern_key = f"{finding.detector}_{finding.category}"
            if pattern_key not in pattern_groups:
                pattern_groups[pattern_key] = []
            pattern_groups[pattern_key].append(finding)
        
        # Create correlations for multi-chain patterns
        for pattern_key, group_findings in pattern_groups.items():
            if len(group_findings) > 1:
                # Check if findings span multiple chains
                chain_ids = set()
                for finding in group_findings:
                    if finding.multi_chain and finding.multi_chain.get("chains"):
                        chain_ids.update(finding.multi_chain["chains"])
                
                if len(chain_ids) > 1:
                    correlation = {
                        "type": "cross_chain_pattern",
                        "pattern": pattern_key,
                        "chains_involved": list(chain_ids),
                        "findings": [f.to_dict() for f in group_findings],
                        "risk_multiplier": 1.2  # Cross-chain risks are elevated
                    }
                    correlations.append(correlation)
        
        return correlations