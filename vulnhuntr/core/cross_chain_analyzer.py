"""
Cross-chain security analysis for Web3 contracts.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

from ..core.models import Contract


class ChainType(Enum):
    """Supported blockchain types."""
    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    FANTOM = "fantom"
    SOLANA = "solana"
    UNKNOWN = "unknown"


@dataclass
class ChainInfo:
    """Blockchain network information."""
    chain_id: int
    name: str
    type: ChainType
    native_token: str
    block_time: float  # seconds
    finality_time: float  # seconds for finality
    has_evm: bool
    bridge_protocols: List[str]
    oracle_providers: List[str]


@dataclass
class CrossChainRisk:
    """Cross-chain security risk assessment."""
    risk_type: str
    description: str
    affected_chains: List[str]
    severity: str
    mitigation: str
    bridge_related: bool
    oracle_related: bool


class CrossChainAnalyzer:
    """
    Analyzes smart contracts for cross-chain deployment risks and vulnerabilities.
    """

    # Oracle provider constants
    CHAINLINK = "Chainlink"
    BAND_PROTOCOL = "Band Protocol"
    UMBRELLA = "Umbrella"
    
    # Bridge protocol constants
    PORTAL = "Portal"
    POLYGON_POS = "Polygon PoS"
    ARBITRUM_BRIDGE = "Arbitrum Bridge"
    BSC_BRIDGE = "BSC Bridge"
    AVALANCHE_BRIDGE = "Avalanche Bridge"
    OPTIMISM_BRIDGE = "Optimism Bridge"

    # Chain configurations
    CHAIN_CONFIGS = {
        1: ChainInfo(1, "Ethereum", ChainType.ETHEREUM, "ETH", 12.0, 78.0, True, 
                    [PORTAL, POLYGON_POS, ARBITRUM_BRIDGE], [CHAINLINK, BAND_PROTOCOL]),
        137: ChainInfo(137, "Polygon", ChainType.POLYGON, "MATIC", 2.0, 4.0, True,
                      [POLYGON_POS, PORTAL], [CHAINLINK, BAND_PROTOCOL, UMBRELLA]),
        56: ChainInfo(56, "BSC", ChainType.BSC, "BNB", 3.0, 15.0, True,
                     [BSC_BRIDGE, PORTAL], [CHAINLINK, BAND_PROTOCOL]),
        43114: ChainInfo(43114, "Avalanche", ChainType.AVALANCHE, "AVAX", 1.0, 2.0, True,
                        [AVALANCHE_BRIDGE, PORTAL], [CHAINLINK, BAND_PROTOCOL]),
        42161: ChainInfo(42161, "Arbitrum One", ChainType.ARBITRUM, "ETH", 0.25, 12.0, True,
                        [ARBITRUM_BRIDGE], [CHAINLINK]),
        10: ChainInfo(10, "Optimism", ChainType.OPTIMISM, "ETH", 2.0, 12.0, True,
                     [OPTIMISM_BRIDGE], [CHAINLINK]),
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_cross_chain_deployment(self, contracts: List[Contract], 
                                     target_chains: List[int]) -> List[CrossChainRisk]:
        """
        Analyze contracts for cross-chain deployment risks.
        
        Args:
            contracts: List of contracts to analyze
            target_chains: List of chain IDs for deployment
            
        Returns:
            List of identified cross-chain risks
        """
        risks = []
        
        # Analyze each target chain combination
        for i, chain_a in enumerate(target_chains):
            for chain_b in target_chains[i+1:]:
                risks.extend(self._analyze_chain_pair(chain_a, chain_b))
        
        # Analyze bridge-specific risks
        risks.extend(self._analyze_bridge_risks(contracts, target_chains))
        
        # Analyze oracle risks across chains
        risks.extend(self._analyze_oracle_cross_chain_risks(contracts, target_chains))
        
        return risks

    def _analyze_chain_pair(self, chain_a: int, chain_b: int) -> List[CrossChainRisk]:
        """
        Analyze risks between two specific chains.
        """
        risks = []
        
        config_a = self.CHAIN_CONFIGS.get(chain_a)
        config_b = self.CHAIN_CONFIGS.get(chain_b)
        
        if not config_a or not config_b:
            return risks

        # Finality time differences
        if abs(config_a.finality_time - config_b.finality_time) > 60:
            risks.append(CrossChainRisk(
                risk_type="finality_mismatch",
                description=f"Significant finality time difference between {config_a.name} ({config_a.finality_time}s) and {config_b.name} ({config_b.finality_time}s)",
                affected_chains=[config_a.name, config_b.name],
                severity="MEDIUM",
                mitigation="Implement time-based delays for cross-chain operations",
                bridge_related=True,
                oracle_related=False
            ))

        # Block time differences (affects oracle updates)
        if abs(config_a.block_time - config_b.block_time) > 10:
            risks.append(CrossChainRisk(
                risk_type="block_time_mismatch",
                description=f"Block time difference may cause oracle update delays between {config_a.name} and {config_b.name}",
                affected_chains=[config_a.name, config_b.name],
                severity="LOW",
                mitigation="Use time-weighted average prices (TWAP) across chains",
                bridge_related=False,
                oracle_related=True
            ))

        # Oracle provider differences
        common_oracles = set(config_a.oracle_providers) & set(config_b.oracle_providers)
        if len(common_oracles) < 2:
            risks.append(CrossChainRisk(
                risk_type="oracle_provider_mismatch",
                description=f"Limited common oracle providers between {config_a.name} and {config_b.name}",
                affected_chains=[config_a.name, config_b.name],
                severity="HIGH",
                mitigation="Ensure multiple shared oracle providers or implement cross-chain oracle validation",
                bridge_related=False,
                oracle_related=True
            ))

        return risks

    def _analyze_bridge_risks(self, contracts: List[Contract], target_chains: List[int]) -> List[CrossChainRisk]:
        """
        Analyze bridge-specific security risks.
        """
        risks = []
        
        # Check for bridge-related contracts
        bridge_contracts = [c for c in contracts if self._is_bridge_contract(c)]
        
        for contract in bridge_contracts:
            # Centralized bridge risk
            risks.append(CrossChainRisk(
                risk_type="centralized_bridge_risk",
                description=f"Contract {contract.name} may rely on centralized bridge infrastructure",
                affected_chains=[self.CHAIN_CONFIGS.get(cid, ChainInfo(cid, f"Chain-{cid}", ChainType.UNKNOWN, "UNK", 0, 0, True, [], [])).name 
                               for cid in target_chains],
                severity="HIGH",
                mitigation="Implement multi-signature validation and decentralized bridge protocols",
                bridge_related=True,
                oracle_related=False
            ))

            # Bridge token minting risks
            if self._has_token_minting(contract):
                risks.append(CrossChainRisk(
                    risk_type="cross_chain_token_minting",
                    description=f"Contract {contract.name} has token minting capabilities across chains",
                    affected_chains=[self.CHAIN_CONFIGS.get(cid, ChainInfo(cid, f"Chain-{cid}", ChainType.UNKNOWN, "UNK", 0, 0, True, [], [])).name 
                                   for cid in target_chains],
                    severity="CRITICAL",
                    mitigation="Implement strict minting controls and cross-chain supply validation",
                    bridge_related=True,
                    oracle_related=False
                ))

        return risks

    def _analyze_oracle_cross_chain_risks(self, contracts: List[Contract], target_chains: List[int]) -> List[CrossChainRisk]:
        """
        Analyze oracle-related cross-chain risks.
        """
        risks = []
        
        oracle_contracts = [c for c in contracts if self._uses_oracle_data(c)]
        
        if oracle_contracts:
            # Cross-chain price manipulation
            risks.append(CrossChainRisk(
                risk_type="cross_chain_price_manipulation",
                description="Oracle price differences across chains enable arbitrage attacks",
                affected_chains=[self.CHAIN_CONFIGS.get(cid, ChainInfo(cid, f"Chain-{cid}", ChainType.UNKNOWN, "UNK", 0, 0, True, [], [])).name 
                               for cid in target_chains],
                severity="HIGH",
                mitigation="Implement cross-chain price validation and maximum deviation limits",
                bridge_related=False,
                oracle_related=True
            ))

            # Oracle availability differences
            risks.append(CrossChainRisk(
                risk_type="oracle_availability_mismatch",
                description="Oracle availability may differ across target chains",
                affected_chains=[self.CHAIN_CONFIGS.get(cid, ChainInfo(cid, f"Chain-{cid}", ChainType.UNKNOWN, "UNK", 0, 0, True, [], [])).name 
                               for cid in target_chains],
                severity="MEDIUM",
                mitigation="Implement fallback oracle mechanisms and circuit breakers",
                bridge_related=False,
                oracle_related=True
            ))

        return risks

    def _is_bridge_contract(self, contract: Contract) -> bool:
        """
        Check if contract is bridge-related.
        """
        bridge_indicators = ['bridge', 'portal', 'tunnel', 'relay', 'cross']
        contract_name_lower = contract.name.lower()
        return any(indicator in contract_name_lower for indicator in bridge_indicators)

    def _has_token_minting(self, contract: Contract) -> bool:
        """
        Check if contract has token minting capabilities.
        """
        # This would need more sophisticated analysis in practice
        mint_indicators = ['mint', 'issue', 'create', 'generate']
        contract_name_lower = contract.name.lower()
        return any(indicator in contract_name_lower for indicator in mint_indicators)

    def _uses_oracle_data(self, contract: Contract) -> bool:
        """
        Check if contract uses oracle data.
        """
        oracle_indicators = ['oracle', 'price', 'feed', 'chainlink', 'band']
        contract_name_lower = contract.name.lower()
        return any(indicator in contract_name_lower for indicator in oracle_indicators)

    def generate_chain_compatibility_report(self, contracts: List[Contract], 
                                          target_chains: List[int]) -> Dict[str, Any]:
        """
        Generate comprehensive chain compatibility report.
        """
        risks = self.analyze_cross_chain_deployment(contracts, target_chains)
        
        # Categorize risks by severity
        critical_risks = [r for r in risks if r.severity == "CRITICAL"]
        high_risks = [r for r in risks if r.severity == "HIGH"]
        medium_risks = [r for r in risks if r.severity == "MEDIUM"]
        low_risks = [r for r in risks if r.severity == "LOW"]

        # Chain-specific statistics
        chain_stats = {}
        for chain_id in target_chains:
            config = self.CHAIN_CONFIGS.get(chain_id)
            if config:
                chain_stats[config.name] = {
                    "finality_time": config.finality_time,
                    "block_time": config.block_time,
                    "oracle_providers": config.oracle_providers,
                    "bridge_protocols": config.bridge_protocols
                }

        return {
            "summary": {
                "total_risks": len(risks),
                "critical_risks": len(critical_risks),
                "high_risks": len(high_risks),
                "medium_risks": len(medium_risks),
                "low_risks": len(low_risks),
                "target_chains": len(target_chains)
            },
            "chain_statistics": chain_stats,
            "risk_categories": {
                "bridge_related": len([r for r in risks if r.bridge_related]),
                "oracle_related": len([r for r in risks if r.oracle_related]),
                "finality_related": len([r for r in risks if "finality" in r.risk_type]),
                "timing_related": len([r for r in risks if "time" in r.risk_type])
            },
            "recommendations": {
                "immediate_action": [r.mitigation for r in critical_risks],
                "high_priority": [r.mitigation for r in high_risks],
                "monitoring_required": [r.mitigation for r in medium_risks + low_risks]
            },
            "detailed_risks": [
                {
                    "type": r.risk_type,
                    "description": r.description,
                    "severity": r.severity,
                    "affected_chains": r.affected_chains,
                    "mitigation": r.mitigation,
                    "categories": {
                        "bridge_related": r.bridge_related,
                        "oracle_related": r.oracle_related
                    }
                }
                for r in risks
            ]
        }