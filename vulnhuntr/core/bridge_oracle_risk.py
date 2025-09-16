"""
Bridge & Oracle Risk Correlator (BRI) for Phase 6.

Analyzes patterns for finality delays, oracle heartbeat divergence,
and timing window vulnerabilities in cross-chain systems.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
from .multi_chain import ChainMetadata, BridgeMetadata, OracleMetadata


@dataclass
class TimingWindow:
    """Represents a timing vulnerability window."""
    
    window_blocks: int
    window_seconds: int
    risk_level: str  # "low", "medium", "high"
    description: str
    affected_operations: List[str] = field(default_factory=list)


@dataclass
class BridgeRiskPattern:
    """Risk pattern for bridge operations."""
    
    pattern_type: str  # "finality_delay", "oracle_divergence", "timing_window"
    bridge_name: str
    source_chain_id: int
    target_chain_id: int
    risk_score: float
    timing_window: Optional[TimingWindow] = None
    mitigation_suggestions: List[str] = field(default_factory=list)


@dataclass 
class OracleRiskPattern:
    """Risk pattern for oracle feeds."""
    
    pattern_type: str  # "heartbeat_delay", "price_divergence", "stale_data"
    oracle_name: str
    feed_address: str
    chain_id: int
    risk_score: float
    last_update_delay: Optional[int] = None  # seconds
    price_deviation: Optional[float] = None  # percentage
    mitigation_suggestions: List[str] = field(default_factory=list)


class BridgeRiskAnalyzer:
    """Analyzes bridge-specific risks."""
    
    def __init__(self, chains: Dict[int, ChainMetadata], bridges: List[BridgeMetadata]):
        self.chains = chains
        self.bridges = bridges
    
    def analyze_finality_delays(self, bridge: BridgeMetadata) -> BridgeRiskPattern:
        """Analyze finality delay patterns for a bridge."""
        source_chain = self.chains.get(bridge.source_chain_id)
        target_chain = self.chains.get(bridge.target_chain_id)
        
        if not source_chain or not target_chain:
            return BridgeRiskPattern(
                pattern_type="finality_delay",
                bridge_name=bridge.name,
                source_chain_id=bridge.source_chain_id,
                target_chain_id=bridge.target_chain_id,
                risk_score=0.0
            )
        
        # Calculate total finality window
        source_finality_time = source_chain.finality_blocks * source_chain.block_time_ms / 1000
        target_finality_time = target_chain.finality_blocks * target_chain.block_time_ms / 1000
        bridge_delay_time = bridge.delay_blocks * source_chain.block_time_ms / 1000
        
        total_delay = source_finality_time + target_finality_time + bridge_delay_time
        total_blocks = (bridge.delay_blocks + 
                       source_chain.finality_blocks + 
                       target_chain.finality_blocks)
        
        # Risk scoring based on delay duration
        if total_delay > 3600:  # > 1 hour
            risk_level = "high"
            risk_score = 0.8
        elif total_delay > 900:  # > 15 minutes
            risk_level = "medium"
            risk_score = 0.5
        else:
            risk_level = "low"
            risk_score = 0.2
        
        timing_window = TimingWindow(
            window_blocks=total_blocks,
            window_seconds=int(total_delay),
            risk_level=risk_level,
            description=f"Cross-chain finality window of {total_delay:.0f}s creates MEV/arbitrage opportunities",
            affected_operations=["cross_chain_transfers", "bridge_withdrawals", "oracle_updates"]
        )
        
        mitigations = [
            "Implement time-lock mechanisms for large transfers",
            "Use multiple oracles for price validation during bridge operations",
            "Consider batching operations to reduce individual exposure"
        ]
        
        return BridgeRiskPattern(
            pattern_type="finality_delay",
            bridge_name=bridge.name,
            source_chain_id=bridge.source_chain_id,
            target_chain_id=bridge.target_chain_id,
            risk_score=risk_score,
            timing_window=timing_window,
            mitigation_suggestions=mitigations
        )
    
    def analyze_all_bridges(self) -> List[BridgeRiskPattern]:
        """Analyze all configured bridges for risk patterns."""
        patterns = []
        
        for bridge in self.bridges:
            finality_pattern = self.analyze_finality_delays(bridge)
            patterns.append(finality_pattern)
        
        return patterns


class OracleRiskAnalyzer:
    """Analyzes oracle-specific risks."""
    
    def __init__(self, oracles: List[OracleMetadata]):
        self.oracles = oracles
    
    def analyze_heartbeat_risks(self, oracle: OracleMetadata) -> OracleRiskPattern:
        """Analyze heartbeat delay risks for an oracle."""
        # In a real implementation, this would query the actual oracle
        # For now, we use heuristic risk assessment based on configuration
        
        # Risk scoring based on heartbeat frequency
        if oracle.heartbeat_seconds > 7200:  # > 2 hours
            risk_score = 0.8
            risk_level = "high"
        elif oracle.heartbeat_seconds > 3600:  # > 1 hour
            risk_score = 0.5
            risk_level = "medium"
        else:
            risk_score = 0.2
            risk_level = "low"
        
        mitigations = [
            f"Monitor {oracle.name} feed for delays exceeding {oracle.heartbeat_seconds}s",
            "Implement fallback oracle sources",
            "Add circuit breakers for stale price data"
        ]
        
        return OracleRiskPattern(
            pattern_type="heartbeat_delay",
            oracle_name=oracle.name,
            feed_address=oracle.feed_address,
            chain_id=oracle.chain_id,
            risk_score=risk_score,
            mitigation_suggestions=mitigations
        )
    
    def analyze_price_divergence(self, oracle: OracleMetadata) -> OracleRiskPattern:
        """Analyze price divergence risks for an oracle."""
        # Risk based on deviation threshold
        if oracle.deviation_threshold > 2.0:  # > 2%
            risk_score = 0.3
        elif oracle.deviation_threshold > 1.0:  # > 1%
            risk_score = 0.5
        else:
            risk_score = 0.7  # Lower threshold = higher sensitivity = higher risk of manipulation
        
        mitigations = [
            f"Validate {oracle.asset_pair} prices against multiple sources",
            f"Alert on price movements > {oracle.deviation_threshold}%",
            "Implement TWAP (Time-Weighted Average Price) mechanisms"
        ]
        
        return OracleRiskPattern(
            pattern_type="price_divergence",
            oracle_name=oracle.name,
            feed_address=oracle.feed_address,
            chain_id=oracle.chain_id,
            risk_score=risk_score,
            price_deviation=oracle.deviation_threshold,
            mitigation_suggestions=mitigations
        )
    
    def analyze_all_oracles(self) -> List[OracleRiskPattern]:
        """Analyze all configured oracles for risk patterns."""
        patterns = []
        
        for oracle in self.oracles:
            heartbeat_pattern = self.analyze_heartbeat_risks(oracle)
            divergence_pattern = self.analyze_price_divergence(oracle)
            patterns.extend([heartbeat_pattern, divergence_pattern])
        
        return patterns


class BridgeOracleCorrelator:
    """Main correlator combining bridge and oracle risk analysis."""
    
    def __init__(self, chains: Dict[int, ChainMetadata], 
                 bridges: List[BridgeMetadata], 
                 oracles: List[OracleMetadata]):
        self.bridge_analyzer = BridgeRiskAnalyzer(chains, bridges)
        self.oracle_analyzer = OracleRiskAnalyzer(oracles)
        self.chains = chains
    
    def analyze_timing_windows(self) -> List[Dict[str, Any]]:
        """Analyze timing windows across bridges and oracles."""
        bridge_patterns = self.bridge_analyzer.analyze_all_bridges()
        oracle_patterns = self.oracle_analyzer.analyze_all_oracles()
        
        timing_analysis = []
        
        # Correlate bridge timing windows with oracle update frequencies
        for bridge_pattern in bridge_patterns:
            if bridge_pattern.timing_window:
                # Find oracles on the same chains
                relevant_oracles = [
                    op for op in oracle_patterns 
                    if op.chain_id in [bridge_pattern.source_chain_id, bridge_pattern.target_chain_id]
                ]
                
                window_analysis = {
                    "bridge_pattern": {
                        "name": bridge_pattern.bridge_name,
                        "timing_window_blocks": bridge_pattern.timing_window.window_blocks,
                        "timing_window_seconds": bridge_pattern.timing_window.window_seconds,
                        "risk_score": bridge_pattern.risk_score,
                        "risk_level": bridge_pattern.timing_window.risk_level
                    },
                    "related_oracles": [
                        {
                            "name": op.oracle_name,
                            "heartbeat_seconds": getattr(op, 'last_update_delay', 0),
                            "risk_score": op.risk_score,
                            "chain_id": op.chain_id
                        }
                        for op in relevant_oracles
                    ],
                    "composite_risk": self._calculate_composite_risk(bridge_pattern, relevant_oracles),
                    "recommendations": self._generate_timing_recommendations(bridge_pattern, relevant_oracles)
                }
                
                timing_analysis.append(window_analysis)
        
        return timing_analysis
    
    def _calculate_composite_risk(self, bridge_pattern: BridgeRiskPattern, 
                                oracle_patterns: List[OracleRiskPattern]) -> float:
        """Calculate composite risk score combining bridge and oracle risks."""
        bridge_risk = bridge_pattern.risk_score
        
        if not oracle_patterns:
            return bridge_risk
        
        # Average oracle risk
        oracle_risk = sum(op.risk_score for op in oracle_patterns) / len(oracle_patterns)
        
        # Weighted combination (bridge risk is primary)
        composite = 0.7 * bridge_risk + 0.3 * oracle_risk
        
        # Boost risk if timing windows align poorly with oracle updates
        if bridge_pattern.timing_window:
            window_seconds = bridge_pattern.timing_window.window_seconds
            for op in oracle_patterns:
                # Check for oracle patterns where heartbeat might fall within bridge window
                if hasattr(op, 'last_update_delay') and op.last_update_delay:
                    if window_seconds > op.last_update_delay * 0.5:  # Window > half heartbeat
                        composite = min(1.0, composite + 0.1)  # Small boost
        
        return round(composite, 3)
    
    def _generate_timing_recommendations(self, bridge_pattern: BridgeRiskPattern,
                                       oracle_patterns: List[OracleRiskPattern]) -> List[str]:
        """Generate recommendations for timing-related risks."""
        recommendations = []
        
        # Bridge-specific recommendations
        recommendations.extend(bridge_pattern.mitigation_suggestions)
        
        # Oracle-specific recommendations
        for op in oracle_patterns:
            recommendations.extend(op.mitigation_suggestions)
        
        # Composite recommendations
        if bridge_pattern.timing_window and bridge_pattern.timing_window.window_seconds > 1800:
            recommendations.append("Consider implementing gradual release mechanisms for large cross-chain transfers")
        
        if len(oracle_patterns) > 1:
            recommendations.append("Implement oracle consensus mechanisms for critical price feeds during cross-chain operations")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def generate_correlation_report(self) -> Dict[str, Any]:
        """Generate comprehensive bridge-oracle correlation report."""
        bridge_patterns = self.bridge_analyzer.analyze_all_bridges()
        oracle_patterns = self.oracle_analyzer.analyze_all_oracles()
        timing_analysis = self.analyze_timing_windows()
        
        report = {
            "summary": {
                "bridges_analyzed": len(bridge_patterns),
                "oracles_analyzed": len(oracle_patterns) // 2,  # Each oracle generates 2 patterns
                "timing_windows_identified": len(timing_analysis),
                "high_risk_patterns": len([p for p in bridge_patterns + oracle_patterns if p.risk_score > 0.7])
            },
            "bridge_patterns": [
                {
                    "bridge_name": p.bridge_name,
                    "pattern_type": p.pattern_type,
                    "risk_score": p.risk_score,
                    "timing_window_blocks": p.timing_window.window_blocks if p.timing_window else None,
                    "source_chain": p.source_chain_id,
                    "target_chain": p.target_chain_id
                }
                for p in bridge_patterns
            ],
            "oracle_patterns": [
                {
                    "oracle_name": p.oracle_name,
                    "pattern_type": p.pattern_type,
                    "risk_score": p.risk_score,
                    "chain_id": p.chain_id,
                    "feed_address": p.feed_address
                }
                for p in oracle_patterns
            ],
            "timing_analysis": timing_analysis,
            "recommendations": {
                "high_priority": [
                    rec for analysis in timing_analysis 
                    if analysis["composite_risk"] > 0.7
                    for rec in analysis["recommendations"]
                ],
                "general": [
                    "Monitor cross-chain timing windows during high volatility periods",
                    "Implement automated alerting for oracle heartbeat delays",
                    "Regular review of bridge delay parameters"
                ]
            }
        }
        
        return report