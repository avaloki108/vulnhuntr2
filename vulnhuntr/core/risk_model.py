"""
Risk Model (RSK) for Phase 6.

Preliminary risk probability model with p_exploit calculation,
expected_loss_estimate with valuation maps, and CSV export utilities.
"""
from __future__ import annotations

import csv
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import json

from .models import Finding, Severity


@dataclass
class RiskFactors:
    """Risk factors for exploit probability calculation."""
    
    reachability: float = 0.5      # Code reachability score (0.0-1.0)
    invariant_violation: float = 0.0  # Invariant violation weight (0.0-1.0)
    economic_feasibility: float = 0.0  # Economic feasibility factor (0.0-1.0)
    consensus_alignment: float = 1.0   # Multi-model consensus alignment (0.0-1.0)
    
    # Additional factors
    complexity: float = 0.5        # Attack complexity (0.0=easy, 1.0=hard)
    public_exposure: float = 0.5   # Public function exposure (0.0-1.0)
    privilege_escalation: float = 0.0  # Privilege escalation potential (0.0-1.0)
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "reachability": self.reachability,
            "invariant_violation": self.invariant_violation,
            "economic_feasibility": self.economic_feasibility,
            "consensus_alignment": self.consensus_alignment,
            "complexity": self.complexity,
            "public_exposure": self.public_exposure,
            "privilege_escalation": self.privilege_escalation
        }


@dataclass
class RiskCoefficients:
    """Tunable coefficients for risk calculation."""
    
    reachability: float = 1.1
    invariant: float = 1.3
    economic: float = 0.9
    consensus: float = 0.4
    
    # Additional coefficients
    complexity: float = -0.8      # Negative: higher complexity reduces risk
    exposure: float = 0.6
    privilege: float = 1.2
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "reachability": self.reachability,
            "invariant": self.invariant,
            "economic": self.economic,
            "consensus": self.consensus,
            "complexity": self.complexity,
            "exposure": self.exposure,
            "privilege": self.privilege
        }


@dataclass
class AssetValuation:
    """Asset valuation for economic loss estimation."""
    
    symbol: str
    address: Optional[str] = None
    usd_value: float = 0.0
    decimals: int = 18
    total_supply: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "address": self.address,
            "usd_value": self.usd_value,
            "decimals": self.decimals,
            "total_supply": self.total_supply
        }


@dataclass
class RiskAssessment:
    """Complete risk assessment for a finding."""
    
    finding_id: str
    p_exploit: float  # Probability of successful exploit (0.0-1.0)
    expected_loss_estimate: Union[float, str]  # USD value or "unknown"
    modeling_version: str = "1.0"
    
    # Supporting data
    risk_factors: RiskFactors = field(default_factory=RiskFactors)
    coefficients: RiskCoefficients = field(default_factory=RiskCoefficients)
    confidence: float = 0.5  # Confidence in the assessment (0.0-1.0)
    
    # Asset context
    affected_assets: List[AssetValuation] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "p_exploit": self.p_exploit,
            "expected_loss_estimate": self.expected_loss_estimate,
            "modeling_version": self.modeling_version,
            "risk_factors": self.risk_factors.to_dict(),
            "coefficients": self.coefficients.to_dict(),
            "confidence": self.confidence,
            "affected_assets": [asset.to_dict() for asset in self.affected_assets]
        }


class ValuationMapLoader:
    """Loads asset valuation mappings from file."""
    
    def __init__(self, valuation_file: Optional[Path] = None):
        self.valuation_file = valuation_file or Path("valuations.json")
        self.valuations: Dict[str, AssetValuation] = {}
        
        if self.valuation_file.exists():
            self._load_valuations()
    
    def _load_valuations(self) -> None:
        """Load valuations from file."""
        try:
            with open(self.valuation_file, 'r') as f:
                data = json.load(f)
            
            for asset_data in data.get("assets", []):
                valuation = AssetValuation(
                    symbol=asset_data["symbol"],
                    address=asset_data.get("address"),
                    usd_value=asset_data.get("usd_value", 0.0),
                    decimals=asset_data.get("decimals", 18),
                    total_supply=asset_data.get("total_supply")
                )
                
                # Index by both symbol and address
                self.valuations[valuation.symbol.upper()] = valuation
                if valuation.address:
                    self.valuations[valuation.address.lower()] = valuation
                    
        except Exception as e:
            print(f"Warning: Failed to load valuation map: {e}")
    
    def get_valuation(self, identifier: str) -> Optional[AssetValuation]:
        """Get valuation by symbol or address."""
        # Try both uppercase symbol and lowercase address
        return (self.valuations.get(identifier.upper()) or 
                self.valuations.get(identifier.lower()))
    
    def create_sample_valuation_file(self) -> None:
        """Create a sample valuations.json file."""
        sample_data = {
            "version": "1.0",
            "updated": "2024-01-01T00:00:00Z",
            "assets": [
                {
                    "symbol": "ETH",
                    "address": "0x0000000000000000000000000000000000000000",
                    "usd_value": 3000.0,
                    "decimals": 18,
                    "total_supply": 120000000.0
                },
                {
                    "symbol": "USDT",
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "usd_value": 1.0,
                    "decimals": 6,
                    "total_supply": 70000000000.0
                },
                {
                    "symbol": "USDC",
                    "address": "0xa0b86a33e6441c7c1d7efa8ef77e04f0e0e8e7c6",
                    "usd_value": 1.0,
                    "decimals": 6,
                    "total_supply": 50000000000.0
                },
                {
                    "symbol": "WBTC",
                    "address": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                    "usd_value": 65000.0,
                    "decimals": 8,
                    "total_supply": 165000.0
                }
            ]
        }
        
        with open(self.valuation_file, 'w') as f:
            json.dump(sample_data, f, indent=2)


class RiskFactorExtractor:
    """Extracts risk factors from findings and context."""
    
    def __init__(self):
        self.severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
    
    def extract_factors(self, finding: Finding, 
                       context: Optional[Dict[str, Any]] = None) -> RiskFactors:
        """Extract risk factors from a finding."""
        context = context or {}
        
        # Base reachability from severity and confidence
        base_reachability = self.severity_weights.get(finding.severity, 0.5)
        confidence_factor = getattr(finding, 'confidence', 0.5)
        reachability = (base_reachability + confidence_factor) / 2
        
        # Invariant violation factor
        invariant_violation = 0.0
        if finding.invariants:
            violated_invariants = [
                inv for inv in finding.invariants 
                if inv.get('status') == 'violated'
            ]
            if violated_invariants:
                invariant_violation = min(1.0, len(violated_invariants) * 0.3)
        
        # Economic feasibility factor
        economic_feasibility = 0.0
        if finding.economic:
            feasibility = finding.economic.get('feasibility', 'unknown')
            if feasibility == 'plausible':
                economic_feasibility = 0.8
            elif feasibility == 'improbable':
                economic_feasibility = 0.2
        
        # Consensus alignment factor
        consensus_alignment = 1.0  # Default full alignment
        if context.get('triage_consensus'):
            consensus_status = context['triage_consensus'].get('consensus_status', 'aligned')
            if consensus_status == 'disputed':
                divergence_score = context['triage_consensus'].get('divergence_score', 0.0)
                consensus_alignment = max(0.1, 1.0 - divergence_score)
        
        # Complexity factor (based on function visibility and modifiers)
        complexity = 0.5  # Default medium complexity
        if finding.function_name:
            # External/public functions are easier to exploit
            if any(word in finding.code.lower() for word in ['external', 'public']):
                complexity = 0.3
            elif 'internal' in finding.code.lower() or 'private' in finding.code.lower():
                complexity = 0.7
        
        # Public exposure (based on function visibility)
        public_exposure = 0.5
        if 'external' in finding.code.lower() or 'public' in finding.code.lower():
            public_exposure = 0.9
        elif 'internal' in finding.code.lower():
            public_exposure = 0.3
        elif 'private' in finding.code.lower():
            public_exposure = 0.1
        
        # Privilege escalation potential
        privilege_escalation = 0.0
        if any(word in finding.code.lower() for word in ['onlyowner', 'onlyadmin', 'access']):
            privilege_escalation = 0.8
        
        return RiskFactors(
            reachability=reachability,
            invariant_violation=invariant_violation,
            economic_feasibility=economic_feasibility,
            consensus_alignment=consensus_alignment,
            complexity=complexity,
            public_exposure=public_exposure,
            privilege_escalation=privilege_escalation
        )


class RiskCalculator:
    """Calculates exploit probability and risk scores."""
    
    def __init__(self, coefficients: Optional[RiskCoefficients] = None):
        self.coefficients = coefficients or RiskCoefficients()
    
    def calculate_p_exploit(self, factors: RiskFactors) -> float:
        """Calculate probability of successful exploit using sigmoid function."""
        # Linear combination of factors
        linear_score = (
            self.coefficients.reachability * factors.reachability +
            self.coefficients.invariant * factors.invariant_violation +
            self.coefficients.economic * factors.economic_feasibility +
            self.coefficients.consensus * factors.consensus_alignment +
            self.coefficients.complexity * factors.complexity +
            self.coefficients.exposure * factors.public_exposure +
            self.coefficients.privilege * factors.privilege_escalation
        )
        
        # Apply sigmoid function to normalize to [0, 1]
        p_exploit = 1 / (1 + math.exp(-linear_score))
        
        # Clamp to reasonable bounds
        return max(0.01, min(0.99, p_exploit))
    
    def calculate_confidence(self, factors: RiskFactors, 
                           context: Optional[Dict[str, Any]] = None) -> float:
        """Calculate confidence in the risk assessment."""
        confidence_factors = []
        
        # Higher confidence for more definitive factors
        if factors.invariant_violation > 0.5:
            confidence_factors.append(0.9)  # High confidence from invariant violations
        
        if factors.economic_feasibility > 0.7:
            confidence_factors.append(0.8)  # High economic feasibility
        
        if factors.consensus_alignment > 0.8:
            confidence_factors.append(0.7)  # Good model consensus
        
        if factors.reachability > 0.7:
            confidence_factors.append(0.6)  # High reachability
        
        # Base confidence
        base_confidence = 0.5
        
        if confidence_factors:
            # Average of confidence factors
            avg_confidence = sum(confidence_factors) / len(confidence_factors)
            return (base_confidence + avg_confidence) / 2
        
        return base_confidence


class EconomicLossEstimator:
    """Estimates potential economic losses."""
    
    def __init__(self, valuation_loader: ValuationMapLoader):
        self.valuation_loader = valuation_loader
    
    def estimate_loss(self, finding: Finding, risk_factors: RiskFactors) -> Union[float, str]:
        """Estimate expected economic loss."""
        if not self.valuation_loader.valuations:
            return "unknown"  # No valuation data available
        
        # Try to identify affected assets from finding
        affected_assets = self._identify_assets(finding)
        
        if not affected_assets:
            return "unknown"  # Cannot identify assets
        
        total_exposure = 0.0
        
        for asset in affected_assets:
            asset_exposure = self._calculate_asset_exposure(finding, asset, risk_factors)
            total_exposure += asset_exposure
        
        return total_exposure
    
    def _identify_assets(self, finding: Finding) -> List[AssetValuation]:
        """Identify assets potentially affected by the finding."""
        assets = []
        
        # Look for asset indicators in the finding
        code_lower = finding.code.lower()
        
        # Common token patterns
        token_patterns = ['transfer', 'balanceof', 'totalsupply', 'mint', 'burn']
        if any(pattern in code_lower for pattern in token_patterns):
            # Try to identify specific tokens from contract name or code
            contract_name = getattr(finding, 'contract_name', '').upper()
            
            # Look for known tokens
            for symbol in ['ETH', 'USDT', 'USDC', 'WBTC']:
                if symbol in contract_name or symbol.lower() in code_lower:
                    valuation = self.valuation_loader.get_valuation(symbol)
                    if valuation:
                        assets.append(valuation)
            
            # If no specific tokens found, use ETH as default
            if not assets:
                eth_valuation = self.valuation_loader.get_valuation('ETH')
                if eth_valuation:
                    assets.append(eth_valuation)
        
        return assets
    
    def _calculate_asset_exposure(self, finding: Finding, asset: AssetValuation,
                                 risk_factors: RiskFactors) -> float:
        """Calculate exposure for a specific asset."""
        # Base exposure calculation
        base_value = asset.usd_value
        
        # Estimate the amount at risk based on finding characteristics
        exposure_factor = 0.1  # Default 10% exposure
        
        # Adjust based on finding type and severity
        if finding.severity == Severity.CRITICAL:
            exposure_factor = 0.5  # Up to 50% for critical issues
        elif finding.severity == Severity.HIGH:
            exposure_factor = 0.3  # Up to 30% for high severity
        elif finding.severity == Severity.MEDIUM:
            exposure_factor = 0.1  # Up to 10% for medium severity
        
        # Adjust based on economic feasibility
        exposure_factor *= (1 + risk_factors.economic_feasibility)
        
        # Calculate total exposure
        if asset.total_supply:
            total_value = asset.total_supply * base_value
            exposure = total_value * exposure_factor
        else:
            # Use a heuristic default value
            default_pool_size = 1000000.0  # $1M default
            exposure = default_pool_size * exposure_factor
        
        return exposure


class RiskModelEngine:
    """Main risk modeling engine."""
    
    def __init__(self, coefficients: Optional[RiskCoefficients] = None,
                 valuation_file: Optional[Path] = None):
        self.coefficients = coefficients or RiskCoefficients()
        self.valuation_loader = ValuationMapLoader(valuation_file)
        self.factor_extractor = RiskFactorExtractor()
        self.risk_calculator = RiskCalculator(self.coefficients)
        self.loss_estimator = EconomicLossEstimator(self.valuation_loader)
    
    def assess_finding(self, finding: Finding, 
                      context: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Perform complete risk assessment for a finding."""
        # Extract risk factors
        risk_factors = self.factor_extractor.extract_factors(finding, context)
        
        # Calculate exploit probability
        p_exploit = self.risk_calculator.calculate_p_exploit(risk_factors)
        
        # Calculate confidence
        confidence = self.risk_calculator.calculate_confidence(risk_factors, context)
        
        # Estimate economic loss
        expected_loss = self.loss_estimator.estimate_loss(finding, risk_factors)
        
        # Identify affected assets
        affected_assets = self.loss_estimator._identify_assets(finding)
        
        # Create finding ID
        finding_id = f"{finding.detector}_{finding.file.split('/')[-1]}_{finding.line}"
        
        return RiskAssessment(
            finding_id=finding_id,
            p_exploit=p_exploit,
            expected_loss_estimate=expected_loss,
            modeling_version="1.0",
            risk_factors=risk_factors,
            coefficients=self.coefficients,
            confidence=confidence,
            affected_assets=affected_assets
        )
    
    def assess_findings(self, findings: List[Finding],
                       context: Optional[Dict[str, Any]] = None) -> List[RiskAssessment]:
        """Assess multiple findings."""
        assessments = []
        
        for finding in findings:
            assessment = self.assess_finding(finding, context)
            assessments.append(assessment)
        
        return assessments


class RiskExporter:
    """Exports risk assessments to various formats."""
    
    def export_to_csv(self, assessments: List[RiskAssessment], 
                     output_file: Path) -> None:
        """Export risk assessments to CSV."""
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'finding_id', 'p_exploit', 'expected_loss_estimate', 
                'modeling_version', 'confidence',
                'reachability', 'invariant_violation', 'economic_feasibility',
                'consensus_alignment', 'complexity', 'public_exposure',
                'privilege_escalation', 'affected_assets_count'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for assessment in assessments:
                row = {
                    'finding_id': assessment.finding_id,
                    'p_exploit': assessment.p_exploit,
                    'expected_loss_estimate': assessment.expected_loss_estimate,
                    'modeling_version': assessment.modeling_version,
                    'confidence': assessment.confidence,
                    'reachability': assessment.risk_factors.reachability,
                    'invariant_violation': assessment.risk_factors.invariant_violation,
                    'economic_feasibility': assessment.risk_factors.economic_feasibility,
                    'consensus_alignment': assessment.risk_factors.consensus_alignment,
                    'complexity': assessment.risk_factors.complexity,
                    'public_exposure': assessment.risk_factors.public_exposure,
                    'privilege_escalation': assessment.risk_factors.privilege_escalation,
                    'affected_assets_count': len(assessment.affected_assets)
                }
                writer.writerow(row)
    
    def export_to_json(self, assessments: List[RiskAssessment],
                      output_file: Path) -> None:
        """Export risk assessments to JSON."""
        data = {
            "version": "1.0",
            "assessments": [assessment.to_dict() for assessment in assessments]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_summary_report(self, assessments: List[RiskAssessment]) -> Dict[str, Any]:
        """Generate summary statistics for risk assessments."""
        if not assessments:
            return {"total_assessments": 0}
        
        # Calculate statistics
        p_exploits = [a.p_exploit for a in assessments]
        confidences = [a.confidence for a in assessments]
        
        # Economic loss statistics (only numeric values)
        numeric_losses = [
            a.expected_loss_estimate for a in assessments 
            if isinstance(a.expected_loss_estimate, (int, float))
        ]
        
        # Risk categories
        high_risk = len([a for a in assessments if a.p_exploit > 0.7])
        medium_risk = len([a for a in assessments if 0.3 < a.p_exploit <= 0.7])
        low_risk = len([a for a in assessments if a.p_exploit <= 0.3])
        
        summary = {
            "total_assessments": len(assessments),
            "risk_distribution": {
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk
            },
            "p_exploit_stats": {
                "mean": sum(p_exploits) / len(p_exploits),
                "max": max(p_exploits),
                "min": min(p_exploits)
            },
            "confidence_stats": {
                "mean": sum(confidences) / len(confidences),
                "max": max(confidences),
                "min": min(confidences)
            }
        }
        
        if numeric_losses:
            summary["economic_loss_stats"] = {
                "total_estimated_loss": sum(numeric_losses),
                "mean_loss": sum(numeric_losses) / len(numeric_losses),
                "max_loss": max(numeric_losses),
                "assessments_with_loss_estimate": len(numeric_losses)
            }
        else:
            summary["economic_loss_stats"] = {
                "note": "No numeric loss estimates available"
            }
        
        return summary


# Utility functions
def create_sample_risk_config() -> Dict[str, Any]:
    """Create sample risk model configuration."""
    return {
        "enable": False,
        "valuation_file": "valuations.json",
        "coefficients": {
            "reachability": 1.1,
            "invariant": 1.3,
            "economic": 0.9,
            "consensus": 0.4,
            "complexity": -0.8,
            "exposure": 0.6,
            "privilege": 1.2
        },
        "export_formats": ["csv", "json"],
        "default_confidence": 0.5
    }