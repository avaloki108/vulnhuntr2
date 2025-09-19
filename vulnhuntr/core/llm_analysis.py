"""
LLM-enhanced security analysis for Web3 contracts.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.models import Finding
from ..config.schema import LLMConfig


@dataclass
class LLMAnalysisResult:
    """Result of LLM-enhanced security analysis."""
    finding_detector: str
    risk_assessment: str
    exploit_likelihood: str
    business_impact: str
    severity_adjustment: Optional[str] = None  # e.g., "UPGRADED_TO_HIGH"
    confidence_score: float = 0.5  # 0.0 to 1.0
    remediation_priority: str = "MEDIUM"  # IMMEDIATE, HIGH, MEDIUM, LOW
    code_fix_suggestion: Optional[str] = None
    defi_context: Optional[str] = None  # DeFi-specific context
    cross_chain_implications: Optional[str] = None
    flash_loan_risk: Optional[str] = None
    mev_vulnerability: Optional[str] = None  # MEV (Maximal Extractable Value) risk


class LLMAnalysisEngine:
    """
    LLM-enhanced analysis engine for Web3 security vulnerabilities.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def analyze_finding(self, finding: Finding, context: Optional[Dict[str, Any]] = None) -> LLMAnalysisResult:
        """
        Analyze a security finding with LLM enhancement.
        
        Args:
            finding: Security finding to analyze
            context: Additional context for analysis
            
        Returns:
            Enhanced analysis result
        """
        if context is None:
            context = {}
            
        # Build Web3-specific analysis prompt
        prompt_context = self._build_analysis_context(finding, context)
        
        # Query LLM for enhanced analysis
        llm_response = self._query_llm_sync(prompt_context)
        
        return self._parse_llm_response(finding, llm_response)

    def _build_analysis_context(self, finding: Finding, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build comprehensive analysis context for LLM.
        """
        return {
            "finding": {
                "title": finding.title,
                "description": finding.description,
                "severity": str(finding.severity),
                "confidence": finding.confidence,
                "location": f"{finding.file}:{finding.line}",
                "detector": finding.detector
            },
            "web3_context": {
                "defi_protocol_type": context.get("defi_protocol"),
                "oracle_dependencies": context.get("oracle_dependencies", []),
                "cross_chain_deployment": context.get("cross_chain", False),
                "token_standard": context.get("token_standard"),
                "governance_model": context.get("governance_model")
            },
            "security_context": {
                "flash_loan_enabled": context.get("flash_loan_enabled", False),
                "mev_protection": context.get("mev_protection", False),
                "timelock_present": context.get("timelock_present", False),
                "multisig_required": context.get("multisig_required", False)
            },
            "analysis_prompt": self._build_analysis_prompt(finding, context)
        }

    def _build_analysis_prompt(self, finding: Finding, context: Dict[str, Any]) -> str:
        """
        Build LLM analysis prompt with Web3-specific context.
        """
        base_prompt = f"""
# Web3 Security Analysis Request

## Vulnerability Details
- **Type**: {finding.title}
- **Description**: {finding.description}
- **Current Severity**: {finding.severity}
- **Location**: {finding.file}:{finding.line}
- **Detector**: {finding.detector}

## Web3 Context Analysis Required

### DeFi Protocol Impact
Analyze how this vulnerability affects:
- Yield farming mechanisms
- Liquidity provision safety
- Token economics and inflation
- AMM (Automated Market Maker) functionality
- Lending/borrowing protocols

### Oracle Security Implications
Evaluate risks related to:
- Price feed manipulation
- Oracle failure scenarios  
- Cross-oracle validation needs
- Time-weighted average price (TWAP) requirements
- Circuit breaker mechanisms

### MEV (Maximal Extractable Value) Vulnerability
Assess potential for:
- Front-running attacks
- Sandwich attacks
- Arbitrage exploitation
- Transaction ordering manipulation
- Block producer extraction

### Flash Loan Attack Vectors
Consider vulnerability to:
- Capital-free price manipulation
- Governance token voting manipulation
- Liquidity pool drainage
- Collateral ratio manipulation
- Cross-protocol composability risks

### Cross-Chain Security
Analyze implications for:
- Bridge protocol security
- Cross-chain message passing
- Finality time differences
- Oracle synchronization across chains
- Rollup/sidechain specific risks

## Analysis Instructions
Provide a comprehensive Web3 security assessment including:
1. **Severity Adjustment**: Should severity be upgraded/downgraded based on Web3 context?
2. **DeFi Impact**: Specific impacts on DeFi protocols and users
3. **Remediation Priority**: IMMEDIATE/HIGH/MEDIUM/LOW with Web3-specific reasoning
4. **Code Fix Suggestions**: Solidity-specific secure coding patterns
5. **MEV Protection**: Recommendations for MEV-resistant design
6. **Oracle Security**: Price feed security recommendations
7. **Flash Loan Protection**: Mitigation strategies for flash loan attacks

Respond with detailed analysis focusing on Web3-specific attack vectors and mitigation strategies.
"""

        # Add context-specific sections
        if context.get("defi_protocol"):
            base_prompt += f"\n### DeFi Protocol Context\nThis is a {context['defi_protocol']} protocol."
            
        if context.get("oracle_dependencies"):
            base_prompt += f"\n### Oracle Dependencies\nProtocol depends on: {', '.join(context['oracle_dependencies'])}"
            
        if context.get("cross_chain"):
            base_prompt += "\n### Cross-Chain Deployment\nThis contract will be deployed across multiple chains."
            
        if context.get("flash_loan_enabled"):
            base_prompt += "\n### Flash Loan Integration\nProtocol integrates with flash loan providers."

        return base_prompt

    def _query_llm_sync(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query the LLM with Web3 security context (synchronous version).
        
        Args:
            context: Analysis context containing prompt and findings
            
        Returns:
            LLM response with Web3 insights
        """
        try:
            # In a real implementation, this would call the actual LLM API
            # Use the context for actual LLM query (placeholder for now)
            _ = context  # Acknowledge the parameter usage
            
            # For now, return a structured placeholder response
            return {
                "web3_insights": {
                    "defi_impact": "Medium - potential yield farming risks",
                    "oracle_risks": "High - price manipulation possible",
                    "cross_chain_implications": "Low - single chain deployment",
                    "mev_vulnerability": "Medium - front-running opportunity exists",
                    "flash_loan_risk": "Low - no flash loan integration detected"
                },
                "confidence": 0.75,
                "risk_assessment": "Significant Web3-specific risks identified",
                "exploit_likelihood": "Medium - requires specific market conditions",
                "business_impact": "High - potential financial losses for users",
                "recommendations": [
                    "Implement TWAP price feeds",
                    "Add MEV protection mechanisms",
                    "Consider timelock for critical functions"
                ]
            }
        except (ConnectionError, ValueError, KeyError) as e:
            self.logger.error("LLM query failed: %s", str(e))
            return {
                "web3_insights": {},
                "confidence": 0.0,
                "risk_assessment": "Analysis failed",
                "exploit_likelihood": "Unknown",
                "business_impact": "Unknown",
                "recommendations": [],
                "error": str(e)
            }

    def _parse_llm_response(self, finding: Finding, response: Dict[str, Any]) -> LLMAnalysisResult:
        """
        Parse LLM response into structured analysis result.
        """
        insights = response.get("web3_insights", {})
        
        return LLMAnalysisResult(
            finding_detector=finding.detector,
            risk_assessment=response.get("risk_assessment", "Unknown risk level"),
            exploit_likelihood=response.get("exploit_likelihood", "Unknown likelihood"),
            business_impact=response.get("business_impact", "Unknown impact"),
            severity_adjustment=None,  # Would be parsed from LLM response
            confidence_score=response.get("confidence", 0.5),
            remediation_priority="HIGH",  # Would be determined from LLM analysis
            code_fix_suggestion=None,  # Would be extracted from LLM response
            defi_context=insights.get("defi_impact"),
            cross_chain_implications=insights.get("cross_chain_implications"),
            flash_loan_risk=insights.get("flash_loan_risk"),
            mev_vulnerability=insights.get("mev_vulnerability")
        )

    def batch_analyze_findings(self, findings: List[Finding], context: Optional[Dict[str, Any]] = None) -> List[LLMAnalysisResult]:
        """
        Analyze multiple findings in batch for efficiency.
        
        Args:
            findings: List of security findings
            context: Shared analysis context
            
        Returns:
            List of enhanced analysis results
        """
        if context is None:
            context = {}
            
        results = []
        for finding in findings:
            try:
                result = self.analyze_finding(finding, context)
                results.append(result)
            except (ValueError, AttributeError, KeyError) as e:
                self.logger.error("Failed to analyze finding %s: %s", finding.detector, str(e))
                # Create error result
                results.append(LLMAnalysisResult(
                    finding_detector=finding.detector,
                    risk_assessment=f"Analysis failed: {e}",
                    exploit_likelihood="Unknown",
                    business_impact="Unknown",
                    severity_adjustment=None,
                    confidence_score=0.0,
                    remediation_priority="UNKNOWN",
                    code_fix_suggestion=None,
                    defi_context=None,
                    cross_chain_implications=None,
                    flash_loan_risk=None,
                    mev_vulnerability=None
                ))
        
        return results

    def generate_web3_security_report(self, analysis_results: List[LLMAnalysisResult]) -> Dict[str, Any]:
        """
        Generate comprehensive Web3 security report from analysis results.
        """
        # Categorize findings by Web3-specific risk types
        defi_risks = [r for r in analysis_results if r.defi_context]
        mev_risks = [r for r in analysis_results if r.mev_vulnerability]
        flash_loan_risks = [r for r in analysis_results if r.flash_loan_risk]
        cross_chain_risks = [r for r in analysis_results if r.cross_chain_implications]
        
        # Calculate overall risk scores
        avg_confidence = sum(r.confidence_score for r in analysis_results) / len(analysis_results) if analysis_results else 0
        
        # Priority distribution
        priority_counts = {}
        for result in analysis_results:
            priority = result.remediation_priority
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

        return {
            "summary": {
                "total_findings": len(analysis_results),
                "average_confidence": round(avg_confidence, 2),
                "web3_specific_risks": {
                    "defi_related": len(defi_risks),
                    "mev_vulnerable": len(mev_risks),
                    "flash_loan_risks": len(flash_loan_risks),
                    "cross_chain_risks": len(cross_chain_risks)
                }
            },
            "priority_distribution": priority_counts,
            "web3_recommendations": {
                "immediate_actions": [
                    r.code_fix_suggestion for r in analysis_results 
                    if r.remediation_priority == "IMMEDIATE" and r.code_fix_suggestion
                ],
                "defi_specific": [
                    "Implement robust oracle price validation",
                    "Add circuit breakers for extreme market conditions",
                    "Use time-weighted average prices (TWAP)",
                    "Implement flash loan protection mechanisms"
                ],
                "mev_protection": [
                    "Add commit-reveal schemes for sensitive operations",
                    "Implement batch auctions for fair ordering",
                    "Use private mempools where appropriate",
                    "Add randomization to prevent MEV extraction"
                ]
            },
            "detailed_analysis": [
                {
                    "detector": r.finding_detector,
                    "risk_assessment": r.risk_assessment,
                    "exploit_likelihood": r.exploit_likelihood,
                    "business_impact": r.business_impact,
                    "priority": r.remediation_priority,
                    "confidence": r.confidence_score,
                    "defi_context": r.defi_context,
                    "mev_risk": r.mev_vulnerability,
                    "flash_loan_risk": r.flash_loan_risk,
                    "cross_chain_implications": r.cross_chain_implications
                }
                for r in analysis_results
            ]
        }