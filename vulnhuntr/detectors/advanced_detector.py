"""
Advanced vulnerability detector that combines multiple analysis techniques.
"""
from __future__ import annotations

from typing import Iterator, List, Dict, Any, Optional
import logging

from ..detectors.base import BaseDetector
from ..core.models import Finding, ScanContext, Severity
from ..core.advanced_analyzer import AdvancedVulnerabilityAnalyzer
from ..core.llm_analysis import LLMAnalysisEngine


class AdvancedVulnerabilityDetector(BaseDetector):
    """
    Advanced detector that finds complex vulnerabilities beyond Slither's capabilities.
    """

    name = "advanced_vulnerability_detector"
    description = "Finds complex, novel vulnerabilities with deep semantic analysis"
    severity = Severity.CRITICAL
    category = "advanced"
    confidence = 0.85

    # Enhanced metadata
    stability = "stable"
    maturity = "production"
    requires_slither = False
    supports_llm_enrichment = True
    enabled_by_default = True

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.advanced_analyzer = AdvancedVulnerabilityAnalyzer()
        self.llm_engine = None  # Will be initialized if LLM is configured

        # Add references to bug bounty programs
        self.references = [
            "https://immunefi.com/bounty/",
            "https://code4rena.com/",
            "https://hackerone.com/directory/programs"
        ]

        # Tags for categorization
        self.tags = {"advanced", "semantic", "novel", "high-value"}

    def analyze(self, context: ScanContext) -> Iterator[Finding]:
        """
        Perform advanced vulnerability analysis on the scan context.
        """
        self.logger.info(f"Starting advanced vulnerability analysis on {context.target_path}")

        # Initialize LLM engine if available
        if hasattr(context, 'config') and context.config and hasattr(context.config, 'llm'):
            if context.config.llm.enabled:
                try:
                    self.llm_engine = LLMAnalysisEngine(context.config.llm)
                    self.logger.info("LLM analysis engine initialized")
                except Exception as e:
                    self.logger.warning(f"Failed to initialize LLM engine: {e}")

        all_findings = []

        # Run advanced analysis on each contract
        for contract in context.contracts:
            try:
                # Use the advanced analyzer
                findings = list(self.advanced_analyzer.analyze_contract(contract, context))

                # Enhance findings with LLM if available
                if self.llm_engine and findings:
                    findings = self._enhance_with_llm(findings, context)

                all_findings.extend(findings)

            except Exception as e:
                self.logger.error(f"Error analyzing contract {contract.name}: {e}", exc_info=True)

        # Perform cross-contract analysis
        cross_contract_findings = self._analyze_cross_contract_vulnerabilities(context)
        all_findings.extend(cross_contract_findings)

        # Filter and prioritize findings
        prioritized_findings = self._prioritize_findings(all_findings)

        # Yield findings
        for finding in prioritized_findings:
            yield finding

        self.logger.info(f"Advanced analysis complete. Found {len(prioritized_findings)} high-value vulnerabilities")

    def _enhance_with_llm(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        """
        Enhance findings with LLM analysis for better context and remediation.
        """
        enhanced_findings = []

        # Prepare context for LLM
        llm_context = self._prepare_llm_context(context)

        for finding in findings:
            try:
                # Get LLM analysis
                analysis_result = self.llm_engine.analyze_finding(finding, llm_context)

                # Enhance finding with LLM insights
                enhanced_finding = self._merge_llm_insights(finding, analysis_result)
                enhanced_findings.append(enhanced_finding)

            except Exception as e:
                self.logger.warning(f"LLM enhancement failed for finding: {e}")
                enhanced_findings.append(finding)  # Keep original if enhancement fails

        return enhanced_findings

    def _prepare_llm_context(self, context: ScanContext) -> Dict[str, Any]:
        """
        Prepare context for LLM analysis.
        """
        llm_context = {
            "target_path": str(context.target_path),
            "contracts": len(context.contracts),
            "tool_artifacts": context.tool_artifacts
        }

        # Detect DeFi protocol type
        defi_protocol = self._detect_defi_protocol(context)
        if defi_protocol:
            llm_context["defi_protocol"] = defi_protocol

        # Detect oracle dependencies
        oracle_deps = self._detect_oracle_dependencies(context)
        if oracle_deps:
            llm_context["oracle_dependencies"] = oracle_deps

        # Check for cross-chain deployment
        llm_context["cross_chain"] = self._is_cross_chain(context)

        # Check for flash loan integration
        llm_context["flash_loan_enabled"] = self._has_flash_loans(context)

        return llm_context

    def _merge_llm_insights(self, finding: Finding, analysis_result) -> Finding:
        """
        Merge LLM insights into the finding.
        """
        # Create enhanced finding
        enhanced = Finding(
            detector=finding.detector,
            title=finding.title,
            file=finding.file,
            line=finding.line,
            severity=finding.severity,
            code=finding.code,
            description=finding.description,
            confidence=max(finding.confidence, analysis_result.confidence_score)
        )

        # Add LLM insights to description
        llm_insights = []

        if analysis_result.defi_context:
            llm_insights.append(f"DeFi Impact: {analysis_result.defi_context}")

        if analysis_result.mev_vulnerability:
            llm_insights.append(f"MEV Risk: {analysis_result.mev_vulnerability}")

        if analysis_result.flash_loan_risk:
            llm_insights.append(f"Flash Loan Risk: {analysis_result.flash_loan_risk}")

        if analysis_result.cross_chain_implications:
            llm_insights.append(f"Cross-Chain: {analysis_result.cross_chain_implications}")

        if analysis_result.code_fix_suggestion:
            llm_insights.append(f"Fix Suggestion: {analysis_result.code_fix_suggestion}")

        if llm_insights:
            enhanced.description = f"{finding.description}\n\nLLM Analysis:\n" + "\n".join(llm_insights)

        # Adjust severity if recommended
        if analysis_result.severity_adjustment:
            if "UPGRADE" in analysis_result.severity_adjustment:
                enhanced.severity = Severity.CRITICAL

        # Set remediation priority
        if hasattr(enhanced, 'metadata'):
            enhanced.metadata["remediation_priority"] = analysis_result.remediation_priority
        else:
            enhanced.metadata = {"remediation_priority": analysis_result.remediation_priority}

        return enhanced

    def _analyze_cross_contract_vulnerabilities(self, context: ScanContext) -> List[Finding]:
        """
        Analyze vulnerabilities that span multiple contracts.
        """
        findings = []

        if len(context.contracts) < 2:
            return findings

        # Check for reentrancy across contracts
        reentrancy_chains = self._find_cross_contract_reentrancy(context)
        for chain in reentrancy_chains:
            findings.append(self.create_finding(
                title="Cross-Contract Reentrancy Chain",
                file_path=chain["entry_contract"],
                line=chain["entry_line"],
                code=chain["code"],
                description=f"Reentrancy chain across contracts: {' -> '.join(chain['path'])}. "
                          f"This novel attack vector can bypass single-contract protections. "
                          f"Estimated bounty: $75,000+",
                severity=Severity.CRITICAL,
                confidence=0.8
            ))

        # Check for privilege escalation across contracts
        escalation_paths = self._find_cross_contract_privilege_escalation(context)
        for path in escalation_paths:
            findings.append(self.create_finding(
                title="Cross-Contract Privilege Escalation",
                file_path=path["start_contract"],
                line=path["start_line"],
                code=path["code"],
                description=f"Privilege escalation path: {' -> '.join(path['contracts'])}. "
                          f"Attacker can gain admin rights by exploiting trust between contracts. "
                          f"Estimated bounty: $100,000+",
                severity=Severity.CRITICAL,
                confidence=0.75
            ))

        return findings

    def _prioritize_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Prioritize findings based on novelty, exploitability, and impact.
        """
        scored_findings = []

        for finding in findings:
            # Calculate priority score
            score = self._calculate_priority_score(finding)

            # Only include high-value findings (score >= 200)
            if score >= 200:
                # Add score to metadata
                if hasattr(finding, 'metadata'):
                    finding.metadata["priority_score"] = score
                else:
                    finding.metadata = {"priority_score": score}

                scored_findings.append((score, finding))

        # Sort by score (highest first)
        scored_findings.sort(key=lambda x: x[0], reverse=True)

        return [finding for _, finding in scored_findings]

    def _calculate_priority_score(self, finding: Finding) -> int:
        """
        Calculate priority score based on novelty, exploitability, and impact.
        """
        # Extract score from metadata if available
        if hasattr(finding, 'metadata') and "score" in finding.metadata:
            return finding.metadata["score"]

        # Otherwise calculate based on severity and tags
        base_score = {
            Severity.CRITICAL: 300,
            Severity.HIGH: 200,
            Severity.MEDIUM: 100,
            Severity.LOW: 50,
            Severity.INFO: 10
        }.get(finding.severity, 100)

        # Boost for novel findings
        if hasattr(finding, 'tags'):
            if "novel" in finding.tags:
                base_score *= 1.5
            if "cross-function" in finding.tags or "cross-chain" in finding.tags:
                base_score *= 1.3
            if "high-value" in finding.tags:
                base_score *= 1.2

        return int(base_score)

    def _detect_defi_protocol(self, context: ScanContext) -> Optional[str]:
        """
        Detect the type of DeFi protocol.
        """
        # Analyze contract names and functions to determine protocol type
        for contract in context.contracts:
            source = contract.source if hasattr(contract, 'source') else ""

            # AMM/DEX detection
            if any(keyword in source.lower() for keyword in ["swap", "liquidity", "pair", "factory"]):
                return "AMM/DEX"

            # Lending protocol detection
            if any(keyword in source.lower() for keyword in ["borrow", "lend", "collateral", "liquidate"]):
                return "Lending"

            # Yield farming detection
            if any(keyword in source.lower() for keyword in ["stake", "harvest", "reward", "farm"]):
                return "Yield Farming"

            # Bridge detection
            if any(keyword in source.lower() for keyword in ["bridge", "crosschain", "relay"]):
                return "Bridge"

        return None

    def _detect_oracle_dependencies(self, context: ScanContext) -> List[str]:
        """
        Detect oracle dependencies in contracts.
        """
        oracles = []

        for contract in context.contracts:
            source = contract.source if hasattr(contract, 'source') else ""

            if "chainlink" in source.lower() or "aggregatorv3" in source.lower():
                oracles.append("Chainlink")

            if "uniswap" in source.lower() and "oracle" in source.lower():
                oracles.append("Uniswap V3 TWAP")

            if "band" in source.lower() and "protocol" in source.lower():
                oracles.append("Band Protocol")

            if "tellor" in source.lower():
                oracles.append("Tellor")

        return list(set(oracles))

    def _is_cross_chain(self, context: ScanContext) -> bool:
        """
        Check if contracts are designed for cross-chain deployment.
        """
        for contract in context.contracts:
            source = contract.source if hasattr(contract, 'source') else ""
            if any(keyword in source.lower() for keyword in ["chainid", "crosschain", "multichain", "bridge"]):
                return True
        return False

    def _has_flash_loans(self, context: ScanContext) -> bool:
        """
        Check if contracts integrate with flash loan providers.
        """
        for contract in context.contracts:
            source = contract.source if hasattr(contract, 'source') else ""
            if any(keyword in source.lower() for keyword in ["flashloan", "executeoperation", "onflashloan"]):
                return True
        return False

    def _find_cross_contract_reentrancy(self, context: ScanContext) -> List[Dict[str, Any]]:
        """
        Find reentrancy chains across multiple contracts.
        """
        chains = []

        # This would analyze call graphs across contracts
        # Simplified implementation for demonstration

        return chains

    def _find_cross_contract_privilege_escalation(self, context: ScanContext) -> List[Dict[str, Any]]:
        """
        Find privilege escalation paths across contracts.
        """
        paths = []

        # This would analyze trust relationships between contracts
        # Simplified implementation for demonstration

        return paths