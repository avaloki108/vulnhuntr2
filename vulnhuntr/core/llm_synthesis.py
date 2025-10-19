"""
LLM synthesis layer for enhanced analysis, remediation, and invariant generation.
Enhanced with Ollama support for holistic smart contract analysis.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
import json
import logging

from .models import Finding, CorrelatedFinding, ScanContext
from .contract_graph import ContractGraph, ContractGraphBuilder
from .ollama_client import OllamaClient, OllamaConfig

logger = logging.getLogger(__name__)


class MockLLMClient:
    """Mock LLM client for testing and development."""
    
    def chat(self, prompt: str, **kwargs) -> str:
        """Mock chat response with synthetic remediation suggestions."""
        if "remediation" in prompt.lower():
            return self._generate_mock_remediation(prompt)
        elif "invariant" in prompt.lower():
            return self._generate_mock_invariant(prompt)
        elif "poc" in prompt.lower():
            return self._generate_mock_poc(prompt)
        
        return "Mock LLM response for: " + prompt[:100] + "..."
    
    def _generate_mock_remediation(self, prompt: str) -> str:
        """Generate mock remediation suggestions."""
        return json.dumps({
            "remediation": "Implement checks-effects-interactions pattern and add reentrancy guard",
            "code_suggestions": [
                "Add ReentrancyGuard modifier from OpenZeppelin",
                "Move state changes before external calls",
                "Use pull payment pattern for fund transfers"
            ],
            "confidence": 0.85
        })
    
    def _generate_mock_invariant(self, prompt: str) -> str:
        """Generate mock invariant suggestions."""
        return json.dumps({
            "invariants": [
                "Contract balance should never decrease without corresponding user withdrawal",
                "Total user deposits should equal contract balance minus fees",
                "State variables should be consistent before and after external calls"
            ],
            "formal_properties": [
                "forall user: balanceOf[user] <= userDeposits[user]",
                "totalSupply() == sum(balanceOf[all_users])"
            ]
        })
    
    def _generate_mock_poc(self, prompt: str) -> str:
        """Generate mock proof-of-concept code."""
        return json.dumps({
            "poc_code": '''
// Proof of Concept for Reentrancy Attack
contract Attacker {
    VulnerableContract target;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }
    
    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw();
        }
    }
}
            ''',
            "explanation": "This PoC demonstrates a reentrancy attack by recursively calling withdraw through the fallback function"
        })


class LLMSynthesisEngine:
    """
    Enhanced engine for LLM-powered analysis with holistic contract understanding.
    Supports both traditional LLM clients and Ollama for local inference.
    """

    def __init__(self, llm_client=None, ollama_config: Optional[OllamaConfig] = None):
        self.llm_client = llm_client or MockLLMClient()
        self.ollama_client = None
        self.contract_graph_builder = ContractGraphBuilder()
        self.contract_graph: Optional[ContractGraph] = None

        # Initialize Ollama client if config provided
        if ollama_config:
            try:
                self.ollama_client = OllamaClient(ollama_config)
                if self.ollama_client.is_available():
                    logger.info(f"Ollama client initialized with model: {ollama_config.model}")
                else:
                    logger.warning("Ollama client not available, falling back to basic LLM")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama client: {e}")

        # Load prompt templates
        self.logic_synthesis_prompt = self._load_logic_synthesis_prompt()
        self.invariant_generation_prompt = self._load_invariant_generation_prompt()
        self.poc_generation_prompt = self._load_poc_generation_prompt()
    
    def build_contract_graph(self, contract_paths: List) -> None:
        """Build contract relationship graph for holistic analysis."""
        try:
            from pathlib import Path
            paths = [Path(p) for p in contract_paths]
            self.contract_graph = self.contract_graph_builder.analyze_project(paths)
            logger.info(f"Built contract graph with {len(self.contract_graph.contracts)} contracts")
        except Exception as e:
            logger.error(f"Failed to build contract graph: {e}")

    def enhance_findings(
        self,
        findings: List[Finding],
        context: ScanContext
    ) -> List[Finding]:
        """
        Enhance findings with LLM-generated remediation and invariant suggestions.
        Now with holistic contract analysis via Ollama.

        Args:
            findings: List of findings to enhance
            context: Scan context with contract information

        Returns:
            Enhanced findings with LLM-generated content and cross-contract analysis
        """
        enhanced = []

        for finding in findings:
            # Use Ollama for holistic analysis if available
            if self.ollama_client and self.ollama_client.is_available() and self.contract_graph:
                enhanced_finding = self._enhance_finding_with_ollama(finding, context)
            else:
                enhanced_finding = self._enhance_single_finding(finding, context)

            enhanced.append(enhanced_finding)

        return enhanced
    
    def enhance_correlated_findings(
        self, 
        correlated_findings: List[CorrelatedFinding], 
        context: ScanContext
    ) -> List[CorrelatedFinding]:
        """
        Enhance correlated findings with compound analysis.
        """
        enhanced = []
        
        for corr_finding in correlated_findings:
            enhanced_corr = self._enhance_correlated_finding(corr_finding, context)
            enhanced.append(enhanced_corr)
        
        return enhanced
    
    def _enhance_single_finding(self, finding: Finding, context: ScanContext) -> Finding:
        """Enhance a single finding with LLM analysis."""
        # Generate remediation if not present
        if not finding.remediation:
            remediation = self._generate_remediation(finding, context)
            finding.remediation = remediation
        
        # Generate invariant suggestion if not present
        if not finding.invariant_suggestion:
            invariant = self._generate_invariant_suggestion(finding, context)
            finding.invariant_suggestion = invariant
        
        # Generate PoC if enabled and not present
        if context.enable_poc_generation and not finding.poc_code:
            poc = self._generate_poc(finding, context)
            finding.poc_code = poc
        
        return finding
    
    def _enhance_correlated_finding(
        self, 
        corr_finding: CorrelatedFinding, 
        context: ScanContext
    ) -> CorrelatedFinding:
        """Enhance correlated finding with compound analysis."""
        # Enhance the primary finding
        corr_finding.primary_finding = self._enhance_single_finding(
            corr_finding.primary_finding, context
        )
        
        # Generate compound analysis
        if not corr_finding.pattern_description:
            corr_finding.pattern_description = self._generate_compound_analysis(
                corr_finding, context
            )
        
        return corr_finding

    def _enhance_finding_with_ollama(self, finding: Finding, context: ScanContext) -> Finding:
        """Enhance finding using Ollama's holistic analysis capabilities."""
        try:
            # Get holistic analysis from Ollama
            ollama_analysis = self.ollama_client.analyze_vulnerability_holistically(
                finding, self.contract_graph, context
            )

            # Apply holistic insights to finding
            if ollama_analysis and not ollama_analysis.get('error'):
                self._apply_ollama_analysis(finding, ollama_analysis)

            # Generate detailed remediation
            if not finding.remediation:
                finding.remediation = self._generate_ollama_remediation(finding, ollama_analysis)

            # Generate enhanced invariant suggestions
            if not finding.invariant_suggestion:
                finding.invariant_suggestion = self._generate_ollama_invariant(finding, ollama_analysis)

            # Generate sophisticated PoC if enabled
            if context.enable_poc_generation and not finding.poc_code:
                finding.poc_code = self._generate_ollama_poc(finding, ollama_analysis)

            return finding

        except Exception as e:
            logger.error(f"Error in Ollama enhancement: {e}")
            # Fallback to basic enhancement
            return self._enhance_single_finding(finding, context)

    def _apply_ollama_analysis(self, finding: Finding, analysis: Dict[str, Any]) -> None:
        """Apply Ollama analysis insights to the finding."""
        if 'holistic_impact' in analysis:
            impact = analysis['holistic_impact']

            # Adjust severity based on holistic analysis
            if 'severity_adjustment' in impact:
                # Store original severity in metadata
                if not hasattr(finding, 'metadata'):
                    finding.metadata = {}
                finding.metadata['original_severity'] = finding.severity.value
                finding.metadata['ollama_severity'] = impact['severity_adjustment']

            # Add ecosystem risk information
            if 'ecosystem_risk' in impact:
                finding.metadata = getattr(finding, 'metadata', {})
                finding.metadata['ecosystem_risk'] = impact['ecosystem_risk']

            # Add affected contracts
            if 'affected_contracts' in impact:
                finding.metadata = getattr(finding, 'metadata', {})
                finding.metadata['affected_contracts'] = impact['affected_contracts']

        # Add attack vector information
        if 'attack_vectors' in analysis:
            finding.metadata = getattr(finding, 'metadata', {})
            finding.metadata['attack_vectors'] = analysis['attack_vectors']

        # Add economic analysis
        if 'economic_analysis' in analysis:
            finding.metadata = getattr(finding, 'metadata', {})
            finding.metadata['economic_analysis'] = analysis['economic_analysis']

    def _generate_ollama_remediation(self, finding: Finding, analysis: Dict[str, Any]) -> str:
        """Generate remediation using Ollama analysis."""
        if analysis and 'remediation' in analysis:
            remediation_data = analysis['remediation']
            parts = []

            if 'immediate_fixes' in remediation_data:
                parts.append("Immediate fixes: " + "; ".join(remediation_data['immediate_fixes']))

            if 'ecosystem_changes' in remediation_data:
                parts.append("Ecosystem changes: " + "; ".join(remediation_data['ecosystem_changes']))

            if 'upgrade_considerations' in remediation_data:
                parts.append("Upgrade considerations: " + "; ".join(remediation_data['upgrade_considerations']))

            if parts:
                return " | ".join(parts)

        # Fallback to basic remediation
        return self._get_fallback_remediation(finding)

    def _generate_ollama_invariant(self, finding: Finding, analysis: Dict[str, Any]) -> str:
        """Generate invariant suggestions using Ollama analysis."""
        if analysis and 'holistic_impact' in analysis:
            impact = analysis['holistic_impact']
            if 'ecosystem_risk' in impact:
                return f"Ecosystem invariant: {impact['ecosystem_risk'][:200]}"

        return self._get_fallback_invariant(finding)

    def _generate_ollama_poc(self, finding: Finding, analysis: Dict[str, Any]) -> str:
        """Generate PoC using Ollama analysis insights."""
        if analysis and 'attack_vectors' in analysis:
            vectors = analysis['attack_vectors']
            poc_parts = []

            if 'cross_contract_exploits' in vectors:
                poc_parts.append("// Cross-contract exploit vector:")
                poc_parts.extend([f"// {exploit}" for exploit in vectors['cross_contract_exploits'][:3]])

            if 'economic_exploits' in vectors:
                poc_parts.append("// Economic exploit vector:")
                poc_parts.extend([f"// {exploit}" for exploit in vectors['economic_exploits'][:3]])

            if poc_parts:
                return "\n".join(poc_parts) + f"\n// Full PoC for {finding.title}\n// TODO: Implement based on analysis above"

        return self._get_fallback_poc(finding)

    def analyze_cross_contract_vulnerabilities(
        self,
        target_contracts: List[str]
    ) -> Dict[str, Any]:
        """
        Perform cross-contract vulnerability analysis using Ollama.

        Args:
            target_contracts: List of contract names to analyze together

        Returns:
            Cross-contract vulnerability analysis results
        """
        if not self.ollama_client or not self.ollama_client.is_available() or not self.contract_graph:
            logger.warning("Ollama or contract graph not available for cross-contract analysis")
            return {"error": "Requirements not met for cross-contract analysis"}

        try:
            return self.ollama_client.analyze_cross_contract_logic(
                self.contract_graph, target_contracts
            )
        except Exception as e:
            logger.error(f"Error in cross-contract analysis: {e}")
            return {"error": str(e)}

    def _generate_remediation(self, finding: Finding, context: ScanContext) -> str:
        """Generate remediation suggestions using LLM."""
        prompt = self.logic_synthesis_prompt.format(
            finding_title=finding.title,
            finding_description=finding.description or "",
            code_snippet=finding.code,
            severity=finding.severity.value,
            category=finding.category
        )
        
        try:
            response = self.llm_client.chat(prompt)
            
            # Try to parse JSON response
            if response.strip().startswith('{'):
                parsed = json.loads(response)
                return parsed.get("remediation", "No specific remediation provided")
            
            return response[:500]  # Truncate if not JSON
            
        except Exception:
            return self._get_fallback_remediation(finding)
    
    def _generate_invariant_suggestion(self, finding: Finding, context: ScanContext) -> str:
        """Generate invariant suggestions using LLM."""
        prompt = self.invariant_generation_prompt.format(
            finding_title=finding.title,
            contract_name=finding.contract_name or "Unknown",
            function_name=finding.function_name or "Unknown",
            code_snippet=finding.code,
            category=finding.category
        )
        
        try:
            response = self.llm_client.chat(prompt)
            
            if response.strip().startswith('{'):
                parsed = json.loads(response)
                invariants = parsed.get("invariants", [])
                return "; ".join(invariants[:3])  # Top 3 invariants
            
            return response[:300]
            
        except Exception:
            return self._get_fallback_invariant(finding)
    
    def _generate_poc(self, finding: Finding, context: ScanContext) -> str:
        """Generate proof-of-concept code using LLM."""
        prompt = self.poc_generation_prompt.format(
            finding_title=finding.title,
            finding_description=finding.description or "",
            code_snippet=finding.code,
            contract_name=finding.contract_name or "VulnerableContract",
            function_name=finding.function_name or "vulnerableFunction"
        )
        
        try:
            response = self.llm_client.chat(prompt)
            
            if response.strip().startswith('{'):
                parsed = json.loads(response)
                return parsed.get("poc_code", "No PoC generated")
            
            return response
            
        except Exception:
            return self._get_fallback_poc(finding)
    
    def _generate_compound_analysis(
        self, 
        corr_finding: CorrelatedFinding, 
        context: ScanContext
    ) -> str:
        """Generate compound vulnerability analysis for correlated findings."""
        findings_summary = []
        for f in corr_finding.all_findings:
            findings_summary.append(f"{f.detector}: {f.title} (Line {f.line})")
        
        compound_prompt = f"""
        Analyze the following compound vulnerability pattern:
        
        Primary Finding: {corr_finding.primary_finding.title}
        Related Findings:
        {chr(10).join(findings_summary)}
        
        Correlation Type: {corr_finding.correlation_type}
        
        Provide analysis of how these vulnerabilities could be chained together for increased impact.
        """
        
        try:
            response = self.llm_client.chat(compound_prompt)
            return response[:500]
        except Exception:
            return f"Compound vulnerability pattern involving {len(corr_finding.all_findings)} related findings"
    
    def _get_fallback_remediation(self, finding: Finding) -> str:
        """Provide fallback remediation based on category."""
        fallbacks = {
            "reentrancy": "Implement checks-effects-interactions pattern and use reentrancy guards",
            "oracle": "Use multiple oracle sources and implement price deviation checks",
            "flashloan": "Add proper checks for flashloan context and invariant validation",
            "access_control": "Implement proper role-based access control with timelock",
            "gas": "Optimize gas usage and implement gas limit checks",
            "unknown": "Review code for security best practices and add appropriate safeguards"
        }
        
        return fallbacks.get(finding.category.lower(), fallbacks["unknown"])
    
    def _get_fallback_invariant(self, finding: Finding) -> str:
        """Provide fallback invariant suggestions."""
        return "Contract state should remain consistent; External calls should not affect core invariants"
    
    def _get_fallback_poc(self, finding: Finding) -> str:
        """Provide fallback PoC template."""
        return f"// PoC template for {finding.title}\n// TODO: Implement specific exploit for this vulnerability"
    
    def _load_logic_synthesis_prompt(self) -> str:
        """Load or define logic synthesis prompt template."""
        return """
        Analyze the following smart contract vulnerability and provide remediation:
        
        Vulnerability: {finding_title}
        Description: {finding_description}
        Code: {code_snippet}
        Severity: {severity}
        Category: {category}
        
        Provide a JSON response with:
        - remediation: Specific remediation steps
        - code_suggestions: List of code improvement suggestions
        - confidence: Confidence score (0-1)
        """
    
    def _load_invariant_generation_prompt(self) -> str:
        """Load or define invariant generation prompt template."""
        return """
        Generate security invariants for the following vulnerability:
        
        Vulnerability: {finding_title}
        Contract: {contract_name}
        Function: {function_name}
        Code: {code_snippet}
        Category: {category}
        
        Provide a JSON response with:
        - invariants: List of natural language invariants
        - formal_properties: List of formal property specifications
        """
    
    def _load_poc_generation_prompt(self) -> str:
        """Load or define PoC generation prompt template."""
        return """
        Generate a proof-of-concept exploit for the following vulnerability:
        
        Vulnerability: {finding_title}
        Description: {finding_description}
        Target Contract: {contract_name}
        Target Function: {function_name}
        Vulnerable Code: {code_snippet}
        
        Provide a JSON response with:
        - poc_code: Solidity contract demonstrating the exploit
        - explanation: Brief explanation of the attack vector
        """