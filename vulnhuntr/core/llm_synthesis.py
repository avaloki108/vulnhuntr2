"""
LLM synthesis layer for enhanced analysis, remediation, and invariant generation.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
import json

from .models import Finding, CorrelatedFinding, ScanContext


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
    Engine for LLM-enhanced analysis including remediation and invariant generation.
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client or MockLLMClient()
        
        # Load prompt templates
        self.logic_synthesis_prompt = self._load_logic_synthesis_prompt()
        self.invariant_generation_prompt = self._load_invariant_generation_prompt()
        self.poc_generation_prompt = self._load_poc_generation_prompt()
    
    def enhance_findings(
        self, 
        findings: List[Finding], 
        context: ScanContext
    ) -> List[Finding]:
        """
        Enhance findings with LLM-generated remediation and invariant suggestions.
        
        Args:
            findings: List of findings to enhance
            context: Scan context with contract information
            
        Returns:
            Enhanced findings with LLM-generated content
        """
        enhanced = []
        
        for finding in findings:
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