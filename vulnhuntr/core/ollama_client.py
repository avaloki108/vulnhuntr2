"""
Ollama client for local LLM inference with sophisticated smart contract analysis.
Provides holistic contract analysis with cross-contract reasoning capabilities.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Optional, Any, Union, Generator
from dataclasses import dataclass

try:
    import ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False

from .models import Finding, ScanContext
from .contract_graph import ContractGraph, ContractNode


logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    """Configuration for Ollama client."""
    model: str = "foundation"  # Force to foundation model
    base_url: str = "http://localhost:11434"
    timeout: int = 120
    temperature: float = 0.1  # Low for consistent analysis
    top_p: float = 0.9
    max_tokens: int = 4096
    stream: bool = False
    keep_alive: str = "5m"


class OllamaClient:
    """
    Advanced Ollama client for smart contract vulnerability analysis.
    Provides holistic reasoning about contract interactions and logic flows.
    """

    def __init__(self, config: OllamaConfig):
        # Always force model to 'foundation' regardless of config
        config.model = "foundation"
        self.config = config
        self.client = None
        self._model_available = False

        if not HAS_OLLAMA:
            logger.warning("Ollama package not installed. Install with: pip install ollama")
            return

        try:
            self.client = ollama.Client(host=config.base_url)
            self._check_model_availability()
        except Exception as e:
            logger.error(f"Failed to initialize Ollama client: {e}")

    def _check_model_availability(self) -> bool:
        """Check if the specified model is available."""
        if not self.client:
            return False

        try:
            models = self.client.list()
            model_names = [model['name'] for model in models.get('models', [])]

            if self.config.model in model_names:
                self._model_available = True
                logger.info(f"Model {self.config.model} is available")
                return True
            else:
                logger.warning(f"Model {self.config.model} not found. Available models: {model_names}")

                # Try to pull the model
                if ':' in self.config.model:  # Has tag
                    logger.info(f"Attempting to pull model {self.config.model}")
                    try:
                        self.client.pull(self.config.model)
                        self._model_available = True
                        logger.info(f"Successfully pulled model {self.config.model}")
                        return True
                    except Exception as e:
                        logger.error(f"Failed to pull model {self.config.model}: {e}")

                return False

        except Exception as e:
            logger.error(f"Error checking model availability: {e}")
            return False

    def is_available(self) -> bool:
        """Check if Ollama client is ready for use."""
        return self.client is not None and self._model_available

    def chat(self, prompt: str, system_prompt: Optional[str] = None, **kwargs) -> str:
        """
        Send a chat request to Ollama.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context
            **kwargs: Additional parameters for the chat request

        Returns:
            Model response text
        """
        if not self.is_available():
            raise RuntimeError("Ollama client not available")

        messages = []
        if system_prompt:
            messages.append({
                'role': 'system',
                'content': system_prompt
            })

        messages.append({
            'role': 'user',
            'content': prompt
        })

        try:
            response = self.client.chat(
                model=self.config.model,
                messages=messages,
                options={
                    'temperature': kwargs.get('temperature', self.config.temperature),
                    'top_p': kwargs.get('top_p', self.config.top_p),
                    'num_predict': kwargs.get('max_tokens', self.config.max_tokens),
                },
                stream=kwargs.get('stream', self.config.stream),
                keep_alive=self.config.keep_alive
            )

            if self.config.stream:
                return self._handle_streaming_response(response)
            else:
                return response['message']['content']

        except Exception as e:
            logger.error(f"Error in Ollama chat request: {e}")
            raise

    def _handle_streaming_response(self, response_stream) -> str:
        """Handle streaming response from Ollama."""
        full_response = ""
        try:
            for chunk in response_stream:
                if 'message' in chunk and 'content' in chunk['message']:
                    full_response += chunk['message']['content']
            return full_response
        except Exception as e:
            logger.error(f"Error handling streaming response: {e}")
            return full_response

    def analyze_vulnerability_holistically(
        self,
        finding: Finding,
        contract_graph: ContractGraph,
        context: ScanContext
    ) -> Dict[str, Any]:
        """
        Perform holistic vulnerability analysis using the full contract graph.

        Args:
            finding: Individual vulnerability finding
            contract_graph: Complete contract relationship graph
            context: Scan context

        Returns:
            Enhanced analysis with cross-contract insights
        """
        if not self.is_available():
            logger.warning("Ollama not available, returning basic analysis")
            return self._fallback_analysis(finding)

        # Build comprehensive context
        analysis_context = self._build_analysis_context(finding, contract_graph, context)

        # Create sophisticated system prompt
        system_prompt = self._create_holistic_system_prompt()

        # Create detailed analysis prompt
        analysis_prompt = self._create_holistic_analysis_prompt(
            finding, analysis_context, contract_graph
        )

        try:
            response = self.chat(analysis_prompt, system_prompt)

            # Try to parse JSON response
            if response.strip().startswith('{'):
                return json.loads(response)
            else:
                # Fallback to structured parsing
                return self._parse_text_response(response, finding)

        except Exception as e:
            logger.error(f"Error in holistic analysis: {e}")
            return self._fallback_analysis(finding)

    def analyze_cross_contract_logic(
        self,
        contract_graph: ContractGraph,
        target_contracts: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze logic flows across multiple contracts to find complex vulnerabilities.

        Args:
            contract_graph: Complete contract relationship graph
            target_contracts: List of contract names to focus analysis on

        Returns:
            Cross-contract vulnerability analysis
        """
        if not self.is_available():
            return {"error": "Ollama not available"}

        # Build cross-contract analysis context
        cross_context = self._build_cross_contract_context(contract_graph, target_contracts)

        system_prompt = self._create_cross_contract_system_prompt()
        analysis_prompt = self._create_cross_contract_analysis_prompt(cross_context)

        try:
            response = self.chat(analysis_prompt, system_prompt, max_tokens=6144)

            if response.strip().startswith('{'):
                return json.loads(response)
            else:
                return self._parse_cross_contract_response(response)

        except Exception as e:
            logger.error(f"Error in cross-contract analysis: {e}")
            return {"error": str(e)}

    def _build_analysis_context(
        self,
        finding: Finding,
        contract_graph: ContractGraph,
        context: ScanContext
    ) -> Dict[str, Any]:
        """Build comprehensive context for analysis."""

        contract_name = finding.contract_name or "Unknown"

        # Get contract relationships
        dependencies = contract_graph.get_dependencies(contract_name)
        dependents = contract_graph.get_dependents(contract_name)

        # Get contract details
        contract_info = contract_graph.contracts.get(contract_name)

        analysis_context = {
            'target_contract': {
                'name': contract_name,
                'functions': contract_info.functions if contract_info else [],
                'state_variables': contract_info.state_variables if contract_info else [],
                'is_proxy': contract_info.is_proxy if contract_info else False,
                'is_library': contract_info.is_library if contract_info else False
            },
            'dependencies': dependencies,
            'dependents': dependents,
            'interaction_summary': contract_graph.get_interaction_summary(),
            'critical_contracts': contract_graph.get_critical_contracts(),
            'proxy_analysis': contract_graph.analyze_proxy_patterns(),
            'vulnerability_context': {
                'detector': finding.detector,
                'category': finding.category,
                'severity': finding.severity.value,
                'line': finding.line,
                'function': finding.function_name
            }
        }

        return analysis_context

    def _build_cross_contract_context(
        self,
        contract_graph: ContractGraph,
        target_contracts: List[str]
    ) -> Dict[str, Any]:
        """Build context for cross-contract analysis."""

        context = {
            'target_contracts': [],
            'relationships': [],
            'call_chains': [],
            'proxy_patterns': contract_graph.analyze_proxy_patterns(),
            'critical_contracts': contract_graph.get_critical_contracts()
        }

        # Add detailed contract information
        for contract_name in target_contracts:
            if contract_name in contract_graph.contracts:
                contract = contract_graph.contracts[contract_name]
                context['target_contracts'].append({
                    'name': contract_name,
                    'functions': contract.functions,
                    'state_variables': contract.state_variables,
                    'modifiers': contract.modifiers,
                    'events': contract.events,
                    'is_proxy': contract.is_proxy,
                    'is_library': contract.is_library,
                    'dependencies': contract_graph.get_dependencies(contract_name),
                    'dependents': contract_graph.get_dependents(contract_name)
                })

        # Add relationships between target contracts
        for relation in contract_graph.relations:
            if (relation.from_contract in target_contracts or
                relation.to_contract in target_contracts):
                context['relationships'].append({
                    'from': relation.from_contract,
                    'to': relation.to_contract,
                    'type': relation.relation_type.value,
                    'details': relation.details,
                    'confidence': relation.confidence
                })

        # Add call chains between contracts
        for i, contract1 in enumerate(target_contracts):
            for contract2 in target_contracts[i+1:]:
                chain = contract_graph.get_call_chain(contract1, contract2)
                if chain:
                    context['call_chains'].append({
                        'from': contract1,
                        'to': contract2,
                        'path': chain
                    })

        return context

    def _create_holistic_system_prompt(self) -> str:
        """Create system prompt for holistic vulnerability analysis."""
        return """You are an expert smart contract security auditor with deep knowledge of Solidity, DeFi protocols, and complex cross-contract interactions. Your task is to perform comprehensive vulnerability analysis that goes beyond surface-level pattern matching.

Key Analysis Principles:
1. Consider the entire contract ecosystem, not just individual contracts
2. Analyze how vulnerabilities can be chained across contract boundaries
3. Focus on business logic flaws and economic attack vectors
4. Consider proxy patterns, upgrade mechanisms, and state dependencies
5. Evaluate real-world exploitability and economic impact
6. Think like an attacker looking for novel, high-impact vulnerabilities

Your analysis should identify:
- Cross-contract logic bugs and state inconsistencies
- Economic attack vectors (MEV, flash loans, oracle manipulation)
- Upgrade and proxy-related vulnerabilities
- Access control bypasses through contract interactions
- Reentrancy and callback vulnerabilities across contracts
- Novel attack patterns that combine multiple vulnerabilities

Always provide structured, actionable analysis with clear explanation of attack vectors and potential impact. Focus on findings that would be valuable for bug bounty programs."""

    def _create_holistic_analysis_prompt(
        self,
        finding: Finding,
        analysis_context: Dict[str, Any],
        contract_graph: ContractGraph
    ) -> str:
        """Create detailed prompt for holistic vulnerability analysis."""

        prompt = f"""
VULNERABILITY ANALYSIS REQUEST

Primary Finding:
- Detector: {finding.detector}
- Title: {finding.title}
- Severity: {finding.severity.value}
- Category: {finding.category}
- Location: {finding.contract_name}:{finding.line} in {finding.function_name}()
- Code: {finding.code}

Contract Ecosystem Context:
- Target Contract: {analysis_context['target_contract']['name']}
- Dependencies: {', '.join(analysis_context['dependencies'])}
- Dependents: {', '.join(analysis_context['dependents'])}
- Contract Type: {'Proxy' if analysis_context['target_contract']['is_proxy'] else 'Library' if analysis_context['target_contract']['is_library'] else 'Standard'}

Critical Infrastructure:
- Critical Contracts: {', '.join(analysis_context['critical_contracts'])}
- Proxy Patterns: {analysis_context['proxy_analysis']}

ANALYSIS REQUIREMENTS:

1. HOLISTIC IMPACT ASSESSMENT
   - How does this vulnerability affect the broader contract ecosystem?
   - What contracts could be impacted through dependencies/interactions?
   - Can this be chained with other contracts for amplified impact?

2. CROSS-CONTRACT ATTACK VECTORS
   - How could an attacker exploit this across contract boundaries?
   - What external contracts could be manipulated to trigger this?
   - Are there proxy upgrade paths that could worsen this vulnerability?

3. ECONOMIC EXPLOIT ANALYSIS
   - What is the realistic economic impact and profit potential?
   - How much capital would an attacker need?
   - What are the gas costs vs potential profit?

4. NOVEL ATTACK PATTERNS
   - Does this enable any novel or creative attack vectors?
   - How could this be combined with flash loans, MEV, or oracle manipulation?
   - Are there state dependency issues across contracts?

5. REMEDIATION STRATEGY
   - How should this be fixed considering the contract ecosystem?
   - What safeguards are needed in dependent contracts?
   - Should upgrade mechanisms be modified?

Provide your analysis as a JSON object with the following structure:
{{
    "holistic_impact": {{
        "severity_adjustment": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
        "ecosystem_risk": "Description of ecosystem-wide risk",
        "affected_contracts": ["list", "of", "contracts"],
        "amplification_factor": "How much worse this is in context"
    }},
    "attack_vectors": {{
        "cross_contract_exploits": ["List of cross-contract attack methods"],
        "economic_exploits": ["List of economic attack vectors"],
        "novel_techniques": ["Creative/novel attack approaches"]
    }},
    "economic_analysis": {{
        "max_extractable_value": "Estimated maximum value at risk",
        "attack_cost": "Capital required for exploitation",
        "profitability_ratio": "Expected profit vs cost ratio",
        "gas_considerations": "Gas cost analysis"
    }},
    "remediation": {{
        "immediate_fixes": ["Critical fixes needed now"],
        "ecosystem_changes": ["Changes needed in other contracts"],
        "upgrade_considerations": ["Upgrade mechanism modifications"]
    }},
    "confidence": 0.95,
    "reasoning": "Detailed explanation of analysis and conclusions"
}}
"""
        return prompt

    def _create_cross_contract_system_prompt(self) -> str:
        """Create system prompt for cross-contract analysis."""
        return """You are an expert smart contract security researcher specializing in complex, multi-contract vulnerability analysis. You excel at identifying logic bugs that span multiple contracts and finding novel attack vectors that exploit contract interactions.

Your expertise includes:
- DeFi protocol architecture and common interaction patterns
- Proxy patterns, upgrades, and delegatecall security
- Flash loan attacks and MEV extraction techniques
- Oracle manipulation and price discovery vulnerabilities
- Cross-chain bridge security and replay attacks
- Token standard vulnerabilities and economic exploits

Focus on finding vulnerabilities that:
1. Require interaction between multiple contracts to exploit
2. Exploit business logic flaws rather than simple coding errors
3. Have significant economic impact and realistic exploitability
4. Represent novel or creative attack vectors
5. Could result in substantial bug bounty rewards ($10k+)

Provide actionable, technically sound analysis with clear exploit paths and impact assessment."""

    def _create_cross_contract_analysis_prompt(self, cross_context: Dict[str, Any]) -> str:
        """Create prompt for cross-contract logic analysis."""

        contracts_summary = ""
        for contract in cross_context['target_contracts']:
            contracts_summary += f"""
Contract: {contract['name']}
- Type: {'Proxy' if contract['is_proxy'] else 'Library' if contract['is_library'] else 'Standard'}
- Functions: {', '.join(contract['functions'][:10])}{'...' if len(contract['functions']) > 10 else ''}
- State Variables: {', '.join(contract['state_variables'][:10])}{'...' if len(contract['state_variables']) > 10 else ''}
- Dependencies: {', '.join(contract['dependencies'])}
- Dependents: {', '.join(contract['dependents'])}
"""

        relationships_summary = ""
        for rel in cross_context['relationships']:
            relationships_summary += f"- {rel['from']} --{rel['type']}--> {rel['to']} (confidence: {rel['confidence']})\n"

        call_chains_summary = ""
        for chain in cross_context['call_chains']:
            call_chains_summary += f"- {' -> '.join(chain['path'])}\n"

        prompt = f"""
CROSS-CONTRACT VULNERABILITY ANALYSIS

CONTRACT ECOSYSTEM:
{contracts_summary}

RELATIONSHIPS:
{relationships_summary}

CALL CHAINS:
{call_chains_summary}

PROXY ANALYSIS:
{json.dumps(cross_context['proxy_patterns'], indent=2)}

CRITICAL INFRASTRUCTURE:
- Critical Contracts: {', '.join(cross_context['critical_contracts'])}

ANALYSIS REQUIREMENTS:

1. LOGIC FLOW ANALYSIS
   - Trace critical data flows between contracts
   - Identify state consistency requirements across contracts
   - Find logic gaps or assumptions that could be violated

2. INTERACTION VULNERABILITY ASSESSMENT
   - Analyze contract interaction patterns for attack vectors
   - Identify reentrancy opportunities across contract boundaries
   - Find access control bypasses through contract delegation

3. ECONOMIC ATTACK MODELING
   - Model potential MEV extraction opportunities
   - Analyze flash loan attack possibilities
   - Identify oracle manipulation attack vectors

4. PROXY/UPGRADE VULNERABILITY ANALYSIS
   - Analyze upgrade mechanisms for bypass opportunities
   - Check for storage collision vulnerabilities
   - Identify delegatecall misuse patterns

5. NOVEL ATTACK VECTOR DISCOVERY
   - Look for creative ways to chain vulnerabilities
   - Identify business logic exploits unique to this architecture
   - Find edge cases in multi-contract workflows

Provide comprehensive analysis as JSON:
{{
    "critical_findings": [
        {{
            "title": "Finding title",
            "description": "Detailed description",
            "affected_contracts": ["contract1", "contract2"],
            "attack_vector": "Step-by-step attack description",
            "economic_impact": "Estimated financial impact",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "proof_of_concept": "High-level PoC description",
            "remediation": "How to fix this issue"
        }}
    ],
    "interaction_risks": [
        {{
            "interaction_type": "Type of risky interaction",
            "contracts": ["involved", "contracts"],
            "risk_description": "What could go wrong",
            "mitigation": "How to mitigate"
        }}
    ],
    "architectural_issues": [
        {{
            "issue": "Architectural problem description",
            "impact": "Potential impact",
            "recommendation": "Suggested improvement"
        }}
    ],
    "economic_analysis": {{
        "max_extractable_value": "Estimate of max MEV",
        "attack_scenarios": ["List of economic attack scenarios"],
        "profitability_assessment": "Is this economically viable to exploit?"
    }},
    "confidence": 0.85,
    "summary": "High-level summary of findings and risk assessment"
}}
"""
        return prompt

    def _parse_text_response(self, response: str, finding: Finding) -> Dict[str, Any]:
        """Parse non-JSON response into structured format."""
        return {
            "holistic_impact": {
                "severity_adjustment": finding.severity.value,
                "ecosystem_risk": "Analysis requires manual review",
                "affected_contracts": [finding.contract_name] if finding.contract_name else [],
                "amplification_factor": "Unable to determine automatically"
            },
            "attack_vectors": {
                "cross_contract_exploits": ["Manual analysis required"],
                "economic_exploits": ["Manual analysis required"],
                "novel_techniques": ["Manual analysis required"]
            },
            "economic_analysis": {
                "max_extractable_value": "Unknown",
                "attack_cost": "Unknown",
                "profitability_ratio": "Unknown",
                "gas_considerations": "Unknown"
            },
            "remediation": {
                "immediate_fixes": ["Review LLM response manually"],
                "ecosystem_changes": ["Manual analysis required"],
                "upgrade_considerations": ["Manual analysis required"]
            },
            "confidence": 0.3,
            "reasoning": response[:1000],  # Truncate long responses
            "raw_response": response
        }

    def _parse_cross_contract_response(self, response: str) -> Dict[str, Any]:
        """Parse cross-contract analysis response."""
        return {
            "critical_findings": [],
            "interaction_risks": [],
            "architectural_issues": [],
            "economic_analysis": {
                "max_extractable_value": "Manual analysis required",
                "attack_scenarios": [],
                "profitability_assessment": "Unknown"
            },
            "confidence": 0.3,
            "summary": response[:500],
            "raw_response": response
        }

    def _fallback_analysis(self, finding: Finding) -> Dict[str, Any]:
        """Provide fallback analysis when Ollama is unavailable."""
        return {
            "holistic_impact": {
                "severity_adjustment": finding.severity.value,
                "ecosystem_risk": "Ollama unavailable - basic analysis only",
                "affected_contracts": [finding.contract_name] if finding.contract_name else [],
                "amplification_factor": "Unknown - requires LLM analysis"
            },
            "attack_vectors": {
                "cross_contract_exploits": ["Requires LLM analysis"],
                "economic_exploits": ["Requires LLM analysis"],
                "novel_techniques": ["Requires LLM analysis"]
            },
            "economic_analysis": {
                "max_extractable_value": "Unknown",
                "attack_cost": "Unknown",
                "profitability_ratio": "Unknown",
                "gas_considerations": "Unknown"
            },
            "remediation": {
                "immediate_fixes": [f"Review {finding.detector} finding manually"],
                "ecosystem_changes": ["Manual analysis required"],
                "upgrade_considerations": ["Manual analysis required"]
            },
            "confidence": 0.1,
            "reasoning": "Ollama client unavailable - using fallback analysis",
            "error": "Ollama not available"
        }