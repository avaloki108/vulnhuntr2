"""
Enhanced orchestrator with intelligent cross-contract analysis and Ollama integration.
Provides holistic vulnerability analysis that understands contract relationships.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

from .orchestrator import Orchestrator
from .models import Finding, ScanContext, Severity
from .contract_graph import ContractGraphBuilder, ContractGraph
from .llm_synthesis import LLMSynthesisEngine
from .ollama_client import OllamaClient, OllamaConfig
from ..config.settings import Settings

logger = logging.getLogger(__name__)


class EnhancedVulnHuntrOrchestrator(Orchestrator):

    def elite_scan_contracts(
        self,
        contract_paths: List[Path],
        scan_context: Optional[ScanContext] = None
    ) -> Dict[str, Any]:
        """
        ELITE multi-phase, multi-agent, adversarial-validated scan as per elite-web3-audit.md.
        """
        logger.info("[ELITE] Starting elite multi-phase scan...")
        results = {"findings": [], "phases": {}}

        # Phase 1: Recon & Protocol Classification
        try:
            recon_prompt = """
You are a supreme Web3 security auditor. Map the contract architecture, inheritance, privilege boundaries, and protocol type (DEX, lending, bridge, etc). Identify protocol-specific risks and unique attack surfaces. Output a JSON summary with protocol_type, key_contracts, privilege_boundaries, and unique_risks."""
            recon_input = "\n".join([p.read_text() for p in contract_paths if p.exists()])[:16000]
            recon_result = self.enhanced_llm_engine.llm_client.chat(recon_prompt + "\n" + recon_input)
            results["phases"]["recon"] = recon_result
        except Exception as e:
            logger.error(f"[ELITE] Recon phase failed: {e}")

        # Phase 2: Multi-Agent Vulnerability Reasoning
        agent_types = [
            ("reentrancy", "Find all reentrancy vulnerabilities and explain attack logic."),
            ("access_control", "Find all access control bypasses and privilege escalations."),
            ("math", "Find all mathematical vulnerabilities, overflows, underflows, rounding errors."),
            ("oracle", "Find all oracle manipulation and price feed vulnerabilities."),
            ("flash_loan", "Find all flash loan attack combinations and economic exploits."),
            ("mev", "Find all MEV extraction opportunities and sandwich/frontrun attacks."),
            ("storage", "Find all storage layout, proxy, and delegatecall vulnerabilities."),
            ("signature", "Find all signature replay, malleability, and permit vulnerabilities."),
            ("edge_case", "Find all edge case, boundary, and DoS vulnerabilities."),
            ("novel_attack", "Invent novel, multi-step, cross-contract attack chains.")
        ]
        agent_findings = []
        for agent, prompt in agent_types:
            try:
                agent_prompt = f"[AGENT: {agent.upper()}] {prompt} For each finding, explain the logic, impact, and exploitation method. Output JSON list."
                agent_input = "\n".join([p.read_text() for p in contract_paths if p.exists()])[:16000]
                agent_result = self.enhanced_llm_engine.llm_client.chat(agent_prompt + "\n" + agent_input)
                results["phases"][agent] = agent_result
                # Try to parse findings if JSON
                import json
                try:
                    parsed = json.loads(agent_result)
                    if isinstance(parsed, list):
                        agent_findings.extend(parsed)
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"[ELITE] Agent {agent} failed: {e}")

        # Phase 3: Aggregate, Deduplicate, and Enhance Findings
        # (Could use LLM for deduplication, here just aggregate for now)
        results["findings"] = agent_findings

        # Phase 4: Adversarial Validation
        validated_findings = []
        for finding in agent_findings:
            try:
                disproval_prompt = f"[VALIDATION] For the following finding, attempt to disprove it using all available code and logic. If it is protected, uneconomical, impossible, or logically flawed, explain why. Otherwise, validate it. Output JSON with status (VALID/INVALID) and reasoning.\nFinding: {finding}"
                disproval_result = self.enhanced_llm_engine.llm_client.chat(disproval_prompt)
                import json
                try:
                    disproval = json.loads(disproval_result)
                    if disproval.get("status", "VALID").upper() == "VALID":
                        finding["validation"] = disproval
                        validated_findings.append(finding)
                except Exception:
                    # If not JSON, accept if not disproved
                    if "invalid" not in disproval_result.lower():
                        finding["validation"] = disproval_result
                        validated_findings.append(finding)
            except Exception as e:
                logger.error(f"[ELITE] Validation failed: {e}")

        results["findings"] = validated_findings

        # Phase 5: Scoring and Report Generation
        elite_reports = []
        for finding in validated_findings:
            try:
                scoring_prompt = f"[SCORING] Score the following finding for Novelty, Exploitability, and Impact (1-10 each), then compute Total = Novelty*Exploitability*Impact. Output JSON with all scores and a short justification.\nFinding: {finding}"
                scoring_result = self.enhanced_llm_engine.llm_client.chat(scoring_prompt)
                import json
                try:
                    scores = json.loads(scoring_result)
                    finding["scores"] = scores
                    if scores.get("Total", 0) >= 200:
                        elite_reports.append(finding)
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"[ELITE] Scoring failed: {e}")

        results["elite_reports"] = elite_reports

        # Phase 6: Professional Report Generation
        reports = []
        for finding in elite_reports:
            try:
                report_prompt = f"[REPORT] Generate a professional bug bounty report for the following validated, high-scoring vulnerability, following the elite-web3-audit.md template.\nFinding: {finding}"
                report = self.enhanced_llm_engine.llm_client.chat(report_prompt)
                finding["report"] = report
                reports.append(report)
            except Exception as e:
                logger.error(f"[ELITE] Report generation failed: {e}")

        results["reports"] = reports
        logger.info(f"[ELITE] Elite scan complete. {len(reports)} high-value reports generated.")
        return results
    """
    Enhanced orchestrator with holistic contract analysis capabilities.

    Features:
    - Cross-contract vulnerability detection
    - Ollama-powered deep analysis
    - Contract relationship mapping
    - Economic impact assessment
    - Novel attack vector discovery
    """

    def __init__(self, settings: Settings):
        super().__init__(settings)

        self.contract_graph: Optional[ContractGraph] = None
        self.contract_graph_builder = ContractGraphBuilder()
        self.enhanced_llm_engine: Optional[LLMSynthesisEngine] = None
        self.cross_contract_enabled = settings.cross_contract.enabled

        # Initialize enhanced LLM engine with Ollama support
        self._initialize_enhanced_llm(settings)

    def _initialize_enhanced_llm(self, settings: Settings) -> None:
        """Initialize enhanced LLM engine with Ollama support."""
        try:
            ollama_config = None
            if settings.ollama.enabled:
                ollama_config = OllamaConfig(
                    model=settings.ollama.model,
                    base_url=settings.ollama.base_url,
                    timeout=settings.ollama.timeout,
                    temperature=settings.ollama.temperature,
                    top_p=settings.ollama.top_p,
                    max_tokens=settings.ollama.max_tokens,
                    stream=settings.ollama.stream,
                    keep_alive=settings.ollama.keep_alive
                )

            self.enhanced_llm_engine = LLMSynthesisEngine(
                llm_client=None,  # Will use mock for traditional LLM
                ollama_config=ollama_config
            )

            if ollama_config and self.enhanced_llm_engine.ollama_client:
                if self.enhanced_llm_engine.ollama_client.is_available():
                    logger.info(f"Enhanced orchestrator initialized with Ollama model: {settings.ollama.model}")
                else:
                    logger.warning("Ollama client initialized but not available")

        except Exception as e:
            logger.error(f"Failed to initialize enhanced LLM engine: {e}")
            self.enhanced_llm_engine = None

    def scan_contracts(
        self,
        contract_paths: List[Path],
        scan_context: Optional[ScanContext] = None
    ) -> Dict[str, Any]:
        """
        Enhanced contract scanning with cross-contract analysis.

        Args:
            contract_paths: List of contract file paths
            scan_context: Optional scan context

        Returns:
            Enhanced scan results with cross-contract insights
        """
        # Step 1: Build contract relationship graph
        logger.info("Building contract relationship graph...")
        try:
            self.contract_graph = self.contract_graph_builder.analyze_project(contract_paths)

            if self.enhanced_llm_engine:
                self.enhanced_llm_engine.contract_graph = self.contract_graph

            logger.info(f"Built contract graph with {len(self.contract_graph.contracts)} contracts")

        except Exception as e:
            logger.error(f"Failed to build contract graph: {e}")
            self.contract_graph = None

        # Step 2: Perform standard vulnerability scanning
        logger.info("Performing standard vulnerability scanning...")

        # Run standard detection on all files
        all_findings = []
        results_dict = {'findings': []}

        try:
            # Determine target directory
            if len(contract_paths) == 1 and contract_paths[0].is_file():
                target_path = contract_paths[0].parent
            else:
                # Find common parent directory
                target_path = Path(os.path.commonpath(contract_paths))

            # Run base orchestrator
            raw_findings = self.run(target_path)

            # Convert findings to Finding objects if they aren't already
            for finding_data in raw_findings:
                if isinstance(finding_data, dict):
                    # Create Finding object from dict
                    finding = Finding(
                        detector=finding_data.get('detector', 'unknown'),
                        title=finding_data.get('title', 'Unknown vulnerability'),
                        description=finding_data.get('description', ''),
                        severity=self._parse_severity(finding_data.get('severity', 'MEDIUM')),
                        confidence=finding_data.get('confidence', 0.5),
                        file_path=finding_data.get('file', ''),
                        line=finding_data.get('line', 0),
                        code=finding_data.get('code', ''),
                        category=finding_data.get('category', 'unknown'),
                        contract_name=finding_data.get('contract_name', None),
                        function_name=finding_data.get('function_name', None)
                    )
                    all_findings.append(finding)
                else:
                    all_findings.append(finding_data)

            results_dict['findings'] = all_findings

        except Exception as e:
            logger.error(f"Error in standard vulnerability scanning: {e}")
            results_dict['findings'] = []

        # Step 3: Enhance findings with cross-contract analysis
        if self.cross_contract_enabled and self.contract_graph and self.enhanced_llm_engine:
            logger.info("Performing cross-contract vulnerability analysis...")
            results_dict = self._enhance_with_cross_contract_analysis(results_dict)

        # Step 4: Identify critical contract interactions
        if self.contract_graph:
            results_dict['contract_analysis'] = self._analyze_contract_ecosystem()

        return results_dict

    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
        try:
            return getattr(Severity, severity_str.upper())
        except (AttributeError, TypeError):
            return Severity.MEDIUM

    def _enhance_with_cross_contract_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance scan results with cross-contract vulnerability analysis."""
        try:
            # Get all contract names from findings
            involved_contracts = set()
            for finding in scan_results.get('findings', []):
                if finding.contract_name:
                    involved_contracts.add(finding.contract_name)

            # Add critical contracts from graph analysis
            critical_contracts = self.contract_graph.get_critical_contracts()
            involved_contracts.update(critical_contracts)

            # Limit analysis scope to prevent overwhelming the LLM
            max_contracts = getattr(self.settings.cross_contract, 'max_contracts_per_analysis', 10)
            target_contracts = list(involved_contracts)[:max_contracts]

            if target_contracts:
                logger.info(f"Analyzing cross-contract logic for {len(target_contracts)} contracts")

                # Perform cross-contract analysis
                cross_analysis = self.enhanced_llm_engine.analyze_cross_contract_vulnerabilities(
                    target_contracts
                )

                if cross_analysis and not cross_analysis.get('error'):
                    scan_results['cross_contract_analysis'] = cross_analysis

                    # Convert critical findings to Finding objects
                    cross_contract_findings = self._convert_cross_contract_findings(
                        cross_analysis.get('critical_findings', [])
                    )

                    # Add to main findings list
                    scan_results.setdefault('findings', []).extend(cross_contract_findings)

                    logger.info(f"Found {len(cross_contract_findings)} cross-contract vulnerabilities")

        except Exception as e:
            logger.error(f"Error in cross-contract analysis: {e}")

        return scan_results

    def _convert_cross_contract_findings(self, critical_findings: List[Dict[str, Any]]) -> List[Finding]:
        """Convert cross-contract analysis results to Finding objects."""
        findings = []

        for cf in critical_findings:
            try:
                # Parse severity
                severity_str = cf.get('severity', 'MEDIUM').upper()
                severity = getattr(Severity, severity_str, Severity.MEDIUM)

                finding = Finding(
                    detector="cross_contract_analyzer",
                    title=cf.get('title', 'Cross-Contract Vulnerability'),
                    description=cf.get('description', ''),
                    severity=severity,
                    confidence=0.8,  # Default confidence for cross-contract findings
                    file_path="multiple_contracts",  # Spans multiple contracts
                    line=1,
                    code=cf.get('proof_of_concept', ''),
                    category="cross_contract",
                    contract_name=",".join(cf.get('affected_contracts', [])),
                    function_name="multiple_functions",
                    remediation=cf.get('remediation', ''),
                    metadata={
                        'cross_contract': True,
                        'affected_contracts': cf.get('affected_contracts', []),
                        'attack_vector': cf.get('attack_vector', ''),
                        'economic_impact': cf.get('economic_impact', ''),
                        'poc': cf.get('proof_of_concept', '')
                    }
                )

                findings.append(finding)

            except Exception as e:
                logger.error(f"Error converting cross-contract finding: {e}")
                continue

        return findings

    def _analyze_contract_ecosystem(self) -> Dict[str, Any]:
        """Analyze the contract ecosystem for insights."""
        if not self.contract_graph:
            return {}

        analysis = {
            'total_contracts': len(self.contract_graph.contracts),
            'interaction_summary': self.contract_graph.get_interaction_summary(),
            'critical_contracts': self.contract_graph.get_critical_contracts(),
            'proxy_analysis': self.contract_graph.analyze_proxy_patterns(),
            'risk_assessment': self._assess_ecosystem_risks()
        }

        return analysis

    def _assess_ecosystem_risks(self) -> Dict[str, Any]:
        """Assess risks in the contract ecosystem."""
        if not self.contract_graph:
            return {}

        risks = {
            'high_dependency_contracts': [],
            'proxy_upgrade_risks': [],
            'cross_contract_call_risks': [],
            'centralization_risks': []
        }

        # Identify contracts with many dependencies
        for name, contract in self.contract_graph.contracts.items():
            dependency_count = len(self.contract_graph.get_dependencies(name))
            dependent_count = len(self.contract_graph.get_dependents(name))

            if dependency_count > 5:
                risks['high_dependency_contracts'].append({
                    'contract': name,
                    'dependency_count': dependency_count,
                    'risk': 'High complexity due to many dependencies'
                })

            if dependent_count > 5:
                risks['centralization_risks'].append({
                    'contract': name,
                    'dependent_count': dependent_count,
                    'risk': 'Single point of failure - many contracts depend on this'
                })

        # Analyze proxy patterns for upgrade risks
        proxy_patterns = self.contract_graph.analyze_proxy_patterns()
        for proxy in proxy_patterns.get('proxy_contracts', []):
            risks['proxy_upgrade_risks'].append({
                'proxy': proxy,
                'risk': 'Upgrade mechanism may introduce vulnerabilities'
            })

        # Analyze external call patterns
        external_call_count = 0
        for relation in self.contract_graph.relations:
            if relation.relation_type.value == 'external_call':
                external_call_count += 1

        if external_call_count > 10:
            risks['cross_contract_call_risks'].append({
                'total_external_calls': external_call_count,
                'risk': 'High number of cross-contract calls increases attack surface'
            })

        return risks

    def enhanced_analyze_finding(self, finding: Finding, context: ScanContext) -> Finding:
        """
        Perform enhanced analysis of a single finding using holistic context.

        Args:
            finding: Individual finding to analyze
            context: Scan context

        Returns:
            Enhanced finding with cross-contract insights
        """
        if not self.enhanced_llm_engine:
            return finding

        try:
            # Use enhanced LLM engine for holistic analysis
            enhanced_findings = self.enhanced_llm_engine.enhance_findings([finding], context)
            return enhanced_findings[0] if enhanced_findings else finding

        except Exception as e:
            logger.error(f"Error in enhanced finding analysis: {e}")
            return finding

    def get_ecosystem_summary(self) -> Dict[str, Any]:
        """Get a comprehensive summary of the contract ecosystem."""
        if not self.contract_graph:
            return {"error": "Contract graph not available"}

        summary = {
            'contracts': {
                'total': len(self.contract_graph.contracts),
                'by_type': {
                    'standard': len([c for c in self.contract_graph.contracts.values()
                                   if not c.is_interface and not c.is_library and not c.is_proxy]),
                    'interfaces': len([c for c in self.contract_graph.contracts.values() if c.is_interface]),
                    'libraries': len([c for c in self.contract_graph.contracts.values() if c.is_library]),
                    'proxies': len([c for c in self.contract_graph.contracts.values() if c.is_proxy])
                }
            },
            'relationships': {
                'total': len(self.contract_graph.relations),
                'by_type': {}
            },
            'critical_contracts': self.contract_graph.get_critical_contracts(),
            'proxy_analysis': self.contract_graph.analyze_proxy_patterns(),
            'risk_factors': self._assess_ecosystem_risks()
        }

        # Count relationships by type
        for relation in self.contract_graph.relations:
            rel_type = relation.relation_type.value
            summary['relationships']['by_type'][rel_type] = \
                summary['relationships']['by_type'].get(rel_type, 0) + 1

        return summary

    def suggest_ollama_model(self) -> str:
        """Suggest optimal Ollama model for smart contract analysis."""
        recommendations = {
            'best_overall': 'qwen2.5-coder:32b',
            'alternatives': [
                'codellama:34b',
                'deepseek-coder:33b',
                'starcoder2:15b',
                'codegemma:7b'
            ],
            'reasoning': {
                'qwen2.5-coder:32b': 'Excellent code understanding and reasoning, good for security analysis',
                'codellama:34b': 'Strong code analysis, good for vulnerability detection',
                'deepseek-coder:33b': 'Good balance of size and performance for code tasks',
                'starcoder2:15b': 'Lighter weight option, still good for basic analysis',
                'codegemma:7b': 'Smallest option for resource-constrained environments'
            }
        }

        return recommendations