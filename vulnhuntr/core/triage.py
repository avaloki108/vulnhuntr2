"""
AI/LLM Triage Layer for vulnhuntr2 Phase 5.
Provides intelligent triage and risk assessment of findings.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import json
import hashlib
import logging
import time
from datetime import datetime, timezone

from ..core.models import Finding, ScanContext, Severity
from ..config.schema import TriageConfig


@dataclass
class TriageResult:
    """Result of AI triage analysis."""
    
    risk_summary: str
    exploit_hypothesis: str
    remediation_actions: List[str] = field(default_factory=list)
    false_positive_likelihood: float = 0.0  # 0.0 to 1.0
    rationale_tokens: List[str] = field(default_factory=list)
    model: str = ""
    created_at_utc: str = ""
    
    # Internal metadata
    triage_status: str = "success"  # success, timeout, error
    cache_hit: bool = False


class TriageEngine:
    """
    AI/LLM-powered triage engine for vulnerability findings.
    """
    
    def __init__(self, config: TriageConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache_dir = config.cache_dir or Path(".vulnhuntr/cache/triage")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize LLM client if enabled
        self.llm_client = None
        if config.enable:
            self._initialize_llm_client()
    
    def triage_findings(self, findings: List[Finding], context: ScanContext) -> Dict[str, TriageResult]:
        """
        Triage a list of findings using AI analysis.
        
        Args:
            findings: List of findings to triage
            context: Scan context for additional information
            
        Returns:
            Dictionary mapping finding IDs to triage results
        """
        if not self.config.enable:
            return {}
            
        # Candidate selection pipeline
        candidates = self._select_candidates(findings)
        
        results = {}
        for finding in candidates:
            finding_id = self._generate_finding_id(finding)
            
            # Check cache first
            if self.config.enable_cache:
                cached_result = self._get_cached_result(finding_id, finding)
                if cached_result:
                    cached_result.cache_hit = True
                    results[finding_id] = cached_result
                    continue
            
            # Perform triage
            triage_result = self._analyze_finding(finding, context)
            
            # Cache result
            if self.config.enable_cache and triage_result.triage_status == "success":
                self._cache_result(finding_id, finding, triage_result)
            
            results[finding_id] = triage_result
        
        return results
    
    def _select_candidates(self, findings: List[Finding]) -> List[Finding]:
        """
        Select findings for triage based on severity and confidence.
        
        Args:
            findings: All findings from scan
            
        Returns:
            Filtered and sorted list of candidate findings
        """
        # Filter by minimum severity
        min_severity = Severity.from_string(self.config.min_severity)
        candidates = []
        for f in findings:
            # Compare using score attribute
            if hasattr(f.severity, 'score') and hasattr(min_severity, 'score'):
                if f.severity.score >= min_severity.score:
                    candidates.append(f)
            else:
                # Fallback comparison
                severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if severity_order.index(f.severity.name) >= severity_order.index(min_severity.name):
                    candidates.append(f)
        
        # Sort by adjusted severity (desc) then low-confidence high-severity
        def sort_key(finding: Finding) -> tuple:
            # Map severity to numeric priority
            severity_priority_map = {
                Severity.CRITICAL: 5,
                Severity.HIGH: 4,
                Severity.MEDIUM: 3,
                Severity.LOW: 2,
                Severity.INFO: 1
            }
            severity_priority = -severity_priority_map.get(finding.severity, 0)  # Higher severity first
            confidence_adjusted = finding.confidence if finding.severity == Severity.HIGH else 1.0 - finding.confidence
            return (severity_priority, -confidence_adjusted)
        
        candidates.sort(key=sort_key)
        
        # Cap to max findings
        return candidates[:self.config.max_findings]
    
    def _analyze_finding(self, finding: Finding, context: ScanContext) -> TriageResult:
        """
        Analyze a single finding using LLM triage.
        
        Args:
            finding: Finding to analyze
            context: Scan context
            
        Returns:
            Triage result with risk assessment
        """
        if not self.llm_client:
            return self._create_fallback_result(finding, "LLM client not available")
        
        try:
            # Prepare sanitized evidence
            evidence = self._prepare_evidence(finding, context)
            
            # Generate prompt
            prompt = self._create_triage_prompt(evidence)
            
            # Call LLM with timeout
            start_time = time.time()
            response = self._call_llm(prompt)
            elapsed = time.time() - start_time
            
            if elapsed > self.config.timeout:
                return self._create_fallback_result(finding, "timeout")
            
            # Parse response
            triage_result = self._parse_llm_response(response, finding)
            triage_result.model = self.config.model
            triage_result.created_at_utc = datetime.now(timezone.utc).isoformat()
            
            return triage_result
            
        except Exception as e:
            self.logger.error(f"Triage analysis failed for {finding.title}: {e}")
            return self._create_fallback_result(finding, f"error: {e}")
    
    def _prepare_evidence(self, finding: Finding, context: ScanContext) -> Dict[str, Any]:
        """
        Prepare sanitized evidence for LLM analysis.
        
        Args:
            finding: Finding to prepare evidence for
            context: Scan context
            
        Returns:
            Sanitized evidence dictionary
        """
        evidence = {
            "title": finding.title,
            "description": finding.description or "",
            "severity": finding.severity.name,
            "category": finding.category,
            "confidence": finding.confidence,
            "file": self._sanitize_path(finding.file),
            "line": finding.line,
            "function": finding.function_name or "unknown",
            "contract": finding.contract_name or "unknown"
        }
        
        # Sanitize code snippet
        code_snippet = finding.code
        if self.config.redact_addresses:
            code_snippet = self._redact_addresses(code_snippet)
        if self.config.redact_secrets:
            code_snippet = self._redact_secrets(code_snippet)
        
        evidence["code"] = code_snippet[:500]  # Limit code length
        
        # Add scoring factors if available
        if hasattr(finding, 'scoring_factors'):
            evidence["scoring_factors"] = getattr(finding, 'scoring_factors', {})
        
        return evidence
    
    def _create_triage_prompt(self, evidence: Dict[str, Any]) -> str:
        """Create structured prompt for LLM triage."""
        return f"""
You are a smart contract security expert. Analyze this vulnerability finding and provide a structured assessment.

FINDING DETAILS:
Title: {evidence['title']}
Severity: {evidence['severity']}
Category: {evidence['category']}
Confidence: {evidence['confidence']:.2f}
Location: {evidence['file']}:{evidence['line']} in {evidence['function']}()
Contract: {evidence['contract']}

DESCRIPTION:
{evidence['description']}

CODE SNIPPET:
```solidity
{evidence['code']}
```

Please provide a JSON response with the following structure:
{{
    "risk_summary": "Brief 1-2 sentence summary of the risk",
    "exploit_hypothesis": "How this vulnerability could be exploited",
    "remediation_actions": ["Action 1", "Action 2", "Action 3"],
    "false_positive_likelihood": 0.0,
    "rationale_tokens": ["key", "reasoning", "factors"]
}}

Focus on:
1. Realistic exploit scenarios
2. Impact assessment 
3. Practical remediation steps
4. False positive probability
"""
    
    def _call_llm(self, prompt: str) -> str:
        """Call LLM API with prompt."""
        if not self.llm_client:
            raise RuntimeError("LLM client not initialized")
        
        # This would integrate with actual LLM providers
        # For now, return a mock response structure
        return '''
{
    "risk_summary": "Potential reentrancy vulnerability in withdraw function",
    "exploit_hypothesis": "Attacker could drain contract funds by calling withdraw recursively before state updates",
    "remediation_actions": ["Implement checks-effects-interactions pattern", "Add reentrancy guard", "Update state before external calls"],
    "false_positive_likelihood": 0.2,
    "rationale_tokens": ["external_call", "state_change", "funds_transfer"]
}
'''
    
    def _parse_llm_response(self, response: str, finding: Finding) -> TriageResult:
        """Parse LLM response into TriageResult."""
        try:
            # Try to parse JSON response
            if response.strip().startswith('{'):
                data = json.loads(response.strip())
                return TriageResult(
                    risk_summary=data.get("risk_summary", "No summary provided"),
                    exploit_hypothesis=data.get("exploit_hypothesis", "No hypothesis provided"),
                    remediation_actions=data.get("remediation_actions", []),
                    false_positive_likelihood=float(data.get("false_positive_likelihood", 0.0)),
                    rationale_tokens=data.get("rationale_tokens", []),
                    triage_status="success"
                )
            else:
                # Fallback for non-JSON response
                return TriageResult(
                    risk_summary=response[:200],
                    exploit_hypothesis="Analysis provided in summary",
                    remediation_actions=["Review finding manually"],
                    false_positive_likelihood=0.5,
                    rationale_tokens=["manual_review"],
                    triage_status="success"
                )
        except Exception as e:
            self.logger.warning(f"Failed to parse LLM response: {e}")
            return self._create_fallback_result(finding, "parse_error")
    
    def _create_fallback_result(self, finding: Finding, status: str) -> TriageResult:
        """Create fallback triage result."""
        fallback_summaries = {
            "reentrancy": "Potential reentrancy vulnerability requiring manual review",
            "oracle": "Oracle manipulation risk requiring validation",
            "access_control": "Access control issue requiring privilege review",
            "unknown": "Security finding requiring manual analysis"
        }
        
        summary = fallback_summaries.get(finding.category.lower(), fallback_summaries["unknown"])
        
        return TriageResult(
            risk_summary=summary,
            exploit_hypothesis="Manual analysis required for exploit assessment",
            remediation_actions=["Conduct manual security review", "Follow security best practices"],
            false_positive_likelihood=0.3,
            rationale_tokens=["fallback", "manual_review"],
            triage_status=status,
            model="fallback",
            created_at_utc=datetime.now(timezone.utc).isoformat()
        )
    
    def _generate_finding_id(self, finding: Finding) -> str:
        """Generate deterministic ID for finding."""
        content = f"{finding.detector}:{finding.title}:{finding.file}:{finding.line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _get_cached_result(self, finding_id: str, finding: Finding) -> Optional[TriageResult]:
        """Get cached triage result if available."""
        cache_key = self._generate_cache_key(finding_id, finding)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    return TriageResult(**data)
            except Exception as e:
                self.logger.warning(f"Failed to load cached result: {e}")
        
        return None
    
    def _cache_result(self, finding_id: str, finding: Finding, result: TriageResult) -> None:
        """Cache triage result."""
        cache_key = self._generate_cache_key(finding_id, finding)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            from dataclasses import asdict
            with open(cache_file, 'w') as f:
                json.dump(asdict(result), f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to cache result: {e}")
    
    def _generate_cache_key(self, finding_id: str, finding: Finding) -> str:
        """Generate cache key including evidence hash."""
        evidence_content = f"{finding.code}:{finding.description}:{self.config.model}"
        evidence_hash = hashlib.sha256(evidence_content.encode()).hexdigest()[:8]
        return f"{finding_id}_{evidence_hash}"
    
    def _sanitize_path(self, path: str) -> str:
        """Sanitize file paths for LLM context."""
        # Remove absolute path components, keep relative structure
        return path.split("/")[-1] if "/" in path else path
    
    def _redact_addresses(self, code: str) -> str:
        """Redact potential Ethereum addresses from code."""
        import re
        # Simple pattern for 0x addresses
        return re.sub(r'0x[a-fA-F0-9]{40}', '0x<REDACTED>', code)
    
    def _redact_secrets(self, code: str) -> str:
        """Redact potential secrets from code."""
        import re
        # Simple patterns for common secrets
        patterns = [
            (r'["\'][a-zA-Z0-9+/]{32,}["\']', '"<REDACTED>"'),  # Base64-like
            (r'sk-[a-zA-Z0-9]{48}', 'sk-<REDACTED>'),           # OpenAI keys
        ]
        
        result = code
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result)
        
        return result
    
    def _initialize_llm_client(self) -> None:
        """Initialize LLM client based on configuration."""
        # This would initialize actual LLM clients (OpenAI, etc.)
        # For now, just mark as available
        self.llm_client = "mock_client"
        self.logger.info(f"Initialized {self.config.provider} client for model {self.config.model}")


# Export main classes
__all__ = ['TriageResult', 'TriageEngine']