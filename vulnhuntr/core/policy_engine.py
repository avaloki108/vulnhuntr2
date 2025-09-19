"""
Policy Engine (GOV) for Phase 6.

Policy governance baseline with severity gating, required invariants,
plugin hash enforcement, and economic feasibility gating.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum


def _yaml_load(path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RuntimeError("pyyaml is required for policy parsing") from e
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def _yaml_dump(path: Path, data: Dict[str, Any]) -> None:
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RuntimeError("pyyaml is required to write policy files") from e
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, indent=2)

from .models import Severity, Finding


class PolicyViolationType(Enum):
    """Types of policy violations."""
    SEVERITY_THRESHOLD = "severity_threshold"
    MISSING_INVARIANTS = "missing_invariants"
    PLUGIN_ATTESTATION = "plugin_attestation"
    ECONOMIC_FEASIBILITY = "economic_feasibility"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    FINDING_COUNT = "finding_count"


@dataclass
class PolicyViolation:
    """A policy violation record."""
    
    violation_type: PolicyViolationType
    severity: str  # "ERROR", "WARNING", "INFO"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_type": self.violation_type.value,
            "severity": self.severity,
            "message": self.message,
            "details": self.details
        }


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    
    compliant: bool
    violations: List[PolicyViolation] = field(default_factory=list)
    exit_code: int = 0
    summary: str = ""
    
    # Detailed results
    findings_evaluated: int = 0
    invariants_checked: int = 0
    plugins_verified: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliant": self.compliant,
            "violations": [v.to_dict() for v in self.violations],
            "exit_code": self.exit_code,
            "summary": self.summary,
            "findings_evaluated": self.findings_evaluated,
            "invariants_checked": self.invariants_checked,
            "plugins_verified": self.plugins_verified
        }


@dataclass
class SeverityPolicy:
    """Policy for severity-based gating."""
    
    enabled: bool = True
    min_severity: str = "MEDIUM"  # Minimum severity to fail
    max_findings: Optional[int] = None  # Max findings before failure
    exclude_categories: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "max_findings": self.max_findings,
            "exclude_categories": self.exclude_categories
        }


@dataclass
class InvariantPolicy:
    """Policy for required invariants."""
    
    enabled: bool = False
    required_invariants: List[str] = field(default_factory=list)
    min_coverage: float = 0.8  # Minimum invariant coverage (0.0-1.0)
    allow_auto_suggested: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "required_invariants": self.required_invariants,
            "min_coverage": self.min_coverage,
            "allow_auto_suggested": self.allow_auto_suggested
        }


@dataclass
class PluginPolicy:
    """Policy for plugin attestation."""
    
    enabled: bool = False
    require_attestation: bool = True
    fail_on_mismatch: bool = False
    allowed_plugins: List[str] = field(default_factory=list)
    blocked_plugins: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "require_attestation": self.require_attestation,
            "fail_on_mismatch": self.fail_on_mismatch,
            "allowed_plugins": self.allowed_plugins,
            "blocked_plugins": self.blocked_plugins
        }


@dataclass
class EconomicPolicy:
    """Policy for economic feasibility gating."""
    
    enabled: bool = False
    min_feasibility_score: float = 0.5  # Minimum feasibility to trigger
    apply_penalty: bool = False  # Apply penalty for improbable exploits
    penalty_factor: float = 0.5  # Severity reduction factor
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "min_feasibility_score": self.min_feasibility_score,
            "apply_penalty": self.apply_penalty,
            "penalty_factor": self.penalty_factor
        }


@dataclass
class PolicyConfiguration:
    """Complete policy configuration."""
    
    version: str = "1.0"
    enabled: bool = False
    
    # Policy modules
    severity: SeverityPolicy = field(default_factory=SeverityPolicy)
    invariants: InvariantPolicy = field(default_factory=InvariantPolicy)
    plugins: PluginPolicy = field(default_factory=PluginPolicy)
    economic: EconomicPolicy = field(default_factory=EconomicPolicy)
    
    # Exit code mappings
    exit_codes: Dict[str, int] = field(default_factory=lambda: {
        "success": 0,
        "policy_violation_severity": 20,
        "invariants_missing": 21,
        "plugin_attestation_failure": 22,
        "economic_feasibility": 23,
        "confidence_threshold": 24,
        "finding_count_exceeded": 25
    })
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "enabled": self.enabled,
            "severity": self.severity.to_dict(),
            "invariants": self.invariants.to_dict(),
            "plugins": self.plugins.to_dict(),
            "economic": self.economic.to_dict(),
            "exit_codes": self.exit_codes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyConfiguration:
        """Create PolicyConfiguration from dictionary."""
        config = cls()
        config.version = data.get("version", "1.0")
        config.enabled = data.get("enabled", False)
        
        # Load severity policy
        if "severity" in data:
            sev_data = data["severity"]
            config.severity = SeverityPolicy(
                enabled=sev_data.get("enabled", True),
                min_severity=sev_data.get("min_severity", "MEDIUM"),
                max_findings=sev_data.get("max_findings"),
                exclude_categories=sev_data.get("exclude_categories", [])
            )
        
        # Load invariant policy
        if "invariants" in data:
            inv_data = data["invariants"]
            config.invariants = InvariantPolicy(
                enabled=inv_data.get("enabled", False),
                required_invariants=inv_data.get("required_invariants", []),
                min_coverage=inv_data.get("min_coverage", 0.8),
                allow_auto_suggested=inv_data.get("allow_auto_suggested", True)
            )
        
        # Load plugin policy
        if "plugins" in data:
            plugin_data = data["plugins"]
            config.plugins = PluginPolicy(
                enabled=plugin_data.get("enabled", False),
                require_attestation=plugin_data.get("require_attestation", True),
                fail_on_mismatch=plugin_data.get("fail_on_mismatch", False),
                allowed_plugins=plugin_data.get("allowed_plugins", []),
                blocked_plugins=plugin_data.get("blocked_plugins", [])
            )
        
        # Load economic policy
        if "economic" in data:
            econ_data = data["economic"]
            config.economic = EconomicPolicy(
                enabled=econ_data.get("enabled", False),
                min_feasibility_score=econ_data.get("min_feasibility_score", 0.5),
                apply_penalty=econ_data.get("apply_penalty", False),
                penalty_factor=econ_data.get("penalty_factor", 0.5)
            )
        
        # Load exit codes
        if "exit_codes" in data:
            config.exit_codes.update(data["exit_codes"])
        
        return config


class PolicyLoader:
    """Loads policy configuration from YAML file."""
    
    def __init__(self, policy_file: Path = Path("policy.yml")):
        self.policy_file = policy_file
    
    def load_policy(self) -> PolicyConfiguration:
        """Load policy from file."""
        if not self.policy_file.exists():
            return PolicyConfiguration()  # Default policy
        
        try:
            data = _yaml_load(self.policy_file)
            
            return PolicyConfiguration.from_dict(data)
            
        except Exception as e:
            raise RuntimeError(f"Failed to load policy file: {e}")
    
    def save_policy(self, policy: PolicyConfiguration) -> None:
        """Save policy to file."""
        try:
            _yaml_dump(self.policy_file, policy.to_dict())
        except Exception as e:
            raise RuntimeError(f"Failed to save policy file: {e}")
    
    def create_sample_policy(self) -> None:
        """Create a sample policy.yml file."""
        sample_policy = PolicyConfiguration(
            enabled=True,
            severity=SeverityPolicy(
                enabled=True,
                min_severity="HIGH",
                max_findings=10,
                exclude_categories=["info", "style"]
            ),
            invariants=InvariantPolicy(
                enabled=True,
                required_invariants=[
                    "token_totalSupply_conservation",
                    "vault_access_control"
                ],
                min_coverage=0.7,
                allow_auto_suggested=True
            ),
            plugins=PluginPolicy(
                enabled=True,
                require_attestation=True,
                fail_on_mismatch=True,
                blocked_plugins=["experimental_detector"]
            ),
            economic=EconomicPolicy(
                enabled=False,  # Disabled by default
                min_feasibility_score=0.3,
                apply_penalty=False
            )
        )
        
        self.save_policy(sample_policy)


class PolicyEngine:
    """Main policy evaluation engine."""
    
    def __init__(self, policy: PolicyConfiguration):
        self.policy = policy
    
    def evaluate_findings(self, findings: List[Finding], 
                         invariant_results: Optional[List[Any]] = None,
                         plugin_results: Optional[List[Any]] = None,
                         economic_scenarios: Optional[List[Any]] = None) -> PolicyResult:
        """Evaluate findings against policy."""
        if not self.policy.enabled:
            return PolicyResult(compliant=True, summary="Policy evaluation disabled")
        
        violations = []
        exit_code = 0
        
        # Evaluate severity policy
        if self.policy.severity.enabled:
            sev_violations = self._evaluate_severity_policy(findings)
            violations.extend(sev_violations)
            if sev_violations:
                exit_code = self.policy.exit_codes.get("policy_violation_severity", 20)
        
        # Evaluate invariant policy
        if self.policy.invariants.enabled:
            inv_violations = self._evaluate_invariant_policy(invariant_results or [])
            violations.extend(inv_violations)
            if inv_violations and exit_code == 0:
                exit_code = self.policy.exit_codes.get("invariants_missing", 21)
        
        # Evaluate plugin policy
        if self.policy.plugins.enabled:
            plugin_violations = self._evaluate_plugin_policy(plugin_results or [])
            violations.extend(plugin_violations)
            if plugin_violations and exit_code == 0:
                exit_code = self.policy.exit_codes.get("plugin_attestation_failure", 22)
        
        # Evaluate economic policy
        if self.policy.economic.enabled:
            econ_violations = self._evaluate_economic_policy(economic_scenarios or [])
            violations.extend(econ_violations)
            if econ_violations and exit_code == 0:
                exit_code = self.policy.exit_codes.get("economic_feasibility", 23)
        
        # Determine compliance
        compliant = len(violations) == 0
        summary = self._generate_summary(violations, len(findings))
        
        return PolicyResult(
            compliant=compliant,
            violations=violations,
            exit_code=exit_code,
            summary=summary,
            findings_evaluated=len(findings),
            invariants_checked=len(invariant_results or []),
            plugins_verified=len(plugin_results or [])
        )
    
    def _evaluate_severity_policy(self, findings: List[Finding]) -> List[PolicyViolation]:
        """Evaluate severity-based policy."""
        violations = []
        
        try:
            min_severity = Severity.from_string(self.policy.severity.min_severity)
        except ValueError:
            violations.append(PolicyViolation(
                violation_type=PolicyViolationType.SEVERITY_THRESHOLD,
                severity="ERROR",
                message=f"Invalid minimum severity: {self.policy.severity.min_severity}"
            ))
            return violations
        
        # Filter findings by category exclusions
        filtered_findings = [
            f for f in findings 
            if f.category not in self.policy.severity.exclude_categories
        ]
        
        # Check severity threshold
        high_severity_findings = [
            f for f in filtered_findings 
            if f.severity.score >= min_severity.score
        ]
        
        if high_severity_findings:
            violations.append(PolicyViolation(
                violation_type=PolicyViolationType.SEVERITY_THRESHOLD,
                severity="ERROR",
                message=f"Found {len(high_severity_findings)} findings with severity >= {min_severity.value}",
                details={
                    "min_severity": min_severity.value,
                    "high_severity_count": len(high_severity_findings),
                    "finding_ids": [f.detector for f in high_severity_findings[:5]]  # First 5
                }
            ))
        
        # Check max findings
        if self.policy.severity.max_findings and len(filtered_findings) > self.policy.severity.max_findings:
            violations.append(PolicyViolation(
                violation_type=PolicyViolationType.FINDING_COUNT,
                severity="ERROR",
                message=f"Found {len(filtered_findings)} findings, exceeds limit of {self.policy.severity.max_findings}",
                details={
                    "max_allowed": self.policy.severity.max_findings,
                    "actual_count": len(filtered_findings)
                }
            ))
        
        return violations
    
    def _evaluate_invariant_policy(self, invariant_results: List[Any]) -> List[PolicyViolation]:
        """Evaluate invariant-based policy."""
        violations = []
        
        # Check required invariants
        available_invariants = {
            getattr(result, 'invariant_name', '') 
            for result in invariant_results
        }
        
        missing_invariants = [
            req_inv for req_inv in self.policy.invariants.required_invariants
            if req_inv not in available_invariants
        ]
        
        if missing_invariants:
            violations.append(PolicyViolation(
                violation_type=PolicyViolationType.MISSING_INVARIANTS,
                severity="ERROR",
                message=f"Missing required invariants: {', '.join(missing_invariants)}",
                details={
                    "required_invariants": self.policy.invariants.required_invariants,
                    "missing_invariants": missing_invariants,
                    "available_invariants": list(available_invariants)
                }
            ))
        
        # Check minimum coverage
        if invariant_results:
            proven_count = len([
                r for r in invariant_results 
                if getattr(r, 'status', '').lower() == 'proven'
            ])
            
            coverage = proven_count / len(invariant_results) if invariant_results else 0
            
            if coverage < self.policy.invariants.min_coverage:
                violations.append(PolicyViolation(
                    violation_type=PolicyViolationType.MISSING_INVARIANTS,
                    severity="WARNING",
                    message=f"Invariant coverage {coverage:.1%} below minimum {self.policy.invariants.min_coverage:.1%}",
                    details={
                        "actual_coverage": coverage,
                        "min_coverage": self.policy.invariants.min_coverage,
                        "proven_count": proven_count,
                        "total_count": len(invariant_results)
                    }
                ))
        
        return violations
    
    def _evaluate_plugin_policy(self, plugin_results: List[Any]) -> List[PolicyViolation]:
        """Evaluate plugin-based policy."""
        violations = []
        
        # Check plugin attestations
        for result in plugin_results:
            plugin_name = getattr(result, 'plugin_name', 'unknown')
            status = getattr(result, 'status', 'unknown')
            
            # Check if plugin is blocked
            if plugin_name in self.policy.plugins.blocked_plugins:
                violations.append(PolicyViolation(
                    violation_type=PolicyViolationType.PLUGIN_ATTESTATION,
                    severity="ERROR",
                    message=f"Blocked plugin detected: {plugin_name}",
                    details={"plugin_name": plugin_name}
                ))
                continue
            
            # Check if plugin requires attestation
            if (self.policy.plugins.require_attestation and 
                status not in ['verified']):
                
                if self.policy.plugins.allowed_plugins and plugin_name not in self.policy.plugins.allowed_plugins:
                    violations.append(PolicyViolation(
                        violation_type=PolicyViolationType.PLUGIN_ATTESTATION,
                        severity="WARNING",
                        message=f"Plugin not in allowed list: {plugin_name}",
                        details={
                            "plugin_name": plugin_name,
                            "status": status,
                            "allowed_plugins": self.policy.plugins.allowed_plugins
                        }
                    ))
            
            # Check for hash mismatches
            if status == 'hash_mismatch' and self.policy.plugins.fail_on_mismatch:
                violations.append(PolicyViolation(
                    violation_type=PolicyViolationType.PLUGIN_ATTESTATION,
                    severity="ERROR",
                    message=f"Plugin hash mismatch: {plugin_name}",
                    details={
                        "plugin_name": plugin_name,
                        "expected_hash": getattr(result, 'expected_hash', ''),
                        "actual_hash": getattr(result, 'actual_hash', '')
                    }
                ))
        
        return violations
    
    def _evaluate_economic_policy(self, economic_scenarios: List[Any]) -> List[PolicyViolation]:
        """Evaluate economic feasibility policy."""
        violations = []
        
        # Check for highly feasible exploits
        for scenario in economic_scenarios:
            feasibility_score = getattr(scenario, 'feasibility_score', 0.0)
            scenario_id = getattr(scenario, 'scenario_id', 'unknown')
            
            if feasibility_score >= self.policy.economic.min_feasibility_score:
                violations.append(PolicyViolation(
                    violation_type=PolicyViolationType.ECONOMIC_FEASIBILITY,
                    severity="WARNING",
                    message=f"Highly feasible exploit scenario detected: {scenario_id}",
                    details={
                        "scenario_id": scenario_id,
                        "feasibility_score": feasibility_score,
                        "threshold": self.policy.economic.min_feasibility_score,
                        "exploit_type": getattr(scenario, 'exploit_type', 'unknown')
                    }
                ))
        
        return violations
    
    def _generate_summary(self, violations: List[PolicyViolation], findings_count: int) -> str:
        """Generate policy evaluation summary."""
        if not violations:
            return f"Policy compliance: PASS ({findings_count} findings evaluated)"
        
        error_count = len([v for v in violations if v.severity == "ERROR"])
        warning_count = len([v for v in violations if v.severity == "WARNING"])
        
        return f"Policy compliance: FAIL ({error_count} errors, {warning_count} warnings)"
    
    def generate_markdown_report(self, result: PolicyResult) -> str:
        """Generate markdown report for policy evaluation."""
        lines = [
            "# Policy Evaluation Report",
            "",
            f"**Status**: {'✅ COMPLIANT' if result.compliant else '❌ NON-COMPLIANT'}",
            f"**Exit Code**: {result.exit_code}",
            f"**Summary**: {result.summary}",
            "",
            "## Statistics",
            f"- Findings Evaluated: {result.findings_evaluated}",
            f"- Invariants Checked: {result.invariants_checked}",
            f"- Plugins Verified: {result.plugins_verified}",
            ""
        ]
        
        if result.violations:
            lines.extend([
                "## Policy Violations",
                ""
            ])
            
            for violation in result.violations:
                severity_icon = {
                    "ERROR": "🚨",
                    "WARNING": "⚠️",
                    "INFO": "ℹ️"
                }.get(violation.severity, "❓")
                
                lines.extend([
                    f"### {severity_icon} {violation.violation_type.value.replace('_', ' ').title()}",
                    f"**Severity**: {violation.severity}",
                    f"**Message**: {violation.message}",
                    ""
                ])
                
                if violation.details:
                    lines.extend([
                        "**Details**:",
                        "```json",
                        json.dumps(violation.details, indent=2),
                        "```",
                        ""
                    ])
        else:
            lines.extend([
                "## ✅ No Policy Violations",
                "All policy checks passed successfully.",
                ""
            ])
        
        return "\n".join(lines)


# Utility functions
def create_sample_policy_yml() -> Dict[str, Any]:
    """Create sample policy.yml structure."""
    return {
        "version": "1.0",
        "enabled": True,
        "severity": {
            "enabled": True,
            "min_severity": "HIGH",
            "max_findings": 10,
            "exclude_categories": ["info", "style"]
        },
        "invariants": {
            "enabled": True,
            "required_invariants": [
                "token_totalSupply_conservation",
                "vault_access_control",
                "arithmetic_overflow_protection"
            ],
            "min_coverage": 0.7,
            "allow_auto_suggested": True
        },
        "plugins": {
            "enabled": True,
            "require_attestation": True,
            "fail_on_mismatch": True,
            "allowed_plugins": ["core_detector", "slither_adapter"],
            "blocked_plugins": ["experimental_detector"]
        },
        "economic": {
            "enabled": False,
            "min_feasibility_score": 0.3,
            "apply_penalty": False,
            "penalty_factor": 0.5
        },
        "exit_codes": {
            "success": 0,
            "policy_violation_severity": 20,
            "invariants_missing": 21,
            "plugin_attestation_failure": 22,
            "economic_feasibility": 23,
            "confidence_threshold": 24,
            "finding_count_exceeded": 25
        }
    }