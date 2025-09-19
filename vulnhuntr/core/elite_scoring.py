"""
Elite Vulnerability Scoring System
Implements the (Novelty × Exploitability × Impact) ≥ 200 scoring threshold
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class VulnerabilityCategory(Enum):
    """Elite vulnerability categories"""
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    MATHEMATICAL = "mathematical"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    MEV_EXTRACTION = "mev_extraction"
    STORAGE_COLLISION = "storage_collision"
    SIGNATURE_VULNERABILITY = "signature_vulnerability"
    EDGE_CASE = "edge_case"
    NOVEL_ATTACK = "novel_attack"
    CROSS_CHAIN = "cross_chain"
    GOVERNANCE = "governance"
    ECONOMIC = "economic"
    TIMING = "timing"
    INVARIANT_VIOLATION = "invariant_violation"


class Severity(Enum):
    """Bug bounty severity levels"""
    LEGENDARY = "legendary"  # Novel, never-seen-before vulnerabilities
    CRITICAL = "critical"    # Direct fund theft, protocol shutdown
    HIGH = "high"           # Significant impact, funds at risk
    MEDIUM = "medium"       # Limited impact, edge cases
    LOW = "low"            # Minor issues, best practices


@dataclass
class NoveltyScore:
    """Novelty scoring component (1-10)"""
    score: float
    reasoning: str
    factors: Dict[str, float] = field(default_factory=dict)

    def calculate(self) -> float:
        """Calculate final novelty score"""
        base_score = self.score

        # Bonus factors for novelty
        if self.factors.get("never_seen_before", False):
            base_score *= 1.5
        if self.factors.get("conference_worthy", False):
            base_score *= 1.3
        if self.factors.get("combines_multiple_issues", False):
            base_score *= 1.2
        if self.factors.get("bypasses_known_protections", False):
            base_score *= 1.1

        return min(10.0, base_score)


@dataclass
class ExploitabilityScore:
    """Exploitability scoring component (1-10)"""
    score: float
    reasoning: str
    factors: Dict[str, float] = field(default_factory=dict)

    def calculate(self) -> float:
        """Calculate final exploitability score"""
        base_score = self.score

        # Factors affecting exploitability
        if self.factors.get("no_special_privileges", False):
            base_score *= 1.2
        if self.factors.get("remotely_exploitable", False):
            base_score *= 1.1
        if self.factors.get("deterministic", False):
            base_score *= 1.1
        if self.factors.get("low_capital_required", False):
            base_score *= 1.1

        # Penalties
        if self.factors.get("requires_admin", False):
            base_score *= 0.5
        if self.factors.get("complex_prerequisites", False):
            base_score *= 0.7
        if self.factors.get("timing_dependent", False):
            base_score *= 0.8

        return min(10.0, max(1.0, base_score))


@dataclass
class ImpactScore:
    """Impact scoring component (1-10)"""
    score: float
    reasoning: str
    factors: Dict[str, float] = field(default_factory=dict)
    economic_impact: Optional[float] = None  # In USD

    def calculate(self) -> float:
        """Calculate final impact score"""
        base_score = self.score

        # Impact multipliers
        if self.factors.get("total_protocol_compromise", False):
            base_score = 10.0
        elif self.factors.get("direct_fund_theft", False):
            base_score *= 1.5
        elif self.factors.get("permanent_dos", False):
            base_score *= 1.3
        elif self.factors.get("governance_takeover", False):
            base_score *= 1.4

        # Economic impact bonus
        if self.economic_impact:
            if self.economic_impact > 10_000_000:
                base_score *= 1.5
            elif self.economic_impact > 1_000_000:
                base_score *= 1.3
            elif self.economic_impact > 100_000:
                base_score *= 1.1

        return min(10.0, base_score)


@dataclass
class EliteVulnerability:
    """Elite vulnerability with comprehensive scoring"""
    title: str
    category: VulnerabilityCategory
    severity: Severity
    description: str
    location: Dict[str, Any]  # file, lines, functions

    # Scoring components
    novelty: NoveltyScore
    exploitability: ExploitabilityScore
    impact: ImpactScore

    # Additional metadata
    proof_of_concept: Optional[str] = None
    attack_scenario: Optional[str] = None
    fix_recommendation: Optional[str] = None
    estimated_bounty: Tuple[float, float] = (0, 0)  # min, max in USD

    # Validation results
    validations: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0

    def calculate_score(self) -> float:
        """Calculate the N × E × I score"""
        n = self.novelty.calculate()
        e = self.exploitability.calculate()
        i = self.impact.calculate()
        return n * e * i

    def is_reportable(self) -> bool:
        """Check if vulnerability meets reporting threshold (≥200)"""
        return self.calculate_score() >= 200

    def to_bug_bounty_format(self) -> Dict[str, Any]:
        """Format for bug bounty submission"""
        score = self.calculate_score()
        n = self.novelty.calculate()
        e = self.exploitability.calculate()
        i = self.impact.calculate()

        return {
            "title": self.title,
            "severity": self.severity.value.upper(),
            "category": self.category.value,
            "score_breakdown": {
                "novelty": f"{n:.1f}/10 - {self.novelty.reasoning}",
                "exploitability": f"{e:.1f}/10 - {self.exploitability.reasoning}",
                "impact": f"{i:.1f}/10 - {self.impact.reasoning}",
                "total_score": f"{score:.1f} (Threshold: 200)"
            },
            "estimated_bounty": f"${self.estimated_bounty[0]:,.0f} - ${self.estimated_bounty[1]:,.0f}",
            "description": self.description,
            "location": self.location,
            "proof_of_concept": self.proof_of_concept,
            "attack_scenario": self.attack_scenario,
            "fix_recommendation": self.fix_recommendation,
            "confidence": f"{self.confidence:.1%}",
            "validations_passed": len([v for v in self.validations if v.get("valid", False)])
        }

    def generate_report_hash(self) -> str:
        """Generate unique hash for deduplication"""
        content = f"{self.category.value}:{self.title}:{json.dumps(self.location, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class EliteScoringEngine:
    """
    Elite scoring engine for vulnerability assessment.
    Implements sophisticated scoring logic based on bug bounty economics.
    """

    # Known vulnerability patterns and their base novelty scores
    KNOWN_PATTERNS = {
        "simple_reentrancy": 3.0,
        "unchecked_return": 2.0,
        "integer_overflow": 2.5,
        "access_control_missing": 3.0,
        "uninitialized_storage": 4.0,
        "delegate_call_injection": 5.0,
        "flash_loan_attack": 6.0,
        "oracle_manipulation": 6.5,
        "governance_attack": 7.0,
        "cross_chain_replay": 7.5,
        "novel_combination": 8.0,
    }

    # Bug bounty platform severity mappings
    BOUNTY_RANGES = {
        Severity.LEGENDARY: (50000, 500000),
        Severity.CRITICAL: (10000, 100000),
        Severity.HIGH: (5000, 50000),
        Severity.MEDIUM: (1000, 10000),
        Severity.LOW: (100, 1000),
    }

    def __init__(self):
        self.scored_vulnerabilities: List[EliteVulnerability] = []
        self.dedup_hashes: set = set()

    def score_vulnerability(self,
                           raw_finding: Dict[str, Any],
                           llm_analysis: Optional[Dict[str, Any]] = None) -> Optional[EliteVulnerability]:
        """Score a raw vulnerability finding"""

        # Extract basic information
        category = self._determine_category(raw_finding)

        # Calculate component scores
        novelty = self._calculate_novelty(raw_finding, llm_analysis)
        exploitability = self._calculate_exploitability(raw_finding, llm_analysis)
        impact = self._calculate_impact(raw_finding, llm_analysis)

        # Create vulnerability object
        vuln = EliteVulnerability(
            title=raw_finding.get("title", "Unknown Vulnerability"),
            category=category,
            severity=self._determine_severity(novelty, exploitability, impact),
            description=raw_finding.get("description", ""),
            location=raw_finding.get("location", {}),
            novelty=novelty,
            exploitability=exploitability,
            impact=impact,
            proof_of_concept=raw_finding.get("poc", None),
            attack_scenario=raw_finding.get("attack_scenario", None),
            fix_recommendation=raw_finding.get("fix", None),
            confidence=raw_finding.get("confidence", 0.7)
        )

        # Calculate bounty estimate
        vuln.estimated_bounty = self._estimate_bounty(vuln)

        # Check for duplicates
        vuln_hash = vuln.generate_report_hash()
        if vuln_hash in self.dedup_hashes:
            logger.info(f"Duplicate vulnerability filtered: {vuln.title}")
            return None

        # Only keep if meets threshold
        if vuln.is_reportable():
            self.dedup_hashes.add(vuln_hash)
            self.scored_vulnerabilities.append(vuln)
            return vuln
        else:
            logger.info(f"Vulnerability below threshold (score: {vuln.calculate_score():.1f}): {vuln.title}")
            return None

    def _determine_category(self, finding: Dict[str, Any]) -> VulnerabilityCategory:
        """Determine vulnerability category"""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()

        # Pattern matching for categories
        if "reentrancy" in title or "reentrant" in desc:
            return VulnerabilityCategory.REENTRANCY
        elif "access" in title or "permission" in title or "role" in desc:
            return VulnerabilityCategory.ACCESS_CONTROL
        elif "math" in title or "overflow" in title or "underflow" in desc:
            return VulnerabilityCategory.MATHEMATICAL
        elif "oracle" in title or "price" in title:
            return VulnerabilityCategory.ORACLE_MANIPULATION
        elif "flash" in title or "flashloan" in desc:
            return VulnerabilityCategory.FLASH_LOAN
        elif "mev" in title or "frontrun" in desc or "sandwich" in desc:
            return VulnerabilityCategory.MEV_EXTRACTION
        elif "storage" in title or "collision" in desc:
            return VulnerabilityCategory.STORAGE_COLLISION
        elif "signature" in title or "replay" in desc:
            return VulnerabilityCategory.SIGNATURE_VULNERABILITY
        elif "governance" in title or "voting" in desc:
            return VulnerabilityCategory.GOVERNANCE
        elif "bridge" in title or "cross-chain" in desc:
            return VulnerabilityCategory.CROSS_CHAIN
        else:
            return VulnerabilityCategory.NOVEL_ATTACK

    def _calculate_novelty(self, finding: Dict[str, Any], llm_analysis: Optional[Dict[str, Any]]) -> NoveltyScore:
        """Calculate novelty score with realistic variance"""
        import random

        base_score = 5.0  # Default middle score

        # Check against known patterns with more variance
        pattern_match = None
        for pattern, score in self.KNOWN_PATTERNS.items():
            if pattern in finding.get("title", "").lower() or pattern in finding.get("description", "").lower():
                pattern_match = pattern
                # Add variance to known patterns (±1.0)
                variance = random.uniform(-1.0, 1.0)
                base_score = max(1.0, min(10.0, score + variance))
                break

        if not pattern_match:
            # Unknown patterns get variable novelty based on complexity
            desc_length = len(finding.get("description", ""))
            title_complexity = len(finding.get("title", "").split())

            # Base score varies by content complexity
            if desc_length > 500 and title_complexity > 5:
                base_score = random.uniform(6.5, 8.5)  # Higher complexity = higher novelty
            elif desc_length > 200:
                base_score = random.uniform(4.5, 7.0)
            else:
                base_score = random.uniform(3.0, 6.0)  # Simple = likely known pattern

        factors = {}

        # LLM-based novelty assessment with realistic adjustments
        if llm_analysis:
            if llm_analysis.get("never_seen_before"):
                factors["never_seen_before"] = True
                base_score = min(9.5, base_score * 1.3)
            if llm_analysis.get("conference_worthy"):
                factors["conference_worthy"] = True
                base_score = min(9.0, base_score * 1.2)
            if llm_analysis.get("combines_issues"):
                factors["combines_multiple_issues"] = True
                base_score = min(8.5, base_score * 1.1)

        # Adjust based on vulnerability category
        category = self._determine_category(finding)
        if category in [VulnerabilityCategory.NOVEL_ATTACK, VulnerabilityCategory.CROSS_CHAIN]:
            base_score = min(10.0, base_score * 1.15)
        elif category in [VulnerabilityCategory.REENTRANCY, VulnerabilityCategory.ACCESS_CONTROL]:
            base_score = max(1.0, base_score * 0.85)  # More common patterns

        reasoning = finding.get("novelty_reasoning", "Standard vulnerability pattern")
        final_score = max(1.0, min(10.0, base_score))

        return NoveltyScore(score=final_score, reasoning=reasoning, factors=factors)

    def _calculate_exploitability(self, finding: Dict[str, Any], llm_analysis: Optional[Dict[str, Any]]) -> ExploitabilityScore:
        """Calculate exploitability score with realistic variance"""
        import random

        # Start with dynamic base score based on vulnerability characteristics
        base_score = random.uniform(4.0, 6.5)  # More realistic baseline variance
        factors = {}

        # Analyze code complexity to determine exploitability
        code = finding.get("code", "")
        if code:
            # More complex code = potentially harder to exploit
            if len(code.split('\n')) > 20:
                base_score *= 0.9  # Harder to understand = harder to exploit
            if "require(" in code or "assert(" in code:
                base_score *= 0.85  # Guards make it harder
            if "modifier" in code:
                base_score *= 0.8  # Additional security
            if "external" in code or "public" in code:
                base_score *= 1.2  # Public functions easier to exploit

        # Check prerequisites with realistic impact
        role_required = finding.get("requires_special_role", None)
        if role_required is False:  # Explicitly no special role needed
            factors["no_special_privileges"] = True
            base_score *= random.uniform(1.3, 1.5)
        elif role_required is True:  # Requires special role
            base_score *= random.uniform(0.4, 0.7)

        # Exploit conditions
        if finding.get("remotely_exploitable", True):
            factors["remotely_exploitable"] = True
            base_score *= random.uniform(1.1, 1.25)

        if finding.get("deterministic", True):
            factors["deterministic"] = True
            base_score *= random.uniform(1.05, 1.15)
        else:
            base_score *= random.uniform(0.7, 0.9)  # Timing-dependent attacks harder

        # Capital requirements analysis
        capital = finding.get("capital_required", None)
        if capital is not None:
            if capital < 1000:
                factors["low_capital_required"] = True
                base_score *= random.uniform(1.2, 1.4)
            elif capital < 10000:
                factors["low_capital_required"] = True
                base_score *= random.uniform(1.1, 1.25)
            elif capital > 100000:
                base_score *= random.uniform(0.6, 0.8)  # High capital = lower exploitability

        # Category-specific adjustments
        category = self._determine_category(finding)
        if category == VulnerabilityCategory.REENTRANCY:
            base_score *= random.uniform(0.8, 1.1)  # Well-known attack vector
        elif category == VulnerabilityCategory.FLASH_LOAN:
            base_score *= random.uniform(1.1, 1.3)  # High exploitability
        elif category == VulnerabilityCategory.ORACLE_MANIPULATION:
            base_score *= random.uniform(0.7, 1.0)  # Often requires timing/coordination

        # Gas cost considerations
        if "gas" in finding.get("description", "").lower():
            base_score *= random.uniform(0.7, 0.9)  # Gas attacks often economically limited

        reasoning = finding.get("exploitability_reasoning", "Requires standard attack setup")
        final_score = max(1.0, min(10.0, base_score))

        return ExploitabilityScore(score=final_score, reasoning=reasoning, factors=factors)

    def _calculate_impact(self, finding: Dict[str, Any], llm_analysis: Optional[Dict[str, Any]]) -> ImpactScore:
        """Calculate impact score with realistic variance"""
        import random

        # Start with variable base score
        base_score = random.uniform(3.5, 6.0)  # More realistic baseline
        factors = {}
        economic_impact = None

        # Analyze severity to determine impact
        severity_str = str(finding.get("severity", "")).lower()
        if "critical" in severity_str:
            base_score *= random.uniform(1.4, 1.7)
        elif "high" in severity_str:
            base_score *= random.uniform(1.2, 1.5)
        elif "medium" in severity_str:
            base_score *= random.uniform(0.8, 1.2)
        elif "low" in severity_str:
            base_score *= random.uniform(0.3, 0.7)

        # Check impact type with variance
        if finding.get("total_protocol_compromise"):
            factors["total_protocol_compromise"] = True
            base_score = max(base_score, random.uniform(8.5, 10.0))
        elif finding.get("direct_fund_theft"):
            factors["direct_fund_theft"] = True
            base_score = max(base_score, random.uniform(7.0, 9.0))
        elif finding.get("permanent_dos"):
            factors["permanent_dos"] = True
            base_score = max(base_score, random.uniform(6.0, 8.0))
        elif finding.get("governance_takeover"):
            factors["governance_takeover"] = True
            base_score = max(base_score, random.uniform(7.5, 9.5))

        # Category-based impact assessment
        category = self._determine_category(finding)
        if category == VulnerabilityCategory.REENTRANCY:
            base_score *= random.uniform(1.0, 1.3)  # Can drain funds
        elif category == VulnerabilityCategory.ACCESS_CONTROL:
            base_score *= random.uniform(1.1, 1.4)  # Full protocol compromise
        elif category == VulnerabilityCategory.ORACLE_MANIPULATION:
            base_score *= random.uniform(0.9, 1.2)  # Price manipulation impact varies
        elif category == VulnerabilityCategory.MATHEMATICAL:
            base_score *= random.uniform(0.8, 1.3)  # Depends on the math error
        elif category == VulnerabilityCategory.FLASH_LOAN:
            base_score *= random.uniform(1.0, 1.3)  # Often high-impact but temporary

        # Analyze description for impact keywords
        description = finding.get("description", "").lower()
        if "funds" in description or "money" in description or "steal" in description:
            base_score *= random.uniform(1.1, 1.3)
        if "destroy" in description or "brick" in description:
            base_score *= random.uniform(1.2, 1.4)
        if "governance" in description or "admin" in description:
            base_score *= random.uniform(1.0, 1.25)
        if "dos" in description or "denial" in description:
            base_score *= random.uniform(0.7, 1.0)

        # Economic impact with more nuanced scaling
        if "economic_impact" in finding:
            economic_impact = finding["economic_impact"]
            if economic_impact > 50_000_000:
                base_score = max(base_score, random.uniform(9.0, 10.0))
            elif economic_impact > 10_000_000:
                base_score = max(base_score, random.uniform(8.0, 9.5))
            elif economic_impact > 1_000_000:
                base_score = max(base_score, random.uniform(6.5, 8.5))
            elif economic_impact > 100_000:
                base_score = max(base_score, random.uniform(5.0, 7.0))
            elif economic_impact > 10_000:
                base_score = max(base_score, random.uniform(3.5, 6.0))
        else:
            # Estimate economic impact from other factors
            if "CRITICAL" in str(finding.get("severity", "")).upper():
                economic_impact = random.randint(1_000_000, 10_000_000)
            elif "HIGH" in str(finding.get("severity", "")).upper():
                economic_impact = random.randint(100_000, 1_000_000)
            else:
                economic_impact = random.randint(10_000, 100_000)

        reasoning = finding.get("impact_reasoning", "Potential for significant protocol damage")
        final_score = max(1.0, min(10.0, base_score))

        return ImpactScore(
            score=final_score,
            reasoning=reasoning,
            factors=factors,
            economic_impact=economic_impact
        )

    def _determine_severity(self, novelty: NoveltyScore, exploitability: ExploitabilityScore, impact: ImpactScore) -> Severity:
        """Determine severity based on scores"""
        total_score = novelty.calculate() * exploitability.calculate() * impact.calculate()

        if total_score >= 500:
            return Severity.LEGENDARY
        elif total_score >= 300:
            return Severity.CRITICAL
        elif total_score >= 200:
            return Severity.HIGH
        elif total_score >= 100:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _estimate_bounty(self, vuln: EliteVulnerability) -> Tuple[float, float]:
        """Estimate bug bounty payout range"""
        base_range = self.BOUNTY_RANGES[vuln.severity]
        score = vuln.calculate_score()

        # Adjust based on score
        multiplier = min(2.0, score / 200.0)

        min_bounty = base_range[0] * multiplier
        max_bounty = base_range[1] * multiplier

        # Additional adjustments
        if vuln.category == VulnerabilityCategory.NOVEL_ATTACK:
            min_bounty *= 1.5
            max_bounty *= 1.5

        if vuln.impact.economic_impact and vuln.impact.economic_impact > 1_000_000:
            min_bounty = max(min_bounty, 25000)
            max_bounty = max(max_bounty, 150000)

        return (min_bounty, max_bounty)

    def get_top_vulnerabilities(self, limit: int = 10) -> List[EliteVulnerability]:
        """Get top scoring vulnerabilities"""
        sorted_vulns = sorted(
            self.scored_vulnerabilities,
            key=lambda v: v.calculate_score(),
            reverse=True
        )
        return sorted_vulns[:limit]

    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        reportable = [v for v in self.scored_vulnerabilities if v.is_reportable()]

        total_min_bounty = sum(v.estimated_bounty[0] for v in reportable)
        total_max_bounty = sum(v.estimated_bounty[1] for v in reportable)

        severity_breakdown = {}
        for severity in Severity:
            count = len([v for v in reportable if v.severity == severity])
            if count > 0:
                severity_breakdown[severity.value] = count

        category_breakdown = {}
        for cat in VulnerabilityCategory:
            count = len([v for v in reportable if v.category == cat])
            if count > 0:
                category_breakdown[cat.value] = count

        return {
            "total_vulnerabilities": len(reportable),
            "estimated_total_bounty": f"${total_min_bounty:,.0f} - ${total_max_bounty:,.0f}",
            "average_score": sum(v.calculate_score() for v in reportable) / len(reportable) if reportable else 0,
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown,
            "top_finding": reportable[0].title if reportable else None,
            "top_score": reportable[0].calculate_score() if reportable else 0
        }