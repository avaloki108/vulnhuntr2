"""
Rule/Pattern DSL foundation for vulnhuntr2 Phase 5.
Provides extensible pattern definition and hot reload capabilities.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path
import json
import time
import logging
import re
from abc import ABC, abstractmethod

from ..core.models import Finding, ScanContext, Severity


@dataclass
class PatternRule:
    """Defines a vulnerability detection pattern."""
    
    id: str
    name: str
    description: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    category: str = "unknown"
    cwe_id: Optional[str] = None
    
    # Pattern configuration
    pattern_type: str = "regex"  # regex, ast, semantic
    flags: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    
    # Scoring factors
    scoring_factors: Dict[str, float] = field(default_factory=dict)
    
    # Hot reload metadata
    file_path: Optional[str] = None
    last_modified: float = 0.0
    
    def matches(self, code: str, context: Optional[ScanContext] = None) -> bool:
        """Check if pattern matches the given code."""
        if self.pattern_type == "regex":
            return bool(re.search(self.pattern, code, re.IGNORECASE | re.MULTILINE))
        else:
            # Other pattern types would be implemented here
            return False
    
    def create_finding(self, file_path: str, line: int, code: str, **kwargs) -> Finding:
        """Create a Finding from this pattern match."""
        return Finding(
            detector=f"pattern_{self.id}",
            title=self.name,
            file=file_path,
            line=line,
            severity=self.severity,
            code=code,
            description=self.description,
            confidence=self.confidence,
            category=self.category,
            cwe_id=self.cwe_id,
            **kwargs
        )


@dataclass
class RuleSet:
    """Collection of pattern rules."""
    
    name: str
    version: str
    rules: List[PatternRule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_rule(self, rule: PatternRule) -> None:
        """Add a rule to the ruleset."""
        self.rules.append(rule)
    
    def get_rule(self, rule_id: str) -> Optional[PatternRule]:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_rules_by_category(self, category: str) -> List[PatternRule]:
        """Get rules by category."""
        return [rule for rule in self.rules if rule.category == category]


class PatternEngine:
    """
    Pattern engine with hot reload and scoring factor adjustments.
    """
    
    def __init__(self, pattern_dirs: List[Path], enable_hot_reload: bool = False):
        self.pattern_dirs = pattern_dirs
        self.enable_hot_reload = enable_hot_reload
        self.rulesets: Dict[str, RuleSet] = {}
        self.file_timestamps: Dict[str, float] = {}
        self.logger = logging.getLogger(__name__)
        
        # Load initial patterns
        self.reload_patterns()
    
    def reload_patterns(self) -> None:
        """Reload all patterns from configured directories."""
        self.logger.info("Reloading patterns...")
        
        for pattern_dir in self.pattern_dirs:
            if not pattern_dir.exists():
                continue
            
            # Load JSON pattern files
            for pattern_file in pattern_dir.glob("**/*.json"):
                self._load_pattern_file(pattern_file)
            
            # Load YAML pattern files (if available)
            for pattern_file in pattern_dir.glob("**/*.yml"):
                self._load_yaml_pattern_file(pattern_file)
            
            for pattern_file in pattern_dir.glob("**/*.yaml"):
                self._load_yaml_pattern_file(pattern_file)
    
    def check_for_updates(self) -> bool:
        """Check if any pattern files have been updated."""
        if not self.enable_hot_reload:
            return False
        
        updated = False
        for pattern_dir in self.pattern_dirs:
            if not pattern_dir.exists():
                continue
            
            for pattern_file in pattern_dir.glob("**/*.json"):
                file_path = str(pattern_file)
                current_mtime = pattern_file.stat().st_mtime
                
                if file_path not in self.file_timestamps:
                    self.file_timestamps[file_path] = current_mtime
                elif current_mtime > self.file_timestamps[file_path]:
                    self.logger.info(f"Pattern file updated: {pattern_file}")
                    self._load_pattern_file(pattern_file)
                    self.file_timestamps[file_path] = current_mtime
                    updated = True
        
        return updated
    
    def apply_patterns(self, code: str, file_path: str, context: Optional[ScanContext] = None) -> List[Finding]:
        """
        Apply patterns to code and return findings.
        
        Args:
            code: Source code to analyze
            file_path: Path to the source file
            context: Scan context for additional information
            
        Returns:
            List of findings from pattern matches
        """
        # Check for hot reload updates
        if self.enable_hot_reload:
            self.check_for_updates()
        
        findings = []
        lines = code.split('\n')
        
        for ruleset in self.rulesets.values():
            for rule in ruleset.rules:
                # Check exclusions first
                if self._is_excluded(code, rule.exclusions):
                    continue
                
                # Apply pattern
                if rule.pattern_type == "regex":
                    findings.extend(self._apply_regex_pattern(rule, code, lines, file_path))
                # Other pattern types would be handled here
        
        return findings
    
    def adjust_scoring_factors(self, rule_id: str, scoring_adjustments: Dict[str, float]) -> bool:
        """
        Adjust scoring factors for a rule at runtime.
        
        Args:
            rule_id: ID of the rule to adjust
            scoring_adjustments: Dictionary of scoring factor adjustments
            
        Returns:
            True if adjustments were applied
        """
        for ruleset in self.rulesets.values():
            rule = ruleset.get_rule(rule_id)
            if rule:
                rule.scoring_factors.update(scoring_adjustments)
                self.logger.info(f"Updated scoring factors for rule {rule_id}: {scoring_adjustments}")
                return True
        
        self.logger.warning(f"Rule {rule_id} not found for scoring adjustment")
        return False
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded patterns."""
        total_rules = sum(len(ruleset.rules) for ruleset in self.rulesets.values())
        
        category_counts = {}
        severity_counts = {}
        
        for ruleset in self.rulesets.values():
            for rule in ruleset.rules:
                category_counts[rule.category] = category_counts.get(rule.category, 0) + 1
                severity_counts[rule.severity.name] = severity_counts.get(rule.severity.name, 0) + 1
        
        return {
            "total_rulesets": len(self.rulesets),
            "total_rules": total_rules,
            "categories": category_counts,
            "severities": severity_counts,
            "hot_reload_enabled": self.enable_hot_reload
        }
    
    def _load_pattern_file(self, pattern_file: Path) -> None:
        """Load patterns from a JSON file."""
        try:
            with open(pattern_file, 'r') as f:
                data = json.load(f)
            
            # Parse ruleset
            ruleset_data = data.get('ruleset', {})
            ruleset = RuleSet(
                name=ruleset_data.get('name', pattern_file.stem),
                version=ruleset_data.get('version', '1.0.0'),
                metadata=ruleset_data.get('metadata', {})
            )
            
            # Parse rules
            for rule_data in data.get('rules', []):
                rule = self._parse_rule(rule_data, str(pattern_file))
                ruleset.add_rule(rule)
            
            self.rulesets[ruleset.name] = ruleset
            self.file_timestamps[str(pattern_file)] = pattern_file.stat().st_mtime
            
            self.logger.info(f"Loaded {len(ruleset.rules)} rules from {pattern_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to load pattern file {pattern_file}: {e}")
    
    def _load_yaml_pattern_file(self, pattern_file: Path) -> None:
        """Load patterns from a YAML file."""
        try:
            import yaml
            
            with open(pattern_file, 'r') as f:
                data = yaml.safe_load(f)
            
            # Parse similar to JSON but from YAML
            ruleset_data = data.get('ruleset', {})
            ruleset = RuleSet(
                name=ruleset_data.get('name', pattern_file.stem),
                version=ruleset_data.get('version', '1.0.0'),
                metadata=ruleset_data.get('metadata', {})
            )
            
            for rule_data in data.get('rules', []):
                rule = self._parse_rule(rule_data, str(pattern_file))
                ruleset.add_rule(rule)
            
            self.rulesets[ruleset.name] = ruleset
            self.file_timestamps[str(pattern_file)] = pattern_file.stat().st_mtime
            
            self.logger.info(f"Loaded {len(ruleset.rules)} rules from {pattern_file}")
            
        except ImportError:
            self.logger.warning(f"PyYAML not available, skipping {pattern_file}")
        except Exception as e:
            self.logger.error(f"Failed to load YAML pattern file {pattern_file}: {e}")
    
    def _parse_rule(self, rule_data: Dict[str, Any], file_path: str) -> PatternRule:
        """Parse a rule from dictionary data."""
        return PatternRule(
            id=rule_data['id'],
            name=rule_data['name'],
            description=rule_data.get('description', ''),
            pattern=rule_data['pattern'],
            severity=Severity.from_string(rule_data.get('severity', 'MEDIUM')),
            confidence=rule_data.get('confidence', 0.5),
            category=rule_data.get('category', 'unknown'),
            cwe_id=rule_data.get('cwe_id'),
            pattern_type=rule_data.get('pattern_type', 'regex'),
            flags=rule_data.get('flags', []),
            exclusions=rule_data.get('exclusions', []),
            scoring_factors=rule_data.get('scoring_factors', {}),
            file_path=file_path,
            last_modified=time.time()
        )
    
    def _apply_regex_pattern(self, rule: PatternRule, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Apply a regex pattern to code."""
        findings = []
        
        # Compile regex with flags
        flags = re.IGNORECASE | re.MULTILINE
        if 'DOTALL' in rule.flags:
            flags |= re.DOTALL
        
        try:
            pattern = re.compile(rule.pattern, flags)
            
            # Find matches
            for match in pattern.finditer(code):
                # Determine line number
                line_number = code[:match.start()].count('\n') + 1
                
                # Extract matching code
                matched_text = match.group(0)
                
                # Create finding
                finding = rule.create_finding(
                    file_path=file_path,
                    line=line_number,
                    code=matched_text
                )
                
                # Apply scoring factors
                if rule.scoring_factors:
                    for factor, weight in rule.scoring_factors.items():
                        finding.confidence *= weight
                
                findings.append(finding)
                
        except re.error as e:
            self.logger.error(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        return findings
    
    def _is_excluded(self, code: str, exclusions: List[str]) -> bool:
        """Check if code matches any exclusion patterns."""
        for exclusion in exclusions:
            if re.search(exclusion, code, re.IGNORECASE | re.MULTILINE):
                return True
        return False


# Example pattern file structure
EXAMPLE_PATTERN_FILE = {
    "ruleset": {
        "name": "basic_vulnerabilities",
        "version": "1.0.0",
        "metadata": {
            "author": "vulnhuntr2",
            "description": "Basic smart contract vulnerability patterns"
        }
    },
    "rules": [
        {
            "id": "reentrancy_001",
            "name": "Potential Reentrancy Vulnerability",
            "description": "External call before state change may allow reentrancy",
            "pattern": r"\.call\{[^}]*\}\([^)]*\)[^;]*;\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=",
            "severity": "HIGH",
            "confidence": 0.8,
            "category": "reentrancy",
            "cwe_id": "CWE-362",
            "pattern_type": "regex",
            "exclusions": [
                r"require\s*\(",
                r"assert\s*\("
            ],
            "scoring_factors": {
                "external_call_factor": 1.2,
                "state_change_factor": 1.1
            }
        }
    ]
}


# Export main classes
__all__ = ['PatternRule', 'RuleSet', 'PatternEngine', 'EXAMPLE_PATTERN_FILE']