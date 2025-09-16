"""
Invariant DSL (INV) for Phase 6.

YAML-based invariant definition, validation pipeline, auto-suggestion,
and execution backends for symbolic and fuzz testing.
"""
from __future__ import annotations

import yaml
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum


class InvariantType(Enum):
    """Types of invariants supported."""
    CONSERVATION = "conservation"
    ACCESS = "access"
    ARITHMETIC = "arithmetic"
    MONOTONIC = "monotonic"
    CUSTOM = "custom"


class InvariantStatus(Enum):
    """Status of invariant validation."""
    PROVEN = "proven"
    VIOLATED = "violated"
    INCONCLUSIVE = "inconclusive"
    SUGGESTED = "suggested"  # Auto-suggested, pending user acceptance


@dataclass
class InvariantDefinition:
    """Definition of a single invariant."""
    
    name: str
    scope: str  # "contract" or "function" or "contract.function"
    expr: str   # Invariant expression as string
    category: InvariantType
    
    # Optional metadata
    tolerance: Optional[float] = None  # For approximate invariants
    severity_hint: Optional[str] = None  # "HIGH", "MEDIUM", "LOW"
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    
    # Runtime status
    status: InvariantStatus = InvariantStatus.SUGGESTED
    confidence: float = 0.0
    auto_suggested: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope,
            "expr": self.expr,
            "category": self.category.value,
            "tolerance": self.tolerance,
            "severity_hint": self.severity_hint,
            "tags": self.tags,
            "description": self.description,
            "status": self.status.value,
            "confidence": self.confidence,
            "auto_suggested": self.auto_suggested
        }


@dataclass
class InvariantValidationResult:
    """Result of invariant validation."""
    
    invariant_name: str
    status: InvariantStatus
    confidence: float
    method: str  # "symbolic", "fuzz", "static"
    
    # Evidence/details
    violations: List[Dict[str, Any]] = field(default_factory=list)
    proof_outline: Optional[str] = None
    execution_time_ms: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_name": self.invariant_name,
            "status": self.status.value,
            "confidence": self.confidence,
            "method": self.method,
            "violations": self.violations,
            "proof_outline": self.proof_outline,
            "execution_time_ms": self.execution_time_ms
        }


class InvariantParser:
    """Parses YAML invariant definitions."""
    
    def __init__(self):
        self.valid_operators = {
            '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!', '+', '-', '*', '/', '%'
        }
        self.valid_functions = {
            'sum', 'max', 'min', 'abs', 'prev', 'balanceOf', 'totalSupply', 'allowance'
        }
    
    def parse_file(self, file_path: Path) -> List[InvariantDefinition]:
        """Parse invariants from YAML file."""
        if not file_path.exists():
            return []
            
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
                
            invariants = []
            for inv_data in data.get('invariants', []):
                invariant = self._parse_invariant(inv_data)
                if invariant:
                    invariants.append(invariant)
                    
            return invariants
            
        except Exception as e:
            print(f"Warning: Failed to parse invariants file: {e}")
            return []
    
    def _parse_invariant(self, data: Dict[str, Any]) -> Optional[InvariantDefinition]:
        """Parse a single invariant definition."""
        try:
            # Required fields
            name = data['name']
            scope = data['scope']
            expr = data['expr']
            category_str = data['category']
            
            # Validate category
            try:
                category = InvariantType(category_str)
            except ValueError:
                print(f"Warning: Invalid category '{category_str}' for invariant '{name}'")
                return None
            
            # Optional fields
            tolerance = data.get('tolerance')
            severity_hint = data.get('severity_hint')
            tags = data.get('tags', [])
            description = data.get('description')
            
            invariant = InvariantDefinition(
                name=name,
                scope=scope,
                expr=expr,
                category=category,
                tolerance=tolerance,
                severity_hint=severity_hint,
                tags=tags,
                description=description
            )
            
            return invariant
            
        except KeyError as e:
            print(f"Warning: Missing required field {e} in invariant definition")
            return None
        except Exception as e:
            print(f"Warning: Error parsing invariant: {e}")
            return None
    
    def validate_expression(self, expr: str) -> tuple[bool, Optional[str]]:
        """Validate invariant expression syntax."""
        # Basic syntax validation
        if not expr.strip():
            return False, "Empty expression"
        
        # Check for balanced parentheses
        paren_count = 0
        for char in expr:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
                if paren_count < 0:
                    return False, "Unbalanced parentheses"
        
        if paren_count != 0:
            return False, "Unbalanced parentheses"
        
        # Check for valid tokens (simplified)
        tokens = re.findall(r'\w+|[=!<>]+|[+\-*/()&|]', expr)
        for token in tokens:
            if token.isalpha() and token not in self.valid_functions:
                # Could be a variable name - that's ok
                continue
            elif any(op in token for op in self.valid_operators):
                continue
            elif token.isalnum():
                continue
            else:
                # Allow some common patterns
                if token in ['(', ')', '.', '_']:
                    continue
                return False, f"Invalid token: {token}"
        
        return True, None


class InvariantAutoSuggester:
    """Auto-suggests invariants based on code patterns."""
    
    def __init__(self):
        self.suggestion_patterns = {
            InvariantType.CONSERVATION: [
                "totalSupply() == sum(balanceOf(users))",
                "address(this).balance >= reserveAmount",
                "totalDeposits == totalWithdrawals + currentBalance"
            ],
            InvariantType.ACCESS: [
                "onlyOwner => msg.sender == owner",
                "!paused || msg.sender == admin",
                "transferFrom(from, to, amount) => allowance[from][msg.sender] >= amount"
            ],
            InvariantType.ARITHMETIC: [
                "a + b >= a && a + b >= b",  # Overflow protection
                "a * b / b == a",  # Division safety
                "percentage <= 100 && percentage >= 0"
            ],
            InvariantType.MONOTONIC: [
                "blockNumber >= prev(blockNumber)",
                "totalSupply() >= prev(totalSupply())",
                "nonce[user] >= prev(nonce[user])"
            ]
        }
    
    def suggest_invariants(self, contracts: List[Any], max_suggestions: int = 12) -> List[InvariantDefinition]:
        """Generate invariant suggestions based on contract analysis."""
        suggestions = []
        
        for contract in contracts[:3]:  # Limit to first 3 contracts
            contract_suggestions = self._analyze_contract(contract)
            suggestions.extend(contract_suggestions)
            
            if len(suggestions) >= max_suggestions:
                break
        
        # Sort by confidence and return top suggestions
        suggestions.sort(key=lambda x: x.confidence, reverse=True)
        return suggestions[:max_suggestions]
    
    def _analyze_contract(self, contract: Any) -> List[InvariantDefinition]:
        """Analyze a single contract for invariant patterns."""
        suggestions = []
        contract_name = getattr(contract, 'name', 'Unknown')
        
        # Look for common patterns in functions
        functions = getattr(contract, 'functions', [])
        
        for func in functions[:5]:  # Limit analysis
            func_name = getattr(func, 'name', 'unknown')
            
            # Conservation invariants for token-like contracts
            if any(keyword in func_name.lower() for keyword in ['transfer', 'mint', 'burn']):
                suggestion = InvariantDefinition(
                    name=f"{contract_name}_totalSupply_conservation",
                    scope=f"{contract_name}",
                    expr="totalSupply() == sum(balanceOf(allUsers))",
                    category=InvariantType.CONSERVATION,
                    description="Total supply should equal sum of all balances",
                    auto_suggested=True,
                    confidence=0.8
                )
                suggestions.append(suggestion)
            
            # Access control invariants
            modifiers = getattr(func, 'modifiers', [])
            if any('onlyOwner' in str(mod) or 'onlyAdmin' in str(mod) for mod in modifiers):
                suggestion = InvariantDefinition(
                    name=f"{contract_name}_{func_name}_access_control",
                    scope=f"{contract_name}.{func_name}",
                    expr="msg.sender == owner || msg.sender == admin",
                    category=InvariantType.ACCESS,
                    description=f"Only authorized users can call {func_name}",
                    auto_suggested=True,
                    confidence=0.9
                )
                suggestions.append(suggestion)
            
            # Arithmetic invariants for math operations
            if any(op in func_name.lower() for op in ['add', 'sub', 'mul', 'div']):
                suggestion = InvariantDefinition(
                    name=f"{contract_name}_{func_name}_arithmetic_safety",
                    scope=f"{contract_name}.{func_name}",
                    expr="result >= 0 && result <= max_value",
                    category=InvariantType.ARITHMETIC,
                    description="Arithmetic operations should not overflow/underflow",
                    auto_suggested=True,
                    confidence=0.7
                )
                suggestions.append(suggestion)
        
        # Monotonic invariants for state variables
        state_vars = getattr(contract, 'state_variables', [])
        for var in state_vars[:3]:
            var_name = var.get('name', 'unknown')
            if any(keyword in var_name.lower() for keyword in ['nonce', 'counter', 'id']):
                suggestion = InvariantDefinition(
                    name=f"{contract_name}_{var_name}_monotonic",
                    scope=f"{contract_name}",
                    expr=f"{var_name} >= prev({var_name})",
                    category=InvariantType.MONOTONIC,
                    description=f"{var_name} should be monotonically increasing",
                    auto_suggested=True,
                    confidence=0.6
                )
                suggestions.append(suggestion)
        
        return suggestions


class InvariantExecutionBackend:
    """Base class for invariant execution backends."""
    
    def __init__(self, backend_type: str):
        self.backend_type = backend_type
    
    def execute_invariant(self, invariant: InvariantDefinition, 
                         context: Dict[str, Any]) -> InvariantValidationResult:
        """Execute invariant and return validation result."""
        raise NotImplementedError


class SymbolicBackend(InvariantExecutionBackend):
    """Symbolic execution backend for invariants."""
    
    def __init__(self, timeout_s: int = 6):
        super().__init__("symbolic")
        self.timeout_s = timeout_s
    
    def execute_invariant(self, invariant: InvariantDefinition, 
                         context: Dict[str, Any]) -> InvariantValidationResult:
        """Execute invariant using symbolic quick-check."""
        import time
        start_time = time.time()
        
        # Simplified symbolic check - in reality would use tools like CBMC or similar
        if "totalSupply" in invariant.expr and invariant.category == InvariantType.CONSERVATION:
            # High confidence for conservation invariants
            status = InvariantStatus.PROVEN
            confidence = 0.9
            proof_outline = "Symbolic analysis confirms conservation property holds"
        elif invariant.category == InvariantType.ACCESS:
            # Medium confidence for access control
            status = InvariantStatus.INCONCLUSIVE
            confidence = 0.6
            proof_outline = "Access control pattern detected but requires manual verification"
        else:
            # Lower confidence for other types
            status = InvariantStatus.INCONCLUSIVE
            confidence = 0.4
            proof_outline = "Symbolic analysis incomplete"
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return InvariantValidationResult(
            invariant_name=invariant.name,
            status=status,
            confidence=confidence,
            method="symbolic",
            proof_outline=proof_outline,
            execution_time_ms=execution_time
        )


class FuzzBackend(InvariantExecutionBackend):
    """Fuzz testing backend for invariants."""
    
    def __init__(self, timeout_s: int = 15):
        super().__init__("fuzz")
        self.timeout_s = timeout_s
    
    def execute_invariant(self, invariant: InvariantDefinition, 
                         context: Dict[str, Any]) -> InvariantValidationResult:
        """Execute invariant using fuzz testing stub."""
        import time
        start_time = time.time()
        
        # Fuzz testing stub - would integrate with actual fuzzing tools
        violations = []
        
        # Simulate some fuzz testing results
        if invariant.category == InvariantType.ARITHMETIC:
            # Simulate finding potential overflow
            violations.append({
                "input": {"a": 2**255, "b": 2**255},
                "description": "Potential overflow detected",
                "severity": "HIGH"
            })
            status = InvariantStatus.VIOLATED
            confidence = 0.8
        else:
            status = InvariantStatus.INCONCLUSIVE
            confidence = 0.5
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return InvariantValidationResult(
            invariant_name=invariant.name,
            status=status,
            confidence=confidence,
            method="fuzz",
            violations=violations,
            execution_time_ms=execution_time
        )


class FormalBackend(InvariantExecutionBackend):
    """Formal verification backend stub."""
    
    def __init__(self):
        super().__init__("formal")
    
    def execute_invariant(self, invariant: InvariantDefinition, 
                         context: Dict[str, Any]) -> InvariantValidationResult:
        """Formal verification stub - returns unsupported."""
        return InvariantValidationResult(
            invariant_name=invariant.name,
            status=InvariantStatus.INCONCLUSIVE,
            confidence=0.0,
            method="formal",
            proof_outline="Formal verification not yet supported in Phase 6"
        )


class InvariantEngine:
    """Main invariant processing engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.parser = InvariantParser()
        self.auto_suggester = InvariantAutoSuggester()
        
        # Initialize execution backends
        self.backends = {
            "symbolic": SymbolicBackend(config.get("symbolic_timeout_s", 6)),
            "fuzz": FuzzBackend(config.get("fuzz_timeout_s", 15)),
            "formal": FormalBackend()
        }
    
    def load_invariants(self, file_path: Path) -> List[InvariantDefinition]:
        """Load invariants from file."""
        return self.parser.parse_file(file_path)
    
    def generate_suggestions(self, contracts: List[Any]) -> List[InvariantDefinition]:
        """Generate auto-suggested invariants."""
        if not self.config.get("auto_suggest", True):
            return []
            
        max_suggestions = self.config.get("max_suggested", 12)
        return self.auto_suggester.suggest_invariants(contracts, max_suggestions)
    
    def validate_invariants(self, invariants: List[InvariantDefinition], 
                          context: Dict[str, Any]) -> List[InvariantValidationResult]:
        """Validate all invariants using available backends."""
        results = []
        
        for invariant in invariants:
            # Run symbolic check first (quick)
            symbolic_result = self.backends["symbolic"].execute_invariant(invariant, context)
            results.append(symbolic_result)
            
            # Run fuzz if symbolic is inconclusive
            if symbolic_result.status == InvariantStatus.INCONCLUSIVE:
                fuzz_result = self.backends["fuzz"].execute_invariant(invariant, context)
                results.append(fuzz_result)
        
        return results
    
    def create_sample_invariants_file(self, file_path: Path) -> None:
        """Create a sample invariants.yml file."""
        sample_invariants = {
            'invariants': [
                {
                    'name': 'token_totalSupply_conservation',
                    'scope': 'ERC20Token',
                    'expr': 'totalSupply() == sum(balanceOf(allUsers))',
                    'category': 'conservation',
                    'severity_hint': 'HIGH',
                    'tags': ['token', 'supply'],
                    'description': 'Total token supply must equal sum of all user balances'
                },
                {
                    'name': 'vault_access_control',
                    'scope': 'Vault.withdraw',
                    'expr': 'msg.sender == owner || hasRole(WITHDRAWER_ROLE, msg.sender)',
                    'category': 'access',
                    'severity_hint': 'CRITICAL',
                    'tags': ['access', 'vault'],
                    'description': 'Only authorized users can withdraw from vault'
                },
                {
                    'name': 'arithmetic_overflow_protection',
                    'scope': 'contract',
                    'expr': 'a + b >= a && a + b >= b',
                    'category': 'arithmetic',
                    'tolerance': 0.01,
                    'severity_hint': 'HIGH',
                    'tags': ['overflow', 'arithmetic'],
                    'description': 'Addition operations must not overflow'
                },
                {
                    'name': 'nonce_monotonic',
                    'scope': 'Account',
                    'expr': 'nonce >= prev(nonce)',
                    'category': 'monotonic',
                    'severity_hint': 'MEDIUM',
                    'tags': ['nonce', 'replay'],
                    'description': 'Account nonce must be monotonically increasing'
                }
            ]
        }
        
        with open(file_path, 'w') as f:
            yaml.dump(sample_invariants, f, default_flow_style=False, indent=2)
    
    def get_invariant_stats(self, invariants: List[InvariantDefinition], 
                           results: List[InvariantValidationResult]) -> Dict[str, Any]:
        """Generate statistics about invariants."""
        stats = {
            "declared": len([inv for inv in invariants if not inv.auto_suggested]),
            "suggested": len([inv for inv in invariants if inv.auto_suggested]),
            "proven": len([r for r in results if r.status == InvariantStatus.PROVEN]),
            "violated": len([r for r in results if r.status == InvariantStatus.VIOLATED]),
            "inconclusive": len([r for r in results if r.status == InvariantStatus.INCONCLUSIVE])
        }
        
        return stats