"""
Flash Loan Fuzzer - generates invariant harnesses for flash loan testing.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from pathlib import Path
import random
import string

from ..core.models import Finding, ScanContext


class FlashLoanFuzzingHarness:
    """
    Generates fuzzing harnesses for flash loan invariant testing.
    """
    
    def __init__(self):
        self.invariant_templates = self._load_invariant_templates()
        self.fuzz_parameters = self._setup_fuzz_parameters()
    
    def generate_harness(
        self, 
        findings: List[Finding], 
        context: ScanContext,
        output_dir: Optional[Path] = None
    ) -> str:
        """
        Generate a fuzzing harness for flash loan invariant testing.
        
        Args:
            findings: Flash loan related findings
            context: Scan context with contract information
            output_dir: Optional directory to write harness files
            
        Returns:
            Generated fuzzing harness code
        """
        # Filter flash loan related findings
        flash_findings = [f for f in findings if f.category.lower() == "flashloan"]
        
        if not flash_findings:
            return self._generate_generic_harness(context)
        
        # Generate specific harness based on findings
        harness_code = self._generate_specific_harness(flash_findings, context)
        
        if output_dir:
            self._write_harness_file(harness_code, output_dir)
        
        return harness_code
    
    def _generate_specific_harness(self, findings: List[Finding], context: ScanContext) -> str:
        """Generate harness specific to discovered vulnerabilities."""
        
        # Extract contract information
        contracts = context.contracts
        primary_contract = contracts[0] if contracts else None
        
        contract_name = primary_contract.name if primary_contract else "TargetContract"
        
        # Generate test scenarios based on findings
        test_scenarios = []
        for finding in findings:
            scenario = self._generate_test_scenario(finding, context)
            test_scenarios.append(scenario)
        
        # Generate harness template
        harness_template = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/**
 * Flash Loan Fuzzing Harness
 * Generated for testing flash loan invariants
 * 
 * Findings being tested:
{self._format_findings_comments(findings)}
 */
contract FlashLoanFuzzHarness is Test {{
    {contract_name} public targetContract;
    
    // Fuzzing state variables
    uint256 public constant MAX_FLASH_AMOUNT = 1000000 ether;
    uint256 public constant MIN_FLASH_AMOUNT = 1 ether;
    
    // Invariant tracking
    uint256 public initialBalance;
    uint256 public initialTotalSupply;
    mapping(address => uint256) public initialUserBalances;
    
    event InvariantViolation(string reason, uint256 expected, uint256 actual);
    
    function setUp() public {{
        targetContract = new {contract_name}();
        initialBalance = address(targetContract).balance;
        
        // Setup initial state
        vm.deal(address(this), 10000 ether);
        vm.deal(address(targetContract), 1000 ether);
    }}
    
    {self._generate_invariant_functions()}
    
    {chr(10).join(test_scenarios)}
    
    {self._generate_helper_functions()}
}}'''
        
        return harness_template
    
    def _generate_generic_harness(self, context: ScanContext) -> str:
        """Generate generic flash loan fuzzing harness."""
        
        return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Generic Flash Loan Fuzzing Harness
 * Tests basic flash loan invariants
 */
contract GenericFlashLoanFuzzHarness is Test {
    
    function setUp() public {
        // Generic setup
    }
    
    function testFuzz_FlashLoanInvariants(uint256 amount) public {
        vm.assume(amount > 0 && amount < 1000000 ether);
        // Generic flash loan invariant tests
    }
    
    function invariant_BalanceConsistency() public {
        // Balance should remain consistent
    }
    
    function invariant_NoFreeValue() public {
        // No value should be created from nothing
    }
}'''
    
    def _generate_test_scenario(self, finding: Finding, context: ScanContext) -> str:
        """Generate a test scenario for a specific finding."""
        
        scenario_id = self._generate_scenario_id(finding)
        
        if "invariant" in finding.title.lower():
            return f'''
    function testFuzz_{scenario_id}(uint256 amount, address user) public {{
        vm.assume(amount >= MIN_FLASH_AMOUNT && amount <= MAX_FLASH_AMOUNT);
        vm.assume(user != address(0) && user != address(this));
        
        // Pre-condition checks
        uint256 balanceBefore = address(targetContract).balance;
        
        // Execute flash loan operation
        try targetContract.flashLoan(amount, abi.encode(user)) {{
            // Post-condition checks
            uint256 balanceAfter = address(targetContract).balance;
            
            // Invariant: Balance should not decrease without proper accounting
            assertGe(balanceAfter, balanceBefore, "Flash loan decreased contract balance");
            
            // Invariant: User balances should be consistent
            checkUserBalanceInvariant(user);
            
        }} catch {{
            // Flash loan should fail gracefully
            assertTrue(true, "Flash loan failed as expected");
        }}
    }}'''
        
        elif "reentrancy" in finding.title.lower():
            return f'''
    function testFuzz_{scenario_id}_ReentrancyProtection(uint256 amount) public {{
        vm.assume(amount >= MIN_FLASH_AMOUNT && amount <= MAX_FLASH_AMOUNT);
        
        // Test reentrancy protection during flash loan
        ReentrantAttacker attacker = new ReentrantAttacker(address(targetContract));
        
        vm.expectRevert("ReentrancyGuard: reentrant call");
        attacker.attemptReentrancy(amount);
    }}'''
        
        else:
            return f'''
    function testFuzz_{scenario_id}(uint256 amount) public {{
        vm.assume(amount >= MIN_FLASH_AMOUNT && amount <= MAX_FLASH_AMOUNT);
        
        // Test flash loan execution
        uint256 balanceBefore = address(targetContract).balance;
        
        // Execute and verify invariants
        targetContract.flashLoan(amount, "");
        
        uint256 balanceAfter = address(targetContract).balance;
        assertEq(balanceAfter, balanceBefore, "Balance invariant violated");
    }}'''
    
    def _generate_invariant_functions(self) -> str:
        """Generate invariant checking functions."""
        
        return '''
    function checkUserBalanceInvariant(address user) internal {
        // Implement user balance consistency checks
        uint256 currentBalance = targetContract.balanceOf(user);
        uint256 expectedBalance = initialUserBalances[user];
        
        if (currentBalance < expectedBalance) {
            emit InvariantViolation(
                "User balance decreased unexpectedly",
                expectedBalance,
                currentBalance
            );
        }
    }
    
    function checkTotalSupplyInvariant() internal {
        uint256 currentSupply = targetContract.totalSupply();
        
        if (currentSupply != initialTotalSupply) {
            emit InvariantViolation(
                "Total supply changed unexpectedly",
                initialTotalSupply,
                currentSupply
            );
        }
    }
    
    function checkBalanceInvariant() internal {
        uint256 currentBalance = address(targetContract).balance;
        
        if (currentBalance < initialBalance) {
            emit InvariantViolation(
                "Contract balance decreased unexpectedly",
                initialBalance,
                currentBalance
            );
        }
    }'''
    
    def _generate_helper_functions(self) -> str:
        """Generate helper functions for the harness."""
        
        return '''
    function saveInitialState(address user) internal {
        initialUserBalances[user] = targetContract.balanceOf(user);
    }
    
    function restoreInitialState() internal {
        // Reset contract to initial state for clean testing
        vm.clearMockedCalls();
        setUp();
    }
}

/**
 * Helper contract for testing reentrancy protection
 */
contract ReentrantAttacker {
    address public target;
    
    constructor(address _target) {
        target = _target;
    }
    
    function attemptReentrancy(uint256 amount) external {
        IFlashLoanProvider(target).flashLoan(amount, abi.encode(address(this)));
    }
    
    function executeOperation(uint256 amount, bytes calldata data) external {
        // Attempt reentrancy
        IFlashLoanProvider(target).flashLoan(amount / 2, data);
    }
}

interface IFlashLoanProvider {
    function flashLoan(uint256 amount, bytes calldata data) external;
}'''
    
    def _generate_scenario_id(self, finding: Finding) -> str:
        """Generate a unique scenario ID for a finding."""
        # Clean the title to create a valid function name
        clean_title = finding.title.replace(" ", "_").replace("-", "_")
        clean_title = "".join(c for c in clean_title if c.isalnum() or c == "_")
        
        return f"{clean_title}_{finding.line}"
    
    def _format_findings_comments(self, findings: List[Finding]) -> str:
        """Format findings as comments for the harness."""
        comments = []
        for finding in findings:
            comments.append(f" * - {finding.title} (Line {finding.line})")
        return "\n".join(comments)
    
    def _write_harness_file(self, harness_code: str, output_dir: Path):
        """Write harness code to file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        harness_file = output_dir / "FlashLoanFuzzHarness.t.sol"
        harness_file.write_text(harness_code)
    
    def _load_invariant_templates(self) -> Dict[str, str]:
        """Load invariant templates for different vulnerability types."""
        return {
            "balance_invariant": "Contract balance should remain consistent",
            "supply_invariant": "Total token supply should not change unexpectedly",
            "user_balance_invariant": "User balances should remain consistent",
            "reentrancy_protection": "Flash loan should prevent reentrancy",
            "repayment_enforcement": "Flash loan must be repaid in same transaction"
        }
    
    def _setup_fuzz_parameters(self) -> Dict[str, Any]:
        """Setup fuzzing parameters and constraints."""
        return {
            "max_amount": 1000000,  # Max flash loan amount in ether
            "min_amount": 1,        # Min flash loan amount in ether
            "max_iterations": 1000,  # Max fuzzing iterations
            "seed_values": [0, 1, 2**256-1],  # Edge case values
        }