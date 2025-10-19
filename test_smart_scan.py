#!/usr/bin/env python3
"""
Test script for the enhanced VulnHuntr2 smart scan functionality.
Demonstrates Ollama-powered holistic contract analysis.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def create_test_contracts():
    """Create sample smart contracts for testing."""

    # Create a temporary directory for test contracts
    test_dir = Path(tempfile.mkdtemp(prefix="vulnhuntr_test_"))

    # Create a vulnerable DEX contract
    dex_contract = test_dir / "DEX.sol"
    dex_contract.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";

contract DEX {
    mapping(address => mapping(address => uint256)) public liquidity;
    mapping(address => uint256) public reserves;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable to reentrancy
    function swap(address tokenA, address tokenB, uint256 amountIn) external {
        require(reserves[tokenA] > 0 && reserves[tokenB] > 0, "Insufficient liquidity");

        uint256 amountOut = getAmountOut(amountIn, tokenA, tokenB);

        // Transfer tokens (vulnerable - external call before state change)
        Token(tokenA).transferFrom(msg.sender, address(this), amountIn);
        Token(tokenB).transfer(msg.sender, amountOut);

        // Update reserves after external calls (vulnerable!)
        reserves[tokenA] += amountIn;
        reserves[tokenB] -= amountOut;
    }

    function getAmountOut(uint256 amountIn, address tokenA, address tokenB)
        public view returns (uint256) {
        // Simplified AMM formula - vulnerable to price manipulation
        return (reserves[tokenB] * amountIn) / (reserves[tokenA] + amountIn);
    }

    // Missing access control
    function setReserves(address token, uint256 amount) external {
        reserves[token] = amount;  // Anyone can manipulate reserves!
    }

    function addLiquidity(address token, uint256 amount) external {
        Token(token).transferFrom(msg.sender, address(this), amount);
        liquidity[msg.sender][token] += amount;
        reserves[token] += amount;
    }
}
""")

    # Create a token contract with vulnerabilities
    token_contract = test_dir / "Token.sol"
    token_contract.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    uint256 public totalSupply;
    string public name;
    string public symbol;
    address public owner;

    constructor(string memory _name, string memory _symbol, uint256 _supply) {
        name = _name;
        symbol = _symbol;
        totalSupply = _supply;
        balances[msg.sender] = _supply;
        owner = msg.sender;
    }

    // Vulnerable to integer overflow (if using older Solidity)
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;  // Potential overflow

        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external returns (bool) {
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");

        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;

        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    // Dangerous mint function without proper access control
    function mint(address to, uint256 amount) external {
        // Only owner should be able to mint, but no check!
        totalSupply += amount;
        balances[to] += amount;
    }

    // Backdoor function
    function emergencyDrain(address to) external {
        require(msg.sender == owner, "Only owner");
        // Drains all tokens to specified address - centralization risk
        balances[to] = totalSupply;
    }
}
""")

    # Create a governance contract with vulnerabilities
    governance_contract = test_dir / "Governance.sol"
    governance_contract.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";
import "./DEX.sol";

contract Governance {
    struct Proposal {
        address target;
        bytes data;
        uint256 votes;
        bool executed;
        uint256 deadline;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;

    Token public governanceToken;
    DEX public dex;

    constructor(address _token, address _dex) {
        governanceToken = Token(_token);
        dex = DEX(_dex);
    }

    // Vulnerable to flash loan governance attacks
    function vote(uint256 proposalId) external {
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(block.timestamp < proposals[proposalId].deadline, "Voting ended");

        // Uses current balance for voting power - vulnerable to flash loans!
        uint256 votingPower = governanceToken.balances(msg.sender);

        proposals[proposalId].votes += votingPower;
        hasVoted[proposalId][msg.sender] = true;
    }

    // Cross-contract vulnerability - can manipulate DEX through governance
    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.votes > getTotalSupply() / 2, "Insufficient votes");
        require(!proposal.executed, "Already executed");
        require(block.timestamp >= proposal.deadline, "Voting still active");

        proposal.executed = true;

        // Dangerous arbitrary call - can call any function on any contract!
        (bool success,) = proposal.target.call(proposal.data);
        require(success, "Execution failed");
    }

    function getTotalSupply() public view returns (uint256) {
        return governanceToken.totalSupply();
    }

    // Missing access control - anyone can create proposals
    function createProposal(address target, bytes calldata data, uint256 duration)
        external returns (uint256) {
        uint256 proposalId = proposalCount++;

        proposals[proposalId] = Proposal({
            target: target,
            data: data,
            votes: 0,
            executed: false,
            deadline: block.timestamp + duration
        });

        return proposalId;
    }
}
""")

    print(f"Created test contracts in: {test_dir}")
    print("Contracts:")
    for contract in test_dir.glob("*.sol"):
        print(f"  - {contract.name}")

    return test_dir

def test_enhanced_orchestrator():
    """Test the enhanced orchestrator directly."""
    print("\n=== Testing Enhanced Orchestrator ===")

    try:
        from vulnhuntr.core.enhanced_orchestrator import EnhancedVulnHuntrOrchestrator
        from vulnhuntr.config.settings import Settings, OllamaConfig, CrossContractConfig
        from vulnhuntr.core.models import ScanContext

        # Create settings
        settings = Settings()
        settings.ollama = OllamaConfig(
            enabled=True,
            model="qwen2.5-coder:32b",
            base_url="http://localhost:11434"
        )
        settings.cross_contract = CrossContractConfig(enabled=True)

        # Create test contracts
        test_dir = create_test_contracts()
        contract_paths = list(test_dir.glob("*.sol"))

        # Initialize orchestrator
        orchestrator = EnhancedVulnHuntrOrchestrator(settings)

        # Check Ollama availability
        if orchestrator.enhanced_llm_engine and orchestrator.enhanced_llm_engine.ollama_client:
            if orchestrator.enhanced_llm_engine.ollama_client.is_available():
                print("✅ Ollama client is available")
            else:
                print("⚠️ Ollama client not available - using fallback")

        # Create scan context
        scan_context = ScanContext(
            enable_poc_generation=True,
            enable_correlation=True,
            target_paths=[str(p) for p in contract_paths]
        )

        # Run scan
        print(f"Scanning {len(contract_paths)} contracts...")
        results = orchestrator.scan_contracts(contract_paths, scan_context)

        # Display results
        findings = results.get('findings', [])
        print(f"Found {len(findings)} vulnerabilities")

        # Show first few findings
        for i, finding in enumerate(findings[:5]):
            print(f"\n{i+1}. {finding.title}")
            print(f"   Severity: {finding.severity.value}")
            print(f"   Detector: {finding.detector}")
            print(f"   Contract: {finding.contract_name}")

        # Show cross-contract analysis if available
        if cross_analysis := results.get('cross_contract_analysis'):
            critical_findings = cross_analysis.get('critical_findings', [])
            print(f"\nCross-contract analysis found {len(critical_findings)} complex vulnerabilities")

            for finding in critical_findings[:3]:
                print(f"  - {finding.get('title', 'Unnamed')}: {finding.get('severity', 'UNKNOWN')}")

        # Show ecosystem analysis
        if ecosystem := results.get('contract_analysis'):
            print(f"\nEcosystem Analysis:")
            print(f"  Total contracts: {ecosystem.get('total_contracts', 0)}")
            print(f"  Critical contracts: {ecosystem.get('critical_contracts', [])}")

        return True

    except Exception as e:
        print(f"Error in enhanced orchestrator test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_contract_graph():
    """Test the contract graph builder."""
    print("\n=== Testing Contract Graph Builder ===")

    try:
        from vulnhuntr.core.contract_graph import ContractGraphBuilder

        # Create test contracts
        test_dir = create_test_contracts()
        contract_paths = list(test_dir.glob("*.sol"))

        # Build contract graph
        builder = ContractGraphBuilder()
        graph = builder.analyze_project(contract_paths)

        print(f"Built graph with {len(graph.contracts)} contracts")
        print(f"Found {len(graph.relations)} relationships")

        # Show contracts
        for name, contract in graph.contracts.items():
            print(f"\nContract: {name}")
            print(f"  Functions: {len(contract.functions)}")
            print(f"  State variables: {len(contract.state_variables)}")
            print(f"  Is proxy: {contract.is_proxy}")

        # Show relationships
        print(f"\nRelationships:")
        for relation in graph.relations[:10]:  # Show first 10
            print(f"  {relation.from_contract} --{relation.relation_type.value}--> {relation.to_contract}")

        # Show analysis
        summary = graph.get_interaction_summary()
        print(f"\nInteraction Summary:")
        print(f"  Total contracts: {summary['total_contracts']}")
        print(f"  Total relations: {summary['total_relations']}")
        print(f"  Critical contracts: {summary['critical_contracts']}")

        return True

    except Exception as e:
        print(f"Error in contract graph test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ollama_client():
    """Test the Ollama client."""
    print("\n=== Testing Ollama Client ===")

    try:
        from vulnhuntr.core.ollama_client import OllamaClient, OllamaConfig

        config = OllamaConfig(
            model="qwen2.5-coder:32b",
            base_url="http://localhost:11434"
        )

        client = OllamaClient(config)

        if client.is_available():
            print("✅ Ollama client is available")

            # Test simple chat
            response = client.chat("Explain what a reentrancy vulnerability is in one sentence.")
            print(f"Response: {response[:200]}...")

            return True
        else:
            print("⚠️ Ollama client not available")
            print("Make sure Ollama is running and the model is pulled:")
            print("  ollama pull qwen2.5-coder:32b")
            return False

    except Exception as e:
        print(f"Error in Ollama client test: {e}")
        return False

def main():
    """Run all tests."""
    print("🧠 VulnHuntr2 Smart Scan Tests")
    print("=" * 50)

    # Test individual components
    tests = [
        ("Ollama Client", test_ollama_client),
        ("Contract Graph", test_contract_graph),
        ("Enhanced Orchestrator", test_enhanced_orchestrator),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} failed: {e}")
            results[test_name] = False

    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)

    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:25} {status}")

    # Overall result
    all_passed = all(results.values())
    print(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")

    if not all_passed:
        print("\nTo fix issues:")
        print("1. Make sure Ollama is running: ollama serve")
        print("2. Pull the recommended model: ollama pull qwen2.5-coder:32b")
        print("3. Check that all dependencies are installed: pip install -e .[dev,full]")

    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)