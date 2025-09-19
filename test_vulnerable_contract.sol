// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test contract with multiple complex vulnerabilities for testing advanced detection
 */

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IFlashLoanReceiver {
    function executeOperation(uint256 amount, uint256 fee, bytes calldata data) external;
}

contract VulnerableDefi {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => bool) public admins;

    address public owner;
    address public oracle;
    uint256 public totalSupply;
    uint256 public exchangeRate;

    // Governance variables
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    struct Proposal {
        address proposer;
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    constructor(address _oracle) {
        owner = msg.sender;
        oracle = _oracle;
        admins[msg.sender] = true;
    }

    // Vulnerability 1: Cross-function reentrancy
    function deposit() external payable {
        uint256 price = IOracle(oracle).getPrice(address(this));
        uint256 shares = (msg.value * 1e18) / price;

        // State change before external call (vulnerable)
        balances[msg.sender] += shares;
        totalSupply += shares;

        // External call that could re-enter through withdraw
        (bool success,) = msg.sender.call{value: msg.value / 100}("");
        require(success, "Refund failed");
    }

    function withdraw(uint256 shares) external {
        require(balances[msg.sender] >= shares, "Insufficient balance");

        uint256 price = IOracle(oracle).getPrice(address(this));
        uint256 payout = (shares * price) / 1e18;

        // Different order than deposit - creates cross-function reentrancy
        (bool success,) = msg.sender.call{value: payout}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= shares;
        totalSupply -= shares;
    }

    // Vulnerability 2: Flash loan governance attack
    function createProposal(address target, bytes calldata data) external returns (uint256) {
        // No snapshot - vulnerable to flash loan attacks
        require(votingPower[msg.sender] > 0, "No voting power");

        uint256 proposalId = proposalCount++;
        proposals[proposalId] = Proposal({
            proposer: msg.sender,
            target: target,
            data: data,
            forVotes: 0,
            againstVotes: 0,
            executed: false
        });

        return proposalId;
    }

    function vote(uint256 proposalId, bool support) external {
        // Voting power can be borrowed via flash loan
        uint256 power = votingPower[msg.sender];
        require(power > 0, "No voting power");

        Proposal storage proposal = proposals[proposalId];

        if (support) {
            proposal.forVotes += power;
        } else {
            proposal.againstVotes += power;
        }
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes > proposal.againstVotes, "Not passed");

        proposal.executed = true;

        // Delegate call allows complete takeover
        (bool success,) = proposal.target.delegatecall(proposal.data);
        require(success, "Execution failed");
    }

    // Vulnerability 3: Oracle manipulation without TWAP
    function liquidate(address user) external {
        // Using spot price - vulnerable to manipulation
        uint256 price = IOracle(oracle).getPrice(address(this));
        uint256 userValue = (balances[user] * price) / 1e18;

        // Simple check vulnerable to flash loan manipulation
        require(userValue < 1000 * 1e18, "Not liquidatable");

        // Liquidator gets everything (MEV opportunity)
        balances[msg.sender] += balances[user];
        balances[user] = 0;
    }

    // Vulnerability 4: Hidden state mutation via assembly
    function updateExchangeRate(uint256 newRate) external onlyAdmin {
        assembly {
            // Direct storage manipulation bypassing checks
            let slot := 0x5  // Assuming exchangeRate is at slot 5
            sstore(slot, newRate)

            // Hidden manipulation of owner (critical vulnerability)
            let ownerSlot := 0x3
            sstore(ownerSlot, caller())
        }
    }

    // Vulnerability 5: Sandwich attack vulnerability
    function swap(address tokenIn, uint256 amountIn) external {
        // No slippage protection
        uint256 price = IOracle(oracle).getPrice(tokenIn);
        uint256 amountOut = (amountIn * price) / 1e18;

        // MEV bots can sandwich this transaction
        balances[msg.sender] -= amountIn;
        balances[msg.sender] += amountOut;

        // Price update happens after swap (bad pattern)
        exchangeRate = price;
    }

    // Vulnerability 6: Flash loan receiver with price manipulation
    function executeOperation(uint256 amount, uint256 fee, bytes calldata data) external {
        // This function can be called by anyone during flash loan
        // and manipulate internal state

        // Decode attack parameters
        (address target, uint256 newPrice) = abi.decode(data, (address, uint256));

        // Manipulate price oracle (if we control it temporarily)
        exchangeRate = newPrice;

        // Perform profitable action with manipulated price
        liquidate(target);

        // Repay flash loan
        require(address(this).balance >= amount + fee, "Cannot repay");
    }

    // Vulnerability 7: Privilege escalation
    function addAdmin(address newAdmin) external onlyAdmin {
        admins[newAdmin] = true;
    }

    function removeAdmin(address admin) external onlyOwner {
        // Bug: doesn't check if removing owner's admin status
        admins[admin] = false;
    }

    function emergencyWithdraw() external onlyAdmin {
        // Admin can drain contract
        payable(msg.sender).transfer(address(this).balance);
    }

    // Vulnerability 8: Invariant violation
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        // Forgot to update totalSupply - breaks invariant
        // totalSupply += amount;
    }

    // Vulnerability 9: Cross-chain replay
    function bridgeTransfer(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // Missing chain ID validation - can be replayed on other chains
        bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));

        // Simplified signature verification
        require(verifySignature(hash, signature), "Invalid signature");

        balances[to] += amount;
    }

    function verifySignature(bytes32 hash, bytes calldata signature) internal pure returns (bool) {
        // Simplified - would use ECDSA in real implementation
        return signature.length > 0;
    }

    // Receive function for accepting ETH
    receive() external payable {}
}