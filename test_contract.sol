// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool private locked;

    modifier noReentrancy() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    // Vulnerable withdraw function - missing reentrancy protection
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State updated after external call - vulnerable to reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }

    // Another vulnerable function - using tx.origin
    function emergencyWithdraw() external {
        require(tx.origin == msg.sender, "Only EOA allowed");
        uint256 balance = balances[msg.sender];
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    // Vulnerable to integer overflow in older Solidity versions
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount; // Potential overflow
    }

    // Unsafe delegatecall
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
