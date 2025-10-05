// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice Example contract demonstrating various vulnerability patterns
 * @dev THIS IS FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    // Missing event for ownership transfer
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;  // VULNERABILITY: No event emitted
    }

    // Reentrancy vulnerability - state changed after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State updated after external call - reentrancy risk
        balances[msg.sender] -= amount;
    }

    // VULNERABILITY: Missing access control
    function emergencyDrain() external {
        // Anyone can call this!
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    // VULNERABILITY: Delegatecall to untrusted address
    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // VULNERABILITY: Insecure randomness
    function getRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
    }

    // Proper deposit function with events
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    event Deposit(address indexed user, uint256 amount);
}
