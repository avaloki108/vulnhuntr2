// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract OraclePair {
    IPriceOracle public oracle;
    address public tokenA;
    address public tokenB;
    
    event PriceUpdated(address indexed token, uint256 price);
    event SwapExecuted(address indexed user, uint256 amountIn, uint256 amountOut);
    
    constructor(address _oracle, address _tokenA, address _tokenB) {
        oracle = IPriceOracle(_oracle);
        tokenA = _tokenA;
        tokenB = _tokenB;
    }
    
    function getPrice(address token) external view returns (uint256) {
        return oracle.getPrice(token);
    }
    
    function updatePrice(address token, uint256 newPrice) external {
        // Privileged function without proper access control
        emit PriceUpdated(token, newPrice);
    }
    
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 priceA = oracle.getPrice(tokenA);
        uint256 priceB = oracle.getPrice(tokenB);
        
        amountOut = (amountIn * priceA) / priceB;
        
        emit SwapExecuted(msg.sender, amountIn, amountOut);
        return amountOut;
    }
    
    function emergencyWithdraw() external {
        // Critical function without events
        // Should emit an event for transparency
    }
}