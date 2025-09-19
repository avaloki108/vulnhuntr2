"""
Tests for the mutation framework module.
"""

import pytest
from pathlib import Path
import tempfile

from vulnhuntr.core.mutations import (
    MutationOperator,
    FunctionVisibilityMutator, 
    AccessControlRemovalMutator,
    ReentrancyMutator,
    MutationEngine,
    create_default_engine
)

# Sample Solidity contract for testing
SAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
    
    function withdraw() public onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call("");
        require(success, "Transfer failed");
    }
}
"""


def test_create_default_engine():
    engine = create_default_engine()
    assert isinstance(engine, MutationEngine)
    # Should have at least the 3 default operators
    assert len(engine.operators) >= 3


def test_generate_mutations(tmp_path: Path):
    # Write sample contract to temp file
    sample = tmp_path / "TestContract.sol"
    sample.write_text(SAMPLE_CONTRACT)

    engine = create_default_engine()
    mutations = engine.generate_mutations(str(sample))

    assert isinstance(mutations, list)
    # We expect some mutations (regex-based) but not asserting exact count
    assert all("description" in m for m in mutations)
    assert all("content" in m for m in mutations)
