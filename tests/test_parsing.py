"""
Tests for the Solidity parser module.
"""

import pytest
from pathlib import Path
import tempfile

from vulnhuntr.core.parser import SolidityParser

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
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
}
"""

@pytest.fixture
def parser():
    """Create a parser instance for tests."""
    try:
        return SolidityParser()
    except RuntimeError:
        pytest.skip("Solidity parser not properly configured")

@pytest.fixture
def sample_file():
    """Create a temporary file with sample Solidity code."""
    with tempfile.NamedTemporaryFile(suffix=".sol", delete=False) as f:
        f.write(SAMPLE_CONTRACT.encode("utf-8"))
        return f.name

def test_parser_initialization(parser):
    """Test that the parser initializes correctly."""
    assert parser.parser is not None
    assert parser.language is not None

def test_parse_file(parser, sample_file):
    """Test parsing a file."""
    tree, content = parser.parse_file(sample_file)
    assert tree is not None
    assert content == SAMPLE_CONTRACT

def test_find_contracts(parser, sample_file):
    """Test finding contracts in parsed file."""
    tree, _ = parser.parse_file(sample_file)
    contracts = parser.find_contracts(tree)
    
    assert len(contracts) == 1
    assert contracts[0]["name"] == "TestContract"
    assert contracts[0]["type"] == "contract"

def test_find_functions(parser, sample_file):
    """Test finding functions in parsed file."""
    tree, _ = parser.parse_file(sample_file)
    functions = parser.find_functions(tree)
    
    # Should find constructor, transferOwnership, and withdraw
    assert len(functions) == 3
    
    function_names = [f["name"] for f in functions]
    assert "constructor" in function_names
    assert "transferOwnership" in function_names
    assert "withdraw" in function_names

def test_extract_function_calls(parser, sample_file):
    """Test extracting function calls from a function."""
    tree, _ = parser.parse_file(sample_file)
    functions = parser.find_functions(tree)
    
    # Find withdraw function
    withdraw_func = None
    for func in functions:
        if func["name"] == "withdraw":
            withdraw_func = func
            break
    
    assert withdraw_func is not None
    
    # Extract calls
    calls = parser.extract_function_calls(withdraw_func["node"])
    
    # Should have at least 2 calls: balance and call
    assert len(calls) >= 2
    
    # Verify call structure
    call_methods = []
    for call in calls:
        if call["type"] == "member" and "method" in call:
            call_methods.append(call["method"])
    
    assert "balance" in call_methods
    assert "call" in call_methods

def test_is_external_call(parser, sample_file):
    """Test detection of external calls."""
    tree, _ = parser.parse_file(sample_file)
    functions = parser.find_functions(tree)
    
    # Find withdraw function
    withdraw_func = None
    for func in functions:
        if func["name"] == "withdraw":
            withdraw_func = func
            break
    
    assert withdraw_func is not None
    
    # Extract calls
    calls = parser.extract_function_calls(withdraw_func["node"])
    
    # Find the call method
    call_node = None
    for call in calls:
        if call["type"] == "member" and "method" in call and call["method"] == "call":
            call_node = call
            break
    
    assert call_node is not None
    assert parser.is_external_call(call_node)

def test_non_external_call(parser, sample_file):
    """Test detection of non-external calls."""
    # Create a dictionary simulating a non-external call
    non_external_call = {
        "type": "member",
        "method": "length"
    }
    
    assert not parser.is_external_call(non_external_call)