"""Tests for Slither adapter integration."""
import pytest
from pathlib import Path

# Try to import slither to check availability
try:
    import slither
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False

from vulnhuntr.parsing.slither_adapter import run_slither, SlitherAnalysisResult


@pytest.fixture
def simple_fixtures_dir():
    """Get path to simple test fixtures."""
    return Path(__file__).parent / "fixtures" / "simple"


@pytest.mark.skipif(not SLITHER_AVAILABLE, reason="Slither not installed")
def test_slither_adapter_basic_extraction(simple_fixtures_dir):
    """Test that Slither adapter can extract basic contract information."""
    result = run_slither(simple_fixtures_dir)
    
    assert result is not None
    assert isinstance(result, SlitherAnalysisResult)
    assert len(result.contracts) >= 1  # Should find at least one contract
    
    # Check that we have the expected contracts
    contract_names = {contract.name for contract in result.contracts}
    assert "OwnableLike" in contract_names
    assert "OraclePair" in contract_names


@pytest.mark.skipif(not SLITHER_AVAILABLE, reason="Slither not installed")
def test_slither_adapter_function_extraction(simple_fixtures_dir):
    """Test that Slither adapter extracts function information correctly."""
    result = run_slither(simple_fixtures_dir)
    
    assert result is not None
    
    # Find OwnableLike contract
    ownable = next((c for c in result.contracts if c.name == "OwnableLike"), None)
    assert ownable is not None
    
    # Check functions were extracted
    assert len(ownable.functions) > 0
    function_names = {func.name for func in ownable.functions}
    assert "transferOwnership" in function_names
    assert "criticalAction" in function_names
    
    # Check function details
    transfer_func = next((f for f in ownable.functions if f.name == "transferOwnership"), None)
    assert transfer_func is not None
    assert transfer_func.visibility == "external"
    assert "onlyOwner" in transfer_func.modifiers


@pytest.mark.skipif(not SLITHER_AVAILABLE, reason="Slither not installed")
def test_slither_adapter_state_variables(simple_fixtures_dir):
    """Test that Slither adapter extracts state variables."""
    result = run_slither(simple_fixtures_dir)
    
    assert result is not None
    
    # Find OwnableLike contract
    ownable = next((c for c in result.contracts if c.name == "OwnableLike"), None)
    assert ownable is not None
    
    # Check state variables
    assert len(ownable.state_vars) > 0
    var_names = {var.name for var in ownable.state_vars}
    assert "owner" in var_names


@pytest.mark.skipif(not SLITHER_AVAILABLE, reason="Slither not installed")
def test_slither_adapter_serialization(simple_fixtures_dir):
    """Test that SlitherAnalysisResult can be serialized to dict."""
    result = run_slither(simple_fixtures_dir)
    
    assert result is not None
    
    # Test serialization
    serialized = result.to_dict()
    assert isinstance(serialized, dict)
    assert "contracts" in serialized
    assert isinstance(serialized["contracts"], list)
    
    # Check contract structure
    if serialized["contracts"]:
        contract = serialized["contracts"][0]
        assert "name" in contract
        assert "file" in contract
        assert "functions" in contract
        assert "state_vars" in contract


def test_slither_adapter_graceful_failure():
    """Test that adapter handles missing Slither gracefully."""
    from vulnhuntr.parsing import slither_adapter
    
    # Temporarily disable Slither availability
    original_available = slither_adapter.SLITHER_AVAILABLE
    slither_adapter.SLITHER_AVAILABLE = False
    
    try:
        result = run_slither(Path("/nonexistent"))
        assert result is None
    finally:
        # Restore original state
        slither_adapter.SLITHER_AVAILABLE = original_available


def test_slither_adapter_invalid_path():
    """Test that adapter handles invalid paths gracefully."""
    if not SLITHER_AVAILABLE:
        pytest.skip("Slither not available")
    
    result = run_slither(Path("/completely/nonexistent/path"))
    assert result is None  # Should return None for failed analysis