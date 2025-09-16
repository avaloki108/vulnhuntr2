"""
Tests for detector selector matching logic.
"""
from vulnhuntr.detectors import explain_selector, _match_detectors
from vulnhuntr.core.registry import get_registered_detectors


def test_exact_selector_matching():
    """Test exact detector name matching."""
    all_detectors = get_registered_detectors()
    
    # Test exact match
    matches = _match_detectors(all_detectors, "reentrancy_heuristic")
    assert len(matches) == 1
    assert matches[0].name == "reentrancy_heuristic"
    
    # Test non-existent detector
    matches = _match_detectors(all_detectors, "non_existent_detector")
    assert len(matches) == 0


def test_glob_selector_matching():
    """Test glob pattern matching."""
    all_detectors = get_registered_detectors()
    
    # Test wildcard at end
    matches = _match_detectors(all_detectors, "*_heuristic")
    detector_names = [d.name for d in matches]
    assert "reentrancy_heuristic" in detector_names
    
    # Test wildcard at start
    matches = _match_detectors(all_detectors, "reentrancy_*")
    detector_names = [d.name for d in matches]
    assert "reentrancy_heuristic" in detector_names
    
    # Test wildcard in middle
    matches = _match_detectors(all_detectors, "*_chain_*")
    detector_names = [d.name for d in matches]
    assert "cross_chain_relay_replay" in detector_names


def test_category_selector_matching():
    """Test category-based selector matching."""
    all_detectors = get_registered_detectors()
    
    # Test specific category
    matches = _match_detectors(all_detectors, "category:reentrancy")
    assert len(matches) >= 1
    for detector in matches:
        assert detector.category == "reentrancy"
    
    # Test category wildcard
    matches = _match_detectors(all_detectors, "category:*")
    assert len(matches) == len(all_detectors)  # Should match all detectors
    
    # Test category pattern
    matches = _match_detectors(all_detectors, "category:cross_*")
    detector_names = [d.name for d in matches]
    assert "cross_chain_relay_replay" in detector_names


def test_explain_selector_structure():
    """Test the explain_selector function returns proper structure."""
    explanation = explain_selector("category:*")
    
    assert "selector" in explanation
    assert "match_type" in explanation
    assert "matched_count" in explanation
    assert "matched_detectors" in explanation
    
    assert explanation["selector"] == "category:*"
    assert explanation["match_type"] == "category"
    assert explanation["matched_count"] > 0
    assert isinstance(explanation["matched_detectors"], list)
    
    if explanation["matched_detectors"]:
        detector_info = explanation["matched_detectors"][0]
        assert "name" in detector_info
        assert "category" in detector_info
        assert "description" in detector_info


def test_explain_selector_match_types():
    """Test that explain_selector correctly identifies match types."""
    # Test exact match
    explanation = explain_selector("reentrancy_heuristic")
    assert explanation["match_type"] == "exact"
    
    # Test glob match
    explanation = explain_selector("*_heuristic")
    assert explanation["match_type"] == "glob"
    
    # Test category match
    explanation = explain_selector("category:reentrancy")
    assert explanation["match_type"] == "category"


def test_empty_selector_matching():
    """Test behavior with selectors that match nothing."""
    all_detectors = get_registered_detectors()
    
    # Test non-existent exact match
    matches = _match_detectors(all_detectors, "nonexistent_detector")
    assert len(matches) == 0
    
    # Test non-existent category
    matches = _match_detectors(all_detectors, "category:nonexistent")
    assert len(matches) == 0
    
    # Test non-matching glob
    matches = _match_detectors(all_detectors, "xyz*abc")
    assert len(matches) == 0


def test_selector_case_sensitivity():
    """Test that selectors are case-sensitive as expected."""
    all_detectors = get_registered_detectors()
    
    # Test exact match with wrong case (should not match)
    matches = _match_detectors(all_detectors, "REENTRANCY_HEURISTIC")
    assert len(matches) == 0
    
    # Test category with wrong case (should not match)
    matches = _match_detectors(all_detectors, "category:REENTRANCY")
    assert len(matches) == 0