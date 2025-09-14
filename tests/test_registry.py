from vulnhuntr.core.registry import get_registered_detectors
import importlib


def test_detectors_registered():
    # Import detectors package to trigger registration side-effects
    importlib.import_module("vulnhuntr.detectors")
    detectors = get_registered_detectors()
    names = {d.name for d in detectors}
    assert "reentrancy_heuristic" in names
