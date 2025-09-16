"""
Tests for CI gating conditions and reporting.
"""
import tempfile
from pathlib import Path

from vulnhuntr.core.models import Finding, Severity
from vulnhuntr.core.reporting import ReportingEngine
from vulnhuntr.config.schema import RunConfig


def create_sample_finding(severity: Severity, confidence: float = 0.7) -> Finding:
    """Helper to create sample findings for testing."""
    return Finding(
        detector="test_detector",
        title="Test Finding",
        file="/test/file.sol",
        line=10,
        severity=severity,
        code="test code",
        confidence=confidence
    )


def test_gating_fail_on_findings():
    """Test basic fail_on_findings gating."""
    config = RunConfig()
    config.reporting.fail_on_findings = True
    
    engine = ReportingEngine(config)
    
    # Test with no findings - should pass
    exit_code, reasons, report = engine.package_results([], [], [], [], [])
    assert exit_code == 0
    assert len(reasons) == 0
    
    # Test with findings - should fail
    findings = [create_sample_finding(Severity.LOW)]
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 1
    assert len(reasons) == 1
    assert "1 findings (fail_on_findings=true)" in reasons[0]


def test_gating_severity_threshold():
    """Test severity-based gating."""
    config = RunConfig()
    config.reporting.fail_on_severity = "HIGH"
    
    engine = ReportingEngine(config)
    
    # Test with only low/medium findings - should pass
    findings = [
        create_sample_finding(Severity.LOW),
        create_sample_finding(Severity.MEDIUM)
    ]
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 0
    assert len(reasons) == 0
    
    # Test with high severity finding - should fail
    findings.append(create_sample_finding(Severity.HIGH))
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 1
    assert len(reasons) == 1
    assert "HIGH" in reasons[0] and "fail_on_severity=HIGH" in reasons[0]


def test_gating_confidence_threshold():
    """Test confidence-based gating."""
    config = RunConfig()
    config.reporting.fail_on_confidence = 0.8
    
    engine = ReportingEngine(config)
    
    # Test with low confidence findings - should pass
    findings = [
        create_sample_finding(Severity.HIGH, confidence=0.5),
        create_sample_finding(Severity.CRITICAL, confidence=0.7)
    ]
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 0
    assert len(reasons) == 0
    
    # Test with high confidence finding - should fail
    findings.append(create_sample_finding(Severity.MEDIUM, confidence=0.9))
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 1
    assert len(reasons) == 1
    assert "0.8 confidence" in reasons[0]


def test_gating_finding_count_threshold():
    """Test finding count-based gating."""
    config = RunConfig()
    config.reporting.fail_on_finding_count = 3
    
    engine = ReportingEngine(config)
    
    # Test with fewer findings - should pass
    findings = [
        create_sample_finding(Severity.LOW),
        create_sample_finding(Severity.MEDIUM)
    ]
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 0
    assert len(reasons) == 0
    
    # Test with threshold count - should fail
    findings.append(create_sample_finding(Severity.LOW))
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 1
    assert len(reasons) == 1
    assert "3 findings >= 3" in reasons[0]


def test_gating_multiple_conditions():
    """Test multiple gating conditions triggering."""
    config = RunConfig()
    config.reporting.fail_on_severity = "MEDIUM"
    config.reporting.fail_on_confidence = 0.6
    config.reporting.fail_on_finding_count = 2
    
    engine = ReportingEngine(config)
    
    # Create findings that trigger all conditions
    findings = [
        create_sample_finding(Severity.HIGH, confidence=0.8),  # Triggers severity + confidence
        create_sample_finding(Severity.MEDIUM, confidence=0.7)  # Triggers count + others
    ]
    
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    assert exit_code == 1
    assert len(reasons) == 3  # All three conditions triggered
    
    # Check that all expected reasons are present
    reasons_text = " ".join(reasons)
    assert "MEDIUM" in reasons_text
    assert "0.6 confidence" in reasons_text
    assert "2 findings >= 2" in reasons_text


def test_report_metadata_structure():
    """Test that report metadata has correct structure."""
    config = RunConfig()
    engine = ReportingEngine(config)
    
    findings = [create_sample_finding(Severity.HIGH)]
    enabled_detectors = ["test_detector"]
    warnings = ["test warning"]
    
    exit_code, reasons, report = engine.package_results(findings, findings, [], enabled_detectors, warnings)
    
    assert "meta" in report
    meta = report["meta"]
    
    # Check required metadata fields
    assert "version" in meta
    assert "config_hash" in meta
    assert "run_started" in meta
    assert "run_finished" in meta
    assert "total_findings" in meta
    assert "detectors_enabled" in meta
    assert "detector_names" in meta
    assert "gating" in meta
    assert "warnings" in meta
    
    # Check gating structure
    gating = meta["gating"]
    assert "triggered" in gating
    assert "reasons" in gating
    assert isinstance(gating["triggered"], bool)
    assert isinstance(gating["reasons"], list)
    
    # Check metadata values
    assert meta["total_findings"] == 1
    assert meta["detectors_enabled"] == 1
    assert meta["warnings"] == warnings


def test_exit_summary_formatting():
    """Test exit summary formatting."""
    config = RunConfig()
    engine = ReportingEngine(config)
    
    # Test success case
    summary = engine.format_exit_summary(0, [])
    assert "✅ All gating conditions passed" in summary
    
    # Test failure case with multiple reasons
    reasons = [
        "Found 5 findings >= HIGH (fail_on_severity=HIGH)",
        "Found 3 findings >= 0.8 confidence (fail_on_confidence=0.8)"
    ]
    summary = engine.format_exit_summary(1, reasons)
    assert "❌ CI gating triggered:" in summary
    assert "1. Found 5 findings >= HIGH" in summary
    assert "2. Found 3 findings >= 0.8" in summary


def test_invalid_gating_configuration():
    """Test handling of invalid gating configuration."""
    config = RunConfig()
    config.reporting.fail_on_severity = "INVALID_SEVERITY"
    
    engine = ReportingEngine(config)
    findings = [create_sample_finding(Severity.HIGH)]
    
    exit_code, reasons, report = engine.package_results(findings, findings, [], [], [])
    
    # Should still fail but with an error reason
    assert exit_code == 1
    assert len(reasons) == 1
    assert "Invalid fail_on_severity" in reasons[0]