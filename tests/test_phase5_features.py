"""
Tests for Phase 5 features: Plugin System, AI Triage, SARIF Export, and Incremental Scanning.
"""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile
import json

from vulnhuntr.plugins import PluginManager, PluginInfo, PluginLoadStatus
from vulnhuntr.core.triage import TriageEngine, TriageResult
from vulnhuntr.core.sarif_export import SarifExporter
from vulnhuntr.core.incremental import IncrementalScanner, DiffChange
from vulnhuntr.core.pattern_engine import PatternEngine, PatternRule
from vulnhuntr.core.models import Finding, ScanContext, Severity
from vulnhuntr.config.schema import TriageConfig, PluginConfig


class TestPluginSystem:
    """Test plugin system functionality."""
    
    def test_plugin_manager_initialization(self):
        """Test plugin manager can be initialized."""
        config = {'detector_init_timeout': 1000}
        manager = PluginManager(config)
        assert manager.config == config
        assert manager.detector_init_timeout == 1000
    
    def test_plugin_info_creation(self):
        """Test plugin info dataclass."""
        info = PluginInfo(
            name="test_plugin",
            version="1.0.0",
            api_version="1.0",
            capabilities=["detector"],
            entry_point="plugin"
        )
        assert info.name == "test_plugin"
        assert "detector" in info.capabilities
    
    def test_plugin_discovery_empty_dirs(self):
        """Test plugin discovery with empty directories."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            manager = PluginManager()
            plugins = manager.discover_plugins([Path(tmp_dir)])
            assert plugins == []


class TestTriageSystem:
    """Test AI triage system functionality."""
    
    def test_triage_engine_initialization(self):
        """Test triage engine can be initialized."""
        config = TriageConfig(enable=True, model="gpt-4", max_findings=5)
        engine = TriageEngine(config)
        assert engine.config.enable
        assert engine.config.max_findings == 5
    
    def test_candidate_selection(self):
        """Test finding candidate selection."""
        config = TriageConfig(enable=True, min_severity="MEDIUM", max_findings=2)
        engine = TriageEngine(config)
        
        findings = [
            Finding(
                detector="test", title="High Severity", file="test.sol", line=1,
                severity=Severity.HIGH, code="code", confidence=0.8
            ),
            Finding(
                detector="test", title="Medium Severity", file="test.sol", line=2,
                severity=Severity.MEDIUM, code="code", confidence=0.6
            ),
            Finding(
                detector="test", title="Low Severity", file="test.sol", line=3,
                severity=Severity.LOW, code="code", confidence=0.4
            )
        ]
        
        candidates = engine._select_candidates(findings)
        assert len(candidates) == 2  # max_findings limit
        assert candidates[0].severity == Severity.HIGH  # sorted by severity
    
    def test_triage_disabled(self):
        """Test triage when disabled."""
        config = TriageConfig(enable=False)
        engine = TriageEngine(config)
        
        findings = [
            Finding(
                detector="test", title="Test", file="test.sol", line=1,
                severity=Severity.HIGH, code="code"
            )
        ]
        context = ScanContext(target_path=Path("."))
        
        results = engine.triage_findings(findings, context)
        assert results == {}


class TestSarifExport:
    """Test SARIF export functionality."""
    
    def test_sarif_exporter_initialization(self):
        """Test SARIF exporter can be initialized."""
        exporter = SarifExporter()
        assert exporter.tool_name == "vulnhuntr2"
    
    def test_sarif_document_structure(self):
        """Test SARIF document has correct structure."""
        exporter = SarifExporter()
        findings = [
            Finding(
                detector="test_detector", title="Test Finding", file="contract.sol", line=10,
                severity=Severity.HIGH, code="vulnerable_code", description="Test description"
            )
        ]
        
        sarif_doc = exporter._create_sarif_document(findings, {})
        
        assert sarif_doc["version"] == "2.1.0"
        assert "$schema" in sarif_doc
        assert "runs" in sarif_doc
        assert len(sarif_doc["runs"]) == 1
        
        run = sarif_doc["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert len(run["results"]) == 1
    
    def test_finding_to_sarif_result(self):
        """Test conversion of finding to SARIF result."""
        exporter = SarifExporter()
        finding = Finding(
            detector="test_detector", title="Test Finding", file="contract.sol", line=10,
            severity=Severity.MEDIUM, code="test_code", confidence=0.8, category="test"
        )
        
        result = exporter._create_result(finding)
        
        assert result["message"]["text"] == "Test Finding"
        assert result["level"] == "warning"  # MEDIUM maps to warning
        assert result["properties"]["confidence"] == 0.8
        assert result["properties"]["category"] == "test"
    
    def test_sarif_export_to_file(self):
        """Test exporting SARIF to file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "test.sarif"
            exporter = SarifExporter()
            
            findings = [
                Finding(
                    detector="test", title="Test", file="test.sol", line=1,
                    severity=Severity.HIGH, code="code"
                )
            ]
            
            exporter.export_findings(findings, output_path)
            
            assert output_path.exists()
            with open(output_path) as f:
                sarif_data = json.load(f)
            
            assert sarif_data["version"] == "2.1.0"
            assert len(sarif_data["runs"][0]["results"]) == 1


class TestIncrementalScanning:
    """Test incremental scanning functionality."""
    
    def test_incremental_scanner_initialization(self):
        """Test incremental scanner can be initialized."""
        scanner = IncrementalScanner(base_ref="main")
        assert scanner.base_ref == "main"
    
    def test_diff_change_creation(self):
        """Test diff change dataclass."""
        change = DiffChange(
            file_path="contract.sol",
            change_type="modified",
            line_start=10,
            line_end=15,
            function_name="transfer"
        )
        assert change.file_path == "contract.sol"
        assert change.function_name == "transfer"
    
    def test_should_scan_file_no_base_ref(self):
        """Test file scanning when no base ref is provided."""
        scanner = IncrementalScanner()
        context = Mock()
        context.base_ref = None
        
        # Should scan all files when no base ref
        assert scanner.should_scan_file("any_file.sol", context) == True
    
    def test_git_diff_parsing_basic(self):
        """Test basic git diff parsing."""
        scanner = IncrementalScanner()
        diff_output = """
diff --git a/contract.sol b/contract.sol
index 1234567..abcdefg 100644
--- a/contract.sol
+++ b/contract.sol
@@ -10,5 +10,6 @@ function transfer(address to, uint256 amount) {
     balances[msg.sender] -= amount;
     balances[to] += amount;
+    emit Transfer(msg.sender, to, amount);
 }
"""
        
        changes = scanner._parse_git_diff(diff_output)
        assert len(changes) == 1
        assert changes[0].file_path == "contract.sol"
        assert changes[0].change_type == "modified"


class TestPatternEngine:
    """Test pattern engine functionality."""
    
    def test_pattern_rule_creation(self):
        """Test pattern rule creation."""
        rule = PatternRule(
            id="test_001",
            name="Test Pattern",
            description="Test description",
            pattern=r"vulnerable_pattern",
            severity=Severity.HIGH,
            confidence=0.9
        )
        assert rule.id == "test_001"
        assert rule.severity == Severity.HIGH
    
    def test_pattern_matching(self):
        """Test pattern matching functionality."""
        rule = PatternRule(
            id="test_001",
            name="Test Pattern", 
            description="Test",
            pattern=r"\.call\{.*\}",
            pattern_type="regex"
        )
        
        # Should match
        code_with_pattern = "target.call{value: amount}(data);"
        assert rule.matches(code_with_pattern)
        
        # Should not match
        code_without_pattern = "transfer(to, amount);"
        assert not rule.matches(code_without_pattern)
    
    def test_pattern_engine_initialization(self):
        """Test pattern engine initialization."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = PatternEngine([Path(tmp_dir)], enable_hot_reload=False)
            assert len(engine.pattern_dirs) == 1
            assert not engine.enable_hot_reload
    
    def test_pattern_engine_apply_empty(self):
        """Test applying patterns with no loaded patterns."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = PatternEngine([Path(tmp_dir)])
            findings = engine.apply_patterns("test code", "test.sol")
            assert findings == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])