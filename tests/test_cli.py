import json
from pathlib import Path
import subprocess
import sys


def run_cli(*args: str):
    cmd = [sys.executable, "-m", "vulnhuntr.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_list_detectors(tmp_path):
    result = run_cli("list-detectors")
    assert result.returncode == 0
    assert "Available Detectors" in result.stdout


def test_scan_json_output(tmp_path):
    sample = tmp_path / "Contract.sol"
    sample.write_text(
        """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract T { function f() public { (bool ok, ) = address(this).call(""); } }"""
    )
    findings_path = tmp_path / "findings.json"
    result = run_cli("scan", str(tmp_path), "--json", str(findings_path))
    assert result.returncode == 0
    assert findings_path.exists()
    data = json.loads(findings_path.read_text())
    
    # Check new structured format
    assert isinstance(data, dict)
    assert "meta" in data
    assert "findings" in data
    assert "correlated_findings" in data
    
    # Check metadata structure
    meta = data["meta"]
    assert "version" in meta
    assert "config_hash" in meta
    assert "total_findings" in meta
    assert "detectors_enabled" in meta
    assert "gating" in meta
    
    # Check findings are in the expected format
    findings = data["findings"]
    assert isinstance(findings, list)
    if findings:  # If any findings exist
        finding = findings[0]
        assert "detector" in finding
        assert "severity" in finding
        assert "file" in finding
