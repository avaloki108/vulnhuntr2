# VulnHuntr2 Quick Start Guide

Welcome to VulnHuntr2! This guide will get you scanning for smart contract vulnerabilities in 5 minutes.

## Installation

```bash
pip install git+https://github.com/avaloki108/vulnhuntr2.git
```

## Your First Scan

1. **Scan the example vulnerable contract:**
   ```bash
   vulnhuntr scan examples/vulnerable_vault.sol
   ```

   You should see output like:
   ```
   Found 17 potential issues:
     MEDIUM: 9
     HIGH: 6
     CRITICAL: 2
   ```

2. **Export results to JSON:**
   ```bash
   vulnhuntr scan examples/vulnerable_vault.sol --json my-findings.json
   ```

3. **Scan your own contracts:**
   ```bash
   vulnhuntr scan path/to/your/contracts/
   ```

## What Gets Detected?

VulnHuntr2 finds 13+ categories of vulnerabilities:

- ✅ **Reentrancy** - External calls before state updates
- ✅ **Access Control** - Missing owner/role checks
- ✅ **Delegatecall Misuse** - Storage collision risks
- ✅ **Missing Events** - Critical operations without logging
- ✅ **Oracle Manipulation** - Price feed vulnerabilities
- ✅ **And 14 more!**

Run `vulnhuntr list-detectors` to see all available detectors.

## Understanding Results

### Finding Format
```
┃ Severity ┃ Detector                  ┃ Title                              ┃ File      ┃ Line ┃ Confidence ┃
┃ CRITICAL ┃ privilege_escalation_path ┃ Delegatecall to untrusted address  ┃ Vault.sol ┃   41 ┃      90.0% ┃
```

- **Severity**: CRITICAL > HIGH > MEDIUM > LOW
- **Detector**: Which vulnerability pattern was matched
- **Confidence**: How certain we are (higher = more likely to be real)
- **Line**: Where the issue is in your code

### JSON Output Structure
```json
{
  "meta": {
    "version": "0.1.0",
    "total_findings": 17,
    "detectors_enabled": ["reentrancy", "access_control", ...]
  },
  "findings": [
    {
      "detector": "reentrancy_heuristic",
      "severity": "HIGH",
      "line": 24,
      "confidence": 0.6,
      "description": "External call detected...",
      ...
    }
  ]
}
```

## CI/CD Integration

Add to your GitHub Actions:

```yaml
- name: Security Scan
  run: |
    pip install git+https://github.com/avaloki108/vulnhuntr2.git
    vulnhuntr scan contracts/ --json security-report.json
    
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: security-report.json
```

## Next Steps

1. **Review Findings**: Not all findings are true vulnerabilities - review each one
2. **Fix Issues**: Address CRITICAL and HIGH severity findings first
3. **Add Configuration**: Create `vulnhuntr.toml` to customize scanning
4. **Learn More**: Read [README.md](README.md) for detailed documentation

## Common Commands

```bash
# List all detectors
vulnhuntr list-detectors

# Get help on a specific vulnerability type
vulnhuntr explain-finding reentrancy_heuristic

# Scan with fail-on-findings (for CI)
vulnhuntr scan contracts/ --fail-on-findings

# Advanced: LLM-powered analysis (requires extra deps)
pip install vulnhuntr2[llm,full]
vulnhuntr elite path/to/contracts
```

## Getting Help

- **Issues**: Found a bug? [Open an issue](https://github.com/avaloki108/vulnhuntr2/issues)
- **Documentation**: See [README.md](README.md) and [FEATURE_STATUS.md](FEATURE_STATUS.md)
- **False Positives**: Some patterns may flag legitimate code - that's normal for static analysis

## Important Notes

⚠️ **This tool assists security analysis but doesn't replace manual audits.**

- Always review findings manually
- Test your fixes thoroughly
- Consider professional audits for production code

---

**Ready to scan?** Run: `vulnhuntr scan examples/vulnerable_vault.sol`
