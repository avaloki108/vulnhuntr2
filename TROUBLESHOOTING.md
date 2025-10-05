# VulnHuntr2 Troubleshooting Guide

## Common Issues and Solutions

### Installation Issues

#### "Command not found: vulnhuntr"

**Problem**: The tool isn't in your PATH after installation.

**Solution**:
```bash
# Make sure you installed with pip
pip install git+https://github.com/avaloki108/vulnhuntr2.git

# Or if using development mode
cd vulnhuntr2
pip install -e .

# Verify installation
pip show vulnhuntr2
```

#### "No module named 'aiohttp'" when using elite detector

**Problem**: Optional dependencies not installed.

**Solution**:
```bash
# Install with LLM support
pip install -e .[llm,full]
```

**Note**: The elite detector will automatically disable if dependencies are missing - the basic scanner still works.

### Scanning Issues

#### "No findings detected" when scanning

**Possible causes**:
1. **No vulnerabilities present** - Your code might be secure!
2. **Wrong file path** - Check that the path is correct
3. **Detectors disabled** - Check your `vulnhuntr.toml` config

**Debugging**:
```bash
# List enabled detectors
vulnhuntr list-detectors

# Try scanning the example contract
vulnhuntr scan examples/vulnerable_vault.sol
```

#### Too many false positives

**Problem**: Pattern-based detection can flag legitimate code.

**Solutions**:
1. **Review confidence scores** - Focus on findings with >70% confidence
2. **Prioritize by severity** - Address CRITICAL and HIGH first
3. **Configure detectors** - Disable noisy detectors in `vulnhuntr.toml`:
   ```toml
   [detectors]
   disabled = ["eventless_critical_action"]
   ```

### Output Issues

#### JSON export creates invalid JSON

**Problem**: Rare edge case with special characters in code.

**Solution**:
```bash
# Use the built-in JSON export
vulnhuntr scan contracts/ --json findings.json

# Verify JSON is valid
python -m json.tool findings.json
```

#### Terminal output looks broken

**Problem**: Terminal doesn't support Unicode/colors.

**Solution**:
```bash
# Export to JSON instead
vulnhuntr scan contracts/ --json findings.json

# View JSON with jq
cat findings.json | jq '.findings[] | {severity, title, line}'
```

### Performance Issues

#### Scanning is very slow

**Possible causes**:
1. Large number of files
2. Very large contract files
3. All detectors running

**Solutions**:
```bash
# Scan specific files only
vulnhuntr scan contracts/MyContract.sol

# Disable slow detectors via config
# Create vulnhuntr.toml:
[detectors]
enabled = ["reentrancy_heuristic", "access_control"]
```

### CI/CD Issues

#### GitHub Actions fails with "command not found"

**Problem**: Tool not installed in CI environment.

**Solution**:
```yaml
- name: Install VulnHuntr2
  run: pip install git+https://github.com/avaloki108/vulnhuntr2.git

- name: Scan
  run: vulnhuntr scan contracts/
```

#### Build fails even with no critical issues

**Problem**: Using `--fail-on-findings` flag.

**Solution**:
```bash
# Fail only on high/critical
# (Feature planned - currently fails on any finding)

# Workaround: Don't use --fail-on-findings, check JSON instead
vulnhuntr scan contracts/ --json findings.json
python -c "import json; f=json.load(open('findings.json')); exit(1 if any(x['severity'] in ['CRITICAL','HIGH'] for x in f['findings']) else 0)"
```

## Understanding Findings

### "Potential reentrancy-sensitive external call"

**What it means**: External call detected that might be vulnerable to reentrancy.

**False positive if**:
- Call is at the end of the function
- State changes happen before the call
- Reentrancy guard is in place

**True positive if**:
- State changes happen after external call
- No reentrancy protection

### "Critical function X lacks access control"

**What it means**: Function has no `onlyOwner`, `require`, or role check.

**False positive if**:
- Function is meant to be public
- Access control is in a modifier not detected

**True positive if**:
- Sensitive operation available to anyone

### "Delegatecall to untrusted address"

**What it means**: Delegatecall allows target to modify storage.

**False positive if**:
- Address is hardcoded/trusted
- Proper validation exists

**True positive if**:
- User controls target address
- No whitelist validation

## Getting Help

### Check Existing Resources

1. **Quick Start**: [QUICKSTART.md](QUICKSTART.md)
2. **Feature Status**: [FEATURE_STATUS.md](FEATURE_STATUS.md)
3. **README**: [README.md](README.md)

### Still Stuck?

1. **Search Issues**: https://github.com/avaloki108/vulnhuntr2/issues
2. **Open New Issue**: Include:
   - Command you ran
   - Error message (full output)
   - Operating system
   - Python version (`python --version`)
   - VulnHuntr2 version (`pip show vulnhuntr2`)

### False Positive?

If you believe a finding is a false positive:

1. Review the code context
2. Check the detector documentation
3. Consider opening an issue with:
   - The finding details
   - Why it's a false positive
   - Code snippet (if possible)

This helps improve the tool!

## Quick Reference

```bash
# Basic commands
vulnhuntr scan path/to/contracts          # Scan contracts
vulnhuntr list-detectors                  # List detectors
vulnhuntr explain-finding detector_name   # Get explanation

# Common flags
--json findings.json                      # Export to JSON
--fail-on-findings                        # Exit 1 if findings

# Installation variants
pip install git+https://github.com/...   # Basic
pip install -e .[llm,full]               # With LLM support
pip install -e .[dev]                    # For development
```

## Tips for Best Results

1. **Start small**: Scan one contract first
2. **Review manually**: Don't auto-fix everything
3. **Check confidence**: Higher = more likely real
4. **Prioritize severity**: Fix CRITICAL/HIGH first
5. **Learn patterns**: Understand what's detected and why

---

**Still having issues?** Open an issue with details!
