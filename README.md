# VulnHuntr2

A practical smart contract vulnerability scanner focused on finding real security issues in Solidity code.

**🚀 New user?** Start with the [Quick Start Guide](QUICKSTART.md)

## What It Does

VulnHuntr2 scans Solidity smart contracts and identifies common vulnerability patterns across 19 different security categories. It's designed for security researchers, auditors, and developers who want to catch vulnerabilities before they make it to production.

**Current Status**: Core scanning functionality is production-ready. Advanced features (LLM analysis, symbolic execution, multi-chain) are in various stages of development.

## Key Features

### ✅ Working Now
- **19 Active Vulnerability Detectors** covering major smart contract security issues
- **Pattern-Based Detection** with modern Solidity syntax support
- **Rich Terminal Output** with beautiful tables and color coding
- **JSON Export** for CI/CD integration
- **TOML Configuration** with environment variable support
- **Severity & Confidence Scoring** for all findings

### 🚧 Optional/Beta Features
- **LLM-Powered Analysis** (requires `pip install vulnhuntr2[llm,full]`)
- **Advanced Correlation** (basic implementation)
- **SARIF Export** (available but needs testing)

See [FEATURE_STATUS.md](FEATURE_STATUS.md) for a complete breakdown of what's implemented vs planned.

## Installation

### Basic Installation

```bash
pip install git+https://github.com/avaloki108/vulnhuntr2.git
```

Or for development:

```bash
git clone https://github.com/avaloki108/vulnhuntr2.git
cd vulnhuntr2
pip install -e .
```

### With Optional Features

```bash
# For LLM-powered analysis
pip install -e .[llm]

# For static analysis integration (Slither)
pip install -e .[static]

# Everything
pip install -e .[full]

# Development tools
pip install -e .[dev]
```

## Quick Start

### Basic Scanning

```bash
# Scan a single contract
vulnhuntr scan MyContract.sol

# Scan a directory
vulnhuntr scan contracts/

# Export to JSON
vulnhuntr scan contracts/ --json security-report.json

# Fail CI build if vulnerabilities found
vulnhuntr scan contracts/ --fail-on-findings
```

### List Available Detectors

```bash
vulnhuntr list-detectors
```

### Get Vulnerability Explanations

```bash
vulnhuntr explain-finding reentrancy_heuristic
```

### Advanced: LLM-Powered Analysis

```bash
# Requires optional dependencies
pip install vulnhuntr2[llm,full]

# Run elite analysis
vulnhuntr elite path/to/contracts
```

## Adding a Detector

Create a file under `vulnhuntr/detectors/`:

```python
from vulnhuntr.core.registry import register, Finding

@register
class MyDetector:
    name = "my_detector"
    description = "What it detects."
    severity = "LOW"

    def analyze(self, path: str, content: str):
        if "pattern" in content:
            yield Finding(
                detector=self.name,
                title="Pattern found",
                file=path,
                line=1,
                severity=self.severity,
                code="pattern",
            )
```

Ensure it is imported (directly or via `__init__.py`).

## Detected Vulnerability Types

VulnHuntr2 currently detects:

1. **Reentrancy Attacks** - External calls before state updates
2. **Access Control Issues** - Missing ownership/role protections
3. **Missing Events** - Critical operations without logging
4. **Oracle Manipulation** - Price feed vulnerabilities
5. **Delegatecall Misuse** - Storage collision risks
6. **Unprotected Self-Destruct** - Contract destruction vulnerabilities
7. **Signature Replay** - EIP-712 and signature validation issues
8. **Gas Griefing** - Unbounded loops and DoS vulnerabilities
9. **Cross-Chain Security** - Bridge and relay attack patterns
10. **Proxy Issues** - Upgradeable contract vulnerabilities
11. **Flash Loan Attacks** - Atomicity violations
12. **Insecure Randomness** - Predictable PRNG usage
13. **Uninitialized Storage** - Storage collision risks

And more! Use `vulnhuntr list-detectors` for the complete list.

## Example Output

```
                                                 Vulnerability Findings                                                 
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Detector                  ┃ Title                                 ┃ File              ┃ Line ┃ Confidence ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━┩
│ CRITICAL │ privilege_escalation_path │ Delegatecall to untrusted address     │ Vault.sol         │   51 │      90.0% │
│ HIGH     │ reentrancy_heuristic      │ Potential reentrancy-sensitive call   │ Vault.sol         │   26 │      60.0% │
│ HIGH     │ privilege_escalation_path │ Critical function lacks access control│ Vault.sol         │   22 │      90.0% │
│ MEDIUM   │ eventless_critical_action │ State change without event            │ Vault.sol         │   29 │      70.0% │
└──────────┴───────────────────────────┴───────────────────────────────────────┴───────────────────┴──────┴────────────┘
```

## Configuration

Create a `vulnhuntr.toml` file in your project:

```toml
[detectors]
# Enable/disable specific detectors
enabled = ["reentrancy", "access_control", "oracle_manipulation"]
# Or disable specific ones
# disabled = ["eventless_critical_action"]

[analysis]
max_findings = 100
min_confidence = 0.5

[output]
format = "json"  # json, table, sarif
include_source = true
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install VulnHuntr2
  run: pip install git+https://github.com/avaloki108/vulnhuntr2.git

- name: Scan Contracts
  run: vulnhuntr scan contracts/ --json security-report.json --fail-on-findings

- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: security-report.json
```

## Development

### Running Tests

```bash
pip install -e .[dev]
pytest -v
```

### Code Quality

```bash
# Linting
ruff check vulnhuntr/

# Formatting
black vulnhuntr/

# Type checking
mypy vulnhuntr/
```

## Adding Your Own Detector

Create a file in `vulnhuntr/detectors/`:

```python
from vulnhuntr.core.registry import register
from vulnhuntr.core.models import Finding, Severity

@register
class MyDetector:
    name = "my_custom_detector"
    description = "Detects my specific vulnerability pattern"
    severity = Severity.HIGH
    category = "custom"
    confidence = 0.8

    def analyze(self, path: str, content: str):
        # Your detection logic here
        if "dangerous_pattern" in content:
            yield Finding(
                detector=self.name,
                title="Dangerous pattern detected",
                file=path,
                line=1,
                severity=self.severity,
                code="dangerous_pattern",
                description="This pattern is dangerous because...",
                confidence=self.confidence
            )
```

The detector will be automatically discovered and loaded.

## Architecture

- **`vulnhuntr/core/`** - Core scanning engine and models
- **`vulnhuntr/detectors/`** - 19+ vulnerability detection modules
- **`vulnhuntr/config/`** - Configuration management
- **`vulnhuntr/correlation/`** - Finding correlation (basic)
- **`vulnhuntr/parsing/`** - Code parsing utilities

## Limitations & Known Issues

1. **False Positives**: Pattern-based detection can flag legitimate code. Always manually review findings.
2. **Modern Solidity**: Best results with Solidity 0.8.x.
3. **Symbolic Execution**: Not yet operational - requires Mythril integration (planned).
4. **Cross-Contract Analysis**: Limited support for multi-contract interactions.

## Roadmap

### Current Focus
- ✅ Core vulnerability detection (Done)
- 🔄 Reducing false positives
- 🔄 SARIF export testing
- 🔄 Better documentation

### Planned Features
- Advanced correlation and clustering
- Symbolic execution integration (Mythril)
- Foundry integration for PoC generation
- GitHub Code Scanning workflow
- Multi-chain analysis

See [dreams.md](dreams.md) for detailed roadmap and [FEATURE_STATUS.md](FEATURE_STATUS.md) for implementation status.

## Contributing

Areas where help is needed:
1. Reducing false positives in detectors
2. Adding new vulnerability patterns
3. Test coverage improvements
4. Documentation and examples
5. Integration with Slither, Mythril, Foundry

## License

Dual source basis from upstream concepts – current code: AGPL-3.0 (see LICENSE).

---

**Note**: This tool assists security analysis but doesn't replace manual audits. Always perform thorough reviews before deploying smart contracts.