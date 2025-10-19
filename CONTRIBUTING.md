# Contributing to VulnHuntr2

Thank you for your interest in contributing to VulnHuntr2! This document provides guidelines and instructions for contributing.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Adding New Detectors](#adding-new-detectors)

## Code of Conduct

This project follows a standard code of conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Assume good intentions
- Report unacceptable behavior to the maintainers

## Getting Started

### Prerequisites
- Python 3.12 or higher
- Git
- Familiarity with smart contract security concepts
- Basic understanding of Solidity

### First Steps
1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/vulnhuntr2.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Submit a pull request

## Development Setup

### Installation

```bash
# Clone the repository
git clone https://github.com/avaloki108/vulnhuntr2.git
cd vulnhuntr2

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e .[dev]

# Verify installation
vulnhuntr --help
pytest -q
```

### Optional Dependencies

For specific features, install additional dependencies:

```bash
# LLM features
pip install -e .[llm]

# Static analysis with Slither
pip install -e .[static]

# Full feature set
pip install -e .[full]
```

## How to Contribute

### Types of Contributions

We welcome:
- **Bug fixes:** Fix issues in existing code
- **New detectors:** Add new vulnerability detection patterns
- **Documentation:** Improve or expand documentation
- **Performance improvements:** Optimize existing code
- **Tests:** Add or improve test coverage
- **Features:** Implement new functionality (discuss first!)

### Finding Work

- Check [Issues](https://github.com/avaloki108/vulnhuntr2/issues) for bugs and feature requests
- Look for issues labeled `good-first-issue` or `help-wanted`
- Propose new features by opening an issue first

## Coding Standards

### Python Style

We follow PEP 8 with some modifications:

```bash
# Format code with Ruff
ruff format vulnhuntr/

# Check linting
ruff check vulnhuntr/

# Alternative: Black formatter
black vulnhuntr/

# Type checking
mypy vulnhuntr/
```

### Code Quality Requirements

- **Line length:** 100 characters max
- **Type hints:** Use for function signatures
- **Docstrings:** Required for public APIs
- **Comments:** Explain "why", not "what"
- **Naming:** Descriptive, follow Python conventions

### Example: Well-Formatted Code

```python
from vulnhuntr.core.registry import register
from vulnhuntr.core.models import Finding, Severity

@register
class MyDetector:
    """Detects a specific vulnerability pattern.
    
    This detector identifies cases where...
    """
    
    name = "my_detector"
    description = "Brief description of what this detects"
    severity = Severity.HIGH
    category = "access_control"
    confidence = 0.8
    
    def analyze(self, path: str, content: str) -> list[Finding]:
        """Analyze contract source code for vulnerabilities.
        
        Args:
            path: File path of the contract
            content: Source code content
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Detection logic here
        if "dangerous_pattern" in content:
            findings.append(Finding(
                detector=self.name,
                title="Dangerous pattern detected",
                file=path,
                line=1,
                severity=self.severity,
                confidence=self.confidence,
                code="dangerous_pattern",
                description="Detailed explanation of the issue",
            ))
        
        return findings
```

## Testing Guidelines

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`
- Use pytest fixtures for common setup
- Aim for >95% code coverage

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_detectors.py

# Run with coverage
pytest --cov=vulnhuntr --cov-report=term

# Run with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
```

### Example Test

```python
def test_my_detector_finds_vulnerability():
    """Test that MyDetector identifies the vulnerability."""
    from vulnhuntr.detectors.my_detector import MyDetector
    
    contract_code = """
    contract Vulnerable {
        function dangerous() public {
            dangerous_pattern();
        }
    }
    """
    
    detector = MyDetector()
    findings = list(detector.analyze("test.sol", contract_code))
    
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "dangerous pattern" in findings[0].title.lower()
```

## Pull Request Process

### Before Submitting

1. **Update your branch:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests:**
   ```bash
   pytest -q
   ruff check vulnhuntr/
   mypy vulnhuntr/
   ```

3. **Update documentation:**
   - Add/update docstrings
   - Update README if needed
   - Add examples if applicable

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] PR description explains changes
- [ ] Added tests for new functionality
- [ ] No unrelated changes included

### PR Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code formatted
```

### Review Process

1. Automated CI checks must pass
2. At least one maintainer review required
3. Address review feedback
4. Maintainer merges when approved

## Adding New Detectors

### Detector Template

Create a file `vulnhuntr/detectors/my_detector.py`:

```python
"""My Detector - Detects specific vulnerability patterns."""

from vulnhuntr.core.registry import register
from vulnhuntr.core.models import Finding, Severity

@register
class MyDetector:
    """Detects [vulnerability type].
    
    This detector identifies contracts that...
    
    References:
        - https://example.com/vulnerability-info
    
    Examples:
        Vulnerable pattern:
        ```solidity
        contract Vulnerable {
            // vulnerable code
        }
        ```
    """
    
    name = "my_detector"
    description = "Clear, concise description"
    severity = Severity.MEDIUM  # or HIGH, CRITICAL, LOW
    category = "access_control"  # or reentrancy, oracle, etc.
    confidence = 0.7  # 0.0 to 1.0
    
    def analyze(self, path: str, content: str) -> list[Finding]:
        """Analyze contract for vulnerabilities.
        
        Args:
            path: Contract file path
            content: Contract source code
            
        Returns:
            List of findings
        """
        findings = []
        
        # Your detection logic here
        
        return findings
```

### Detector Categories

Choose the appropriate category:
- `reentrancy` - Reentrancy vulnerabilities
- `access_control` - Missing access controls
- `oracle_manipulation` - Oracle/price feed issues
- `delegatecall_misuse` - Delegatecall risks
- `cross_chain` - Bridge/cross-chain issues
- `proxy_upgrade` - Proxy upgrade vulnerabilities
- `flash_loan` - Flash loan attacks
- `insecure_randomness` - RNG issues
- `gas_griefing` - DoS/gas vulnerabilities
- `signature_replay` - Signature replay attacks

### Testing New Detectors

Create `tests/test_my_detector.py`:

```python
import pytest
from vulnhuntr.detectors.my_detector import MyDetector

def test_detects_vulnerability():
    """Test detection of vulnerable pattern."""
    code = """
    contract Vulnerable {
        // vulnerable code
    }
    """
    
    detector = MyDetector()
    findings = list(detector.analyze("test.sol", code))
    
    assert len(findings) > 0
    assert findings[0].severity == Severity.MEDIUM

def test_no_false_positive():
    """Test that safe code doesn't trigger detector."""
    code = """
    contract Safe {
        // safe code
    }
    """
    
    detector = MyDetector()
    findings = list(detector.analyze("test.sol", code))
    
    assert len(findings) == 0
```

## Advanced Topics

### Adding LLM Features

For LLM-powered detectors:

```python
from vulnhuntr.LLMs import get_llm_client

class LLMDetector:
    def analyze(self, path: str, content: str) -> list[Finding]:
        client = get_llm_client()
        response = client.analyze(content)
        # Process LLM response
        return findings
```

### Performance Optimization

- Use caching for repeated analysis
- Avoid redundant parsing
- Profile with `pytest --profile`
- Consider incremental scanning

### Documentation

Add to appropriate sections:
- `README.md` - High-level overview
- `docs/detectors.md` - Detector catalog
- `CLAUDE.md` - AI assistant guidance
- Inline docstrings - API documentation

## Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** File an issue
- **Chat:** Join our Discord (link TBD)
- **Email:** security@vulnhuntr.io (for security issues)

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- Annual contributor spotlight

Thank you for contributing to making smart contracts more secure! 🛡️
