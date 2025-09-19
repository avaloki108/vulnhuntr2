# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulnHuntr2 is a sophisticated smart contract vulnerability analysis framework built in Python 3.12+. It's designed for professional security researchers and uses a multi-detector plugin architecture to discover vulnerabilities in Solidity smart contracts.

## Core Commands

### Development Setup
```bash
# Install for development with all optional dependencies
pip install -e .[dev,full]

# Install minimal version
pip install -e .

# Install with specific feature sets
pip install -e .[llm,static]  # LLM + Slither integration
```

### Primary CLI Commands
```bash
# Core vulnerability scanning
vulnhuntr scan path/to/contracts
vulnhuntr scan path/to/contracts --json findings.json
vulnhuntr scan path/to/contracts --fail-on-findings

# List available detectors and their metadata
vulnhuntr list-detectors

# Advanced LLM-powered analysis (requires [llm] extras)
vulnhuntr elite path/to/contracts

# Get detailed explanations of specific vulnerabilities
vulnhuntr explain-finding detector_name
```

### Development Commands
```bash
# Run tests
pytest -q

# Linting and formatting
ruff check vulnhuntr/
black --check vulnhuntr/
ruff format vulnhuntr/  # Auto-fix

# Type checking
mypy vulnhuntr/

# Run specific test modules
pytest tests/test_mutations.py -v
pytest tests/test_parsing.py -v
```

## Architecture Overview

### Core Package Structure
- **`vulnhuntr/core/`** - Core orchestration, models, and analysis engines
  - `orchestrator.py` - Main scanning coordinator
  - `models.py` - Finding and severity data models
  - `scoring.py` - Advanced Phase 4 scoring system with weighted factors
  - `reporting.py` - Multi-format output generation (JSON, SARIF, table)
  - `registry.py` - Detector plugin registration system

- **`vulnhuntr/detectors/`** - 19+ vulnerability detection modules
  - Plugin-based architecture using `@register` decorator
  - Each detector inherits from `BaseDetector` or `HeuristicDetector`
  - Supports pattern-based detection with confidence scoring

- **`vulnhuntr/config/`** - Configuration management
  - `settings.py` - Pydantic-based hierarchical configuration
  - Supports TOML files (`vulnhuntr.toml`) and environment variables (`VULNHUNTR_*`)

- **`vulnhuntr/parsing/`** - Code parsing and analysis
  - `slither_adapter.py` - Integration with Slither static analysis
  - Tree-sitter support for advanced syntax parsing

### Detector System

**Registration Pattern**: Use the `@register` decorator for auto-discovery:
```python
from vulnhuntr.core.registry import register

@register
class MyDetector(BaseDetector):
    name = "my_detector"
    description = "What it detects"
    severity = Severity.HIGH
    category = "access_control"
    confidence = 0.8

    def analyze(self, path: str, content: str):
        # Detection logic here
        yield Finding(...)
```

**Detector Categories**:
- `reentrancy` - External call patterns and state changes
- `access_control` - Missing ownership/role protections
- `oracle_manipulation` - Price feed vulnerabilities
- `delegatecall_misuse` - Storage collision risks
- `cross_chain` - Bridge and relay attacks
- `proxy_upgrade` - Upgradeable contract risks
- `flash_loan` - Atomicity violations
- And 12+ more specialized categories

### Scoring System

**Advanced Phase 4 Scoring** (`vulnhuntr/core/scoring.py`):
- **Weighted Factor Model**: 13 distinct factors with transparent weights
- **Context-Aware**: Function complexity, external calls, guard presence
- **Evidence-Based**: Symbolic confirmation, path complexity, cluster size
- **Severity Adjustment**: Automatic severity escalation/de-escalation
- **Confidence Boosting**: Multi-detector correlation increases confidence

**Key Scoring Components**:
- `ScoringFactors` - Individual factor contributions (0.0-1.0)
- `ScoringWeights` - Transparent weight distribution (sums to 1.0)
- `ScoringResult` - Complete scoring breakdown with rationale

### Configuration System

**Hierarchical Configuration Loading**:
1. `./vulnhuntr.toml` (project-specific)
2. `~/.config/vulnhuntr/config.toml` (user global)
3. Environment variables (`VULNHUNTR_*`)
4. CLI arguments (highest precedence)

**Key Config Sections**:
```toml
[detectors]
include = ["reentrancy", "access_control"]
exclude = ["low_severity_detector"]

[analysis]
max_findings = 100
min_confidence = 0.5

[output]
format = "json"  # json, table, sarif
include_source = true

[llm]
provider = "openai"  # openai, anthropic
model = "gpt-4"
```

### Advanced Features

**Phase 5/6 Capabilities**:
- **Incremental Scanning**: Git-aware differential analysis
- **Multi-Chain Analysis**: Cross-chain vulnerability detection
- **Economic Simulation**: MEV and economic exploit modeling
- **Knowledge Graph**: Contract relationship mapping
- **AI Triage**: LLM-powered finding analysis and filtering

**Output Formats**:
- **JSON** - Machine-readable findings with full metadata
- **SARIF** - Industry-standard static analysis format
- **Table** - Human-readable terminal output with Rich formatting
- **CI/CD Integration** - Configurable fail conditions and thresholds

## Development Notes

### Python Requirements
- **Python 3.12** (strict requirement)
- Core dependencies: `rich`, `typer`, `pydantic`
- Optional: `openai`, `slither-analyzer`, `tree-sitter-languages`

### Testing Strategy
- Unit tests for core components (`tests/`)
- Integration tests for CLI commands
- Mutation testing framework for detector validation
- Phase 5/6 feature tests for advanced capabilities

### Code Quality Tools
- **Ruff**: Fast Python linter (configured for line length 100)
- **Black**: Code formatter (Python 3.12 target)
- **MyPy**: Static type checking
- **Pytest**: Test framework with coverage reporting

### Adding New Detectors

1. Create detector file in `vulnhuntr/detectors/`
2. Use `@register` decorator for auto-discovery
3. Inherit from `BaseDetector` or `HeuristicDetector`
4. Implement `analyze()` method yielding `Finding` objects
5. Add comprehensive tests
6. Update detector registry in `__init__.py`

The codebase is production-ready with 19+ active detectors, comprehensive error handling, and enterprise-grade configuration management. Focus on the plugin architecture when extending functionality and leverage the advanced scoring system for accurate vulnerability assessment.