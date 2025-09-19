# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

vulnhuntr2 is a prototype smart contract vulnerability hunting tool with two main components:
1. **CLI Scanner**: Basic heuristic-based Solidity (.sol) file scanner with plugin-style detectors
2. **LLM-Powered Analyzer**: Advanced Python vulnerability analysis using Claude, GPT, or Ollama models

The project uses a plugin registry system for vulnerability detectors and supports JSON export of findings.

## Development Environment & Dependencies

This is a Python 3.12 project managed with Poetry and setuptools. Key dependencies include:
- **CLI**: Typer + Rich for command-line interface
- **LLM Support**: OpenAI, Anthropic (Claude), Ollama clients
- **Analysis**: tree-sitter for code parsing, Pydantic for data validation
- **Dev Tools**: Ruff, Black, MyPy, Pytest

### Environment Setup
```bash
# Using pip (as shown in README)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]

# Or with Poetry (project has both pyproject.toml and poetry.lock)
poetry install
```

## Common Development Commands

### Core CLI Usage
```bash
# List available detectors
vulnhuntr list-detectors

# Scan Solidity files/directories
vulnhuntr scan path/to/contracts
vulnhuntr scan path/to/contracts --json findings.json
vulnhuntr scan path/to/contracts --fail-on-findings
```

### LLM-Powered Analysis
```bash
# Advanced vulnerability analysis (requires API keys)
python -m vulnhuntr -r /path/to/project --llm claude
python -m vulnhuntr -r /path/to/project --analyze specific/file.py
python -m vulnhuntr -r /path/to/project --llm gpt -v  # verbose
```

### Testing & Quality
```bash
# Run tests
pytest -q
pytest tests/  # specific directory

# Code formatting and linting
black vulnhuntr/
ruff check vulnhuntr/
mypy vulnhuntr/

# Run single test file
pytest tests/test_cli.py -v
```

## Architecture Overview

### Detector Registry System (`vulnhuntr/core/registry.py`)
- Plugin-style architecture using `@register` decorator
- `Finding` dataclass for standardized vulnerability reports
- Protocol-based `Detector` interface with `analyze(path, content)` method

### CLI Layer (`vulnhuntr/cli.py`)
- Built with Typer, uses Rich for formatted output
- `Orchestrator` handles file discovery and detector execution
- Supports `.sol` file scanning with JSON export

### LLM Analysis Engine (`vulnhuntr/__main__.py`)
- Multi-step vulnerability analysis with context gathering
- Supports Claude, ChatGPT, and Ollama models
- Uses XML-based prompt templates and Pydantic response validation
- Iterative analysis with context code extraction via `SymbolExtractor`

### Key Components:
- **`LLMs.py`**: Base LLM class with provider-specific implementations
- **`prompts.py`**: Vulnerability-specific prompt templates (LFI, RCE, SSRF, etc.)
- **`symbol_finder.py`**: Code context extraction for LLM analysis
- **`core/orchestrator.py`**: File scanning and detector orchestration

## Adding New Detectors

Create detector files in `vulnhuntr/detectors/`:

```python
from vulnhuntr.core.registry import register, Finding

@register
class MyDetector:
    name = "my_detector"
    description = "What it detects."
    severity = "LOW"  # LOW/MEDIUM/HIGH

    def analyze(self, path: str, content: str):
        if "vulnerable_pattern" in content:
            yield Finding(
                detector=self.name,
                title="Vulnerability found",
                file=path,
                line=42,
                severity=self.severity,
                code="vulnerable_pattern",
            )
```

Ensure the detector is imported via `vulnhuntr/detectors/__init__.py`.

## LLM Configuration

Set environment variables in `.env`:
```bash
# Required for LLM analysis
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here

# Optional model/endpoint overrides
ANTHROPIC_MODEL=claude-3-5-sonnet-latest
ANTHROPIC_BASE_URL=https://api.anthropic.com
OPENAI_MODEL=chatgpt-4o-latest
OPENAI_BASE_URL=https://api.openai.com/v1
OLLAMA_MODEL=llama3
OLLAMA_BASE_URL=http://127.0.0.1:11434/api/generate
```

## Testing Strategy

The project uses Pytest with:
- **CLI testing**: Subprocess calls to test command-line interface
- **Registry testing**: Import-based detector registration validation
- **Integration testing**: JSON output validation

Test structure focuses on the CLI interface and detector registry system. The LLM analysis components appear to be tested manually or through integration testing.

## Development Notes

- The project has dual nature: basic Solidity scanning + advanced Python analysis
- LLM analysis uses structured XML prompts with vulnerability-specific templates
- The `RepoOps` class contains extensive regex patterns for identifying network-related Python code
- Support for Kali Linux environment with various security tools integration via MCP
- Uses viem, forge, and anvil for testing and recording security exploits per user rules

## Project Status

This is marked as an "early scaffold" prototype with planned roadmap including:
- Proper Solidity parsing (tree-sitter/slither integration) 
- Mutation testing framework
- SARIF output format
- Configuration files and ignore rules