# vulnhuntr2

Prototype mutation / heuristic smart contract vulnerability hunting tool (early scaffold).

## Features (Current Prototype)

- CLI with Typer + Rich
- Detector registry and plug-in style registration via decorator
- Simple orchestrator to walk Solidity sources (`.sol`)
- Example heuristic detector (`reentrancy_heuristic`) flagging external call patterns
- JSON export of findings
- Dev tooling: Ruff, Black, Mypy, Pytest

## Install

```bash
git clone https://github.com/avaloki108/vulnhuntr2.git
cd vulnhuntr2
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]
```

## CLI Usage

```bash
vulnhuntr list-detectors
vulnhuntr scan path/to/contracts
vulnhuntr scan path/to/contracts --json findings.json
vulnhuntr scan path/to/contracts --fail-on-findings
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

## Tests

```bash
pytest -q
```

## Roadmap Ideas

- Proper Solidity parsing (tree-sitter / slither integration)
- Mutation framework
- LLM-assisted triage (optional extra)
- Severity aggregation & SARIF output
- Config file & ignore rules

## License

Dual source basis from upstream concepts – current code: AGPL-3.0 (see LICENSE).