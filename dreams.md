this was my original road map:
High-Level Vision
Transform vulnhuntr2 from a generic LLM-driven vulnerability explorer into a modular Web3-focused security analysis orchestrator that:

Aggregates results from established static + dynamic + symbolic tools (Slither, Mythril, Foundry (forge), Echidna, Semgrep rules for Solidity, optionally Slither detectors extended by AI).
Uses LLM reasoning layers to:
Correlate multi-tool findings
De-duplicate + prioritize
Suggest remediation patches
Generate formal-ish invariants (draft) and test scaffolds
Supports chain-aware enrichment (fetch verified source from Etherscan / Sourcify / Blockscout).
Produces standardized outputs (JSON, SARIF, Markdown, optional HTML) suitable for CI and GitHub Code Scanning.
Provides plugin-like detectors (traditional + LLM-backed).
Is packaged (pip installable), reproducible (locked deps), and CI-verified (GitHub Actions).
Runs cross-platform (Windows + Linux) with optional Docker path for deterministic tooling.
Core Web3 Vulnerability Domains to Cover
Initial detection categories (map to detectors + correlation layer):

Reentrancy (classic, cross-function, ERC777 hooks)
Access control / missing onlyOwner / role gating
Delegatecall misuse / proxy storage collision
Integer truncation / old compiler semantics (flag mismatched pragmas)
Oracle / price manipulation surface
Frontrunning / sandwich risk patterns (state-dependent pricing, AMM misordering)
Unprotected selfdestruct
Insecure randomness (block vars, predictable seeds)
Signature replay / EIP-712 misuse
Flash loan attack surfaces (lack of invariant checks)
Uninitialized storage / unbounded loops / gas griefing
Upgradeable proxy anti-patterns (storage gaps, initializer misuse)
Event emission inconsistencies (for compliance / monitoring gaps)
Later phases: cross-contract invariant inference, DeFi-specific patterns (liquidation flaws, TWAP oracle windows, fee accounting drift).

Architecture Upgrade
Code
vulnhuntr2/
  pyproject.toml
  src/vulnhuntr/
    __init__.py
    cli.py
    config/
      loader.py
      schema.py
    core/
      models.py          (Finding, Artifact, RunContext)
      runner.py          (Orchestrator)
      registry.py        (Plugin registration)
      correlation.py     (LLM & rule based collation)
      reporting.py       (Markdown/SARIF/JSON)
      llm_client.py      (provider abstraction: OpenAI, Anthropic, local)
    scanners/
      base.py
      slither_runner.py
      mythril_runner.py
      semgrep_runner.py
      foundry_runner.py
      echidna_runner.py
      etherscan_fetcher.py
    detectors/
      base.py
      llm_reentrancy.py
      llm_access_control.py
      heuristic_oracle.py
    outputs/
      templates/
        summary.md.j2
    utils/
      process.py
      paths.py
      log.py
  tests/
    unit/
    integration/
  vulnhuntr.example.toml
  README.md
  CONTRIBUTING.md
  LICENSE (AGPL-3.0 from upstream)
  .github/
    workflows/
      ci.yml
      nightly-web3-scan.yml
Data Model (Conceptual)
Finding:

id (stable hash)
source (slither | mythril | llm | correlation)
category (reentrancy, access-control, etc.)
severity (informational / low / medium / high / critical)
confidence (0–1 or textual: low/med/high)
file / contract / function / line
raw_evidence (tool output snippet)
normalized_description
remediation (LLM-generated candidate patch / guidance)
correlations (list of related finding ids)
RunContext:

project root
contracts discovered
compiler versions (from pragmas)
chain metadata (optional)
config flags
LLM Layer Strategy
Abstraction (llm_client) with provider drivers & environment selection:

Priority features:

Retry & backoff
Deterministic mode (no LLM for CI if flag set)
JSON schema enforcement (validation for structured outputs)
Prompt library (prompt/ directory) with version tags
LLM Use Cases:

Upgrade raw tool messages into normalized taxonomy
Generate remediation suggestions (with patch blocks)
Correlate multi-tool signals into higher-confidence compound findings
Optional: propose invariants for Echidna / Foundry property tests
Config (vulnhuntr.toml)
Code
[project]
name = "sample-dapp"
chain = "ethereum"
mode = "full"   # quick | full

[paths]
contracts = ["contracts/"]
exclude = ["node_modules/", "lib/"]

[tools]
slither = { enabled = true }
mythril = { enabled = true, max_depth = 30 }
foundry = { enabled = true, tests = true }
echidna = { enabled = false }

[enrichment]
etherscan = { enabled = true, api_key_env = "ETHERSCAN_API_KEY" }

[llm]
provider = "openai"
model = "gpt-4o-mini"
temperature = 0.0
enable_correlation = true
enable_remediation = true

[output]
formats = ["json","markdown","sarif"]
destination = "reports/"
CLI UX
Code
vulnhuntr scan --config vulnhuntr.toml
vulnhuntr fetch --address 0xContract --chain ethereum --out ./contracts/fetched
vulnhuntr correlate --input reports/raw.json
vulnhuntr report --format sarif
vulnhuntr list-detectors
vulnhuntr version
GitHub Actions
ci.yml

Setup Python, Node (if Foundry)
Install Foundry (foundryup)
Run pip install .[web3]
Run vulnhuntr scan --config vulnhuntr.toml --no-llm (for speed)
Upload SARIF (github/codeql-action/upload-sarif)
nightly-web3-scan.yml

Full mode with LLM correlation
Artifacts: JSON + Markdown
(Optional) create/update an issue if new high severity findings appear.
Dependencies (Proposed Extras)
pyproject optional extras:

Code
[project.optional-dependencies]
web3 = [
  "slither-analyzer>=0.10.4",
  "mythril>=0.24.0",
  "semgrep>=1.72.0",
  "web3>=6.0.0",
  "jinja2>=3.1.2",
  "requests>=2.32.0",
  "pydantic>=2.6.0",
  "rich>=13.7.0",
  "typer>=0.12.0",
  "tomli; python_version<'3.11'"
]
dev = [
  "pytest",
  "pytest-cov",
  "ruff",
  "mypy"
]
Initial Phase Roadmap (Suggested PR Sequence)
Scaffolding & Packaging
Add pyproject.toml, basic CLI, logging, config loader.
Slither Integration
Run slither, parse JSON (use --json), map to Finding objects.
Mythril Integration
Selective targeted functions or full contract.
Output Writers (JSON + Markdown)
LLM Normalization + Correlation (optional toggle)
Etherscan Fetcher (verified source ingestion)
Foundry / Echidna hooks (generate property stubs from LLM)
Semgrep custom Solidity rule bundle (basic patterns)
SARIF export + GitHub Action integration
Advanced detectors (delegatecall misuse inference, oracle surface)
Caching & performance (avoid duplicate compilation, reuse slither intermediate)
Windows + Docker polish (shell abstraction, path normalization)
Documentation & contributor guide
Example Skeleton Files

src/vulnhuntr/cli.py
v1
import typer
from .core.runner import Orchestrator
from .config.loader import load_config

app = typer.Typer(help="vulnhuntr2 - Web3-focused vulnerability discovery")


src/vulnhuntr/scanners/slither_runner.py
import subprocess, json, tempfile, shutil
from pathlib import Path
from ..core.models import Finding

class SlitherRunner:
    def __init__(self, cfg, logger):

src/vulnhuntr/core/models.py
v1
from dataclasses import dataclass, field
from typing import List, Optional, Dict
import hashlib, json

@dataclass
class Finding:

pyproject.toml
v1
[project]
name = "vulnhuntr2"
version = "0.1.0"
description = "Web3-focused LLM-augmented vulnerability discovery"
authors = [{name="Your Name", email="you@example.com"}]
license = "AGPL-3.0"

README.md
v1
# vulnhuntr2 (Web3 Edition)

Web3-focused, LLM-augmented vulnerability discovery orchestrator.  
Integrates Slither, Mythril, Semgrep, (optionally) Foundry & Echidna, plus LLM correlation and remediation suggestion layers.

## Quick Start
Correlation & Prioritization Logic (Conceptual)
Group findings by (file, function, category).
Merge Slither + Mythril overlapping items (increase confidence).
Use LLM to label composite risk (e.g., reentrancy + missing access control).
Escalate severity if multiple supporting signals.
Generate remediation patch template:
Insert ReentrancyGuard
Add checks-effects-interactions ordering
Add role-based modifier (e.g. OpenZeppelin AccessControl)
Windows Considerations
Avoid shell=True; pass lists to subprocess.
Provide --foundry-bin override if user installed non-default path.
Offer --docker flag to run scanners inside a container (future).
Normalize paths with pathlib consistently for file mapping.
_______________________________________________________________________________
Phase 3: Config + Extensibility – Detailed Implementation Plan

Goal
Introduce a robust, user‑tunable configuration system that controls detector selection, feature toggles (LLM, PoC, Slither), output modes, and CI gating. Establish consistent precedence (CLI > env vars > project toml defaults) and pave the way for future plug‑ins.

High-Level Outcomes
1. Rich TOML schema (vulnhuntr.toml) with validation.
2. Enable/disable detectors via globs, exact names, or categories.
3. Optional dependency groups ([llm], [static], [detectors-extra], later [mythril], etc.).
4. Environment variable overrides using a predictable namespace (VULNHUNTR_*).
5. CLI introspection: list detectors with status (enabled, disabled, unavailable).
6. Deterministic CI gating (--fail-on-severity, --fail-on-confidence).
7. Config dump/export for reproducibility.

Planned Additions & Modifications

File / Module Plan

```python name=src/vulnhuntr/core/version.py
VERSION = "0.1.0-alpha"  # bump to alpha once Phase 2 merges; Phase 3 may set 0.2.0-alpha
```

```python name=src/vulnhuntr/config/schema.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal

SeverityStr = Literal["INFO","LOW","MEDIUM","HIGH","CRITICAL"]

@dataclass
class RunConfig:
    enable_llm: bool = False
    enable_poc: bool = False
    enable_correlation: bool = True
    use_slither: bool = False

@dataclass
class DetectorSelection:
    enable: List[str] = field(default_factory=lambda: ["*"])
    disable: List[str] = field(default_factory=list)

@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 800
    timeout_s: int = 45

@dataclass
class OutputConfig:
    min_severity: SeverityStr = "LOW"
    min_confidence: float = 0.0
    formats: List[str] = field(default_factory=lambda: ["console"])
    fail_on_severity: Optional[SeverityStr] = None
    fail_on_confidence: Optional[float] = None
    fail_on_finding_count: Optional[int] = None

@dataclass
class ConfigModel:
    run: RunConfig = RunConfig()
    detectors: DetectorSelection = DetectorSelection()
    llm: LLMConfig = LLMConfig()
    output: OutputConfig = OutputConfig()
    raw: Dict = field(default_factory=dict)  # keep untouched original for debugging
```

```python name=src/vulnhuntr/config/loader.py
import os, re, json
from pathlib import Path
from typing import Optional
try:
    import tomllib  # py3.11+
except ImportError:
    import tomli as tomllib

from .schema import ConfigModel, RunConfig, DetectorSelection, LLMConfig, OutputConfig

ENV_PREFIX = "VULNHUNTR_"

def _env(key: str, default=None):
    return os.getenv(f"{ENV_PREFIX}{key}", default)

def load_config(explicit_path: Optional[Path]) -> ConfigModel:
    paths = []
    if explicit_path:
        paths.append(explicit_path)
    else:
        for candidate in ("vulnhuntr.toml", ".vulnhuntr.toml", "config/vulnhuntr.toml"):
            p = Path(candidate)
            if p.exists():
                paths.append(p); break
    data = {}
    src_file = None
    if paths:
        src_file = paths[0]
        with open(src_file, "rb") as f:
            data = tomllib.load(f)

    cfg = ConfigModel()
    cfg.raw = data

    # Merge TOML
    run = data.get("run", {})
    det = data.get("detectors", {})
    llm = data.get("llm", {})
    out = data.get("output", {})

    cfg.run = RunConfig(
        enable_llm=run.get("enable_llm", cfg.run.enable_llm),
        enable_poc=run.get("enable_poc", cfg.run.enable_poc),
        enable_correlation=run.get("enable_correlation", cfg.run.enable_correlation),
        use_slither=run.get("use_slither", cfg.run.use_slither),
    )
    cfg.detectors = DetectorSelection(
        enable=det.get("enable", cfg.detectors.enable),
        disable=det.get("disable", cfg.detectors.disable),
    )
    cfg.llm = LLMConfig(
        provider=llm.get("provider", cfg.llm.provider),
        model=llm.get("model", cfg.llm.model),
        temperature=llm.get("temperature", cfg.llm.temperature),
        max_tokens=llm.get("max_tokens", cfg.llm.max_tokens),
        timeout_s=llm.get("timeout_s", cfg.llm.timeout_s),
    )
    cfg.output = OutputConfig(
        min_severity=out.get("min_severity", cfg.output.min_severity),
        min_confidence=out.get("min_confidence", cfg.output.min_confidence),
        formats=out.get("formats", cfg.output.formats),
        fail_on_severity=out.get("fail_on_severity", cfg.output.fail_on_severity),
        fail_on_confidence=out.get("fail_on_confidence", cfg.output.fail_on_confidence),
        fail_on_finding_count=out.get("fail_on_finding_count", cfg.output.fail_on_finding_count),
    )

    # ENV overrides (simple examples)
    if _env("ENABLE_LLM") is not None:
        cfg.run.enable_llm = _env("ENABLE_LLM").lower() in ("1","true","yes")
    if _env("ENABLE_POC") is not None:
        cfg.run.enable_poc = _env("ENABLE_POC").lower() in ("1","true","yes")
    if _env("DETECTORS_ENABLE"):
        cfg.detectors.enable = [s.strip() for s in _env("DETECTORS_ENABLE").split(",") if s.strip()]
    if _env("DETECTORS_DISABLE"):
        cfg.detectors.disable = [s.strip() for s in _env("DETECTORS_DISABLE").split(",") if s.strip()]
    if _env("FAIL_ON_SEVERITY"):
        cfg.output.fail_on_severity = _env("FAIL_ON_SEVERITY").upper()

    return cfg

def dump_config(cfg: ConfigModel) -> str:
    # Lightweight JSON renderer for --config-dump
    obj = {
        "run": cfg.run.__dict__,
        "detectors": cfg.detectors.__dict__,
        "llm": cfg.llm.__dict__,
        "output": cfg.output.__dict__,
    }
    return json.dumps(obj, indent=2)
```

```python name=src/vulnhuntr/detectors/base.py
# Add metadata hooks for config-driven enabling
class BaseDetector(ABC):
    name: str = "base"
    category: str = "generic"
    stability: str = "experimental"  # could be stable/experimental/deprecated
    default_enabled: bool = True

    @classmethod
    def matches_selector(cls, selector: str) -> bool:
        # selector can be exact name, category:, or glob
        import fnmatch
        if selector.startswith("category:"):
            return selector.split(":",1)[1] == cls.category
        return fnmatch.fnmatch(cls.name, selector)
```

```python name=src/vulnhuntr/detectors/__init__.py
# After auto-discovery, apply config filtering
def load_detectors(config=None):
    detectors = _auto_discover()  # existing
    if not config:
        return detectors
    enabled_selectors = config.detectors.enable or ["*"]
    disabled_selectors = config.detectors.disable or []
    filtered = []
    for dcls in detectors:
        # compute enabled
        explicit_enable = any(dcls.matches_selector(sel) for sel in enabled_selectors)
        explicit_disable = any(dcls.matches_selector(sel) for sel in disabled_selectors)
        if explicit_disable:
            continue
        if explicit_enable or (dcls.default_enabled and "*" in enabled_selectors):
            filtered.append(dcls)
    return filtered
```

```python name=src/vulnhuntr/cli.py
# Pseudocode additions inside existing Typer app
@app.command()
def scan(
    path: Path = typer.Argument(...),
    config_file: Optional[Path] = typer.Option(None, "--config"),
    enable: List[str] = typer.Option([], "--enable", help="Extra detector selectors to enable"),
    disable: List[str] = typer.Option([], "--disable", help="Detector selectors to disable"),
    fail_on_severity: Optional[str] = typer.Option(None, "--fail-on-severity"),
    fail_on_confidence: Optional[float] = typer.Option(None, "--fail-on-confidence"),
    config_dump: bool = typer.Option(False, "--config-dump", help="Print merged config and exit"),
    # existing flags preserved...
):
    cfg = load_config(config_file)
    if enable:
        cfg.detectors.enable.extend(enable)
    if disable:
        cfg.detectors.disable.extend(disable)
    if fail_on_severity:
        cfg.output.fail_on_severity = fail_on_severity.upper()
    if fail_on_confidence is not None:
        cfg.output.fail_on_confidence = fail_on_confidence
    if config_dump:
        print(dump_config(cfg)); raise typer.Exit()

    detector_classes = load_detectors(cfg)
    # ... existing scanning pipeline
    # After findings gathered:
    exit_code = 0
    from vulnhuntr.core.models import Severity
    def sev_ge(a,b):
        order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
        return order.index(a) >= order.index(b)

    if cfg.output.fail_on_severity:
        if any(sev_ge(f.severity.name if hasattr(f.severity,'name') else f.severity,
                      cfg.output.fail_on_severity) for f in findings):
            exit_code = 1
    if cfg.output.fail_on_confidence is not None:
        if any(f.confidence >= cfg.output.fail_on_confidence for f in findings):
            exit_code = 1
    if cfg.output.fail_on_finding_count is not None:
        if len(findings) >= cfg.output.fail_on_finding_count:
            exit_code = 1
    raise typer.Exit(code=exit_code)
```

Sample Configuration

````markdown name=vulnhuntr.example.toml
[run]
enable_llm = false
enable_poc = false
enable_correlation = true
use_slither = false

[detectors]
enable = ["*"]
disable = ["gas-sensitive-branching"]  # temporarily disabled

[llm]
provider = "openai"
model = "gpt-4o-mini"
temperature = 0.1
max_tokens = 800
timeout_s = 45

[output]
min_severity = "LOW"
min_confidence = 0.0
formats = ["console", "json"]
fail_on_severity = "HIGH"
# fail_on_confidence = 0.85
# fail_on_finding_count = 50
````

Tests

```python name=tests/test_config_precedence.py
def test_cli_overrides_env(monkeypatch, tmp_path):
    from vulnhuntr.config.loader import load_config
    monkeypatch.setenv("VULNHUNTR_ENABLE_LLM", "1")
    cfg = load_config(None)
    assert cfg.run.enable_llm is True
```

```python name=tests/test_detector_enable_disable.py
def test_enable_disable_cycle(monkeypatch):
    from vulnhuntr.config.schema import ConfigModel, DetectorSelection
    from vulnhuntr.detectors import load_detectors
    cfg = ConfigModel()
    cfg.detectors = DetectorSelection(enable=["reentrancy*"], disable=["*"])
    dets = load_detectors(cfg)
    # Expect explicit enable to override blanket disable except for conflict order -> refine logic if needed
```

Environment Variable Mapping
VULNHUNTR_ENABLE_LLM=true
VULNHUNTR_ENABLE_POC=1
VULNHUNTR_DETECTORS_ENABLE=reentrancy*,flashloan*
VULNHUNTR_DETECTORS_DISABLE=gas-sensitive-branching
VULNHUNTR_FAIL_ON_SEVERITY=HIGH

Selector Semantics
- Exact match: privilege-escalation-path
- Glob: reentrancy*, *oracle*
- Category match: category:access-control

Failure Gate Logic
Triggered if any condition holds:
1. severity >= fail_on_severity
2. confidence >= fail_on_confidence
3. total findings >= fail_on_finding_count

We exit with code 1 (non-zero) for CI fail; otherwise 0.

Edge Cases & Safeguards
- Conflicting selectors (enable + disable): last-applied precedence (we can define explicit rule: disable wins unless an explicit CLI --enable was provided after config load; can finalize).
- Unknown detectors in enable list: emit a warning but continue.
- Empty enable list: results in no detectors unless user passes "*" explicitly.

Optional Nice-to-Haves (If Time Allows)
- --explain-selector selector: Output which detectors matched.
- JSON schema export for config (vulnhuntr config-schema --json).
- Colored diff when using --config-dump with an existing file (future).

Acceptance Criteria
- vulnhuntr scan respects enable/disable logic.
- Environment variables override TOML.
- CLI flags override both.
- Non-zero exit under defined gating conditions.
- list-detectors shows columns: name, category, enabled (Yes/No), reason (disabled-by-config, default, explicit-enable).

If you want I can open the Phase 3 PR scaffold now. Just say: “Create the Phase 3 PR” (or tweak anything first).

Let me know any adjustments (naming, selector precedence, additional output formats like SARIF early, etc.) and I’ll incorporate before generating the PR. Ready when you are.
_____________________________________________________________________________
Below is a comprehensive (go-the-extra‑mile) proposal for Phase 4, building directly atop Phases 1–3. I’ve framed multiple thematic options, then a recommended composite scope that gives you strong differentiating capability while keeping risk bounded.

---

## Phase 4 Theme: “Semantic Correlation, Path Reasoning & Enriched Evidence”

Goal  
Transform raw detector hits into higher‑signal findings by:  
1. Performing intra‑ and inter‑contract path & state impact reasoning (leveraging Slither CFG + dataflow).  
2. (Optionally) Incorporating Mythril symbolic exploration for selective deep traces (behind an extra).  
3. Correlating multiple low/medium heuristic signals into composite higher‑confidence vulnerabilities.  
4. Producing structured “evidence bundles” (traces, variable snapshots, event sequences) for each enriched finding.  
5. Introducing a scoring model that normalizes severity & confidence with explainable sub-scores.  

---

## Alternative Focus Options (Pick & Mix if you prefer)

| Option | Focus | Pros | Cons | Effort |
|--------|-------|------|------|--------|
| A | Pure CFG/Dataflow correlation | Lightweight (reuses Slither), deterministic | Limited depth for complex auth flaws | Medium |
| B | Symbolic Trace Augmentation (Mythril) | Deeper reachability proofs | Performance overhead, complexity | High |
| C | Evidence & Scoring Framework only | Immediately improves output clarity | Still heuristic; no new deeper analysis | Low-Med |
| D | Plugin Execution Framework (Activated) | Ecosystem expansion | Dilutes core analysis focus this phase | Medium |
| E | LLM Triage Layer (Selective) | Human-like reasoning description | Token cost, gating complexity | Medium-High |

Recommended Phase 4 Composite: A + partial B (guarded, opt-in) + C. Defer full plugin execution and broad LLM triage to Phase 5/6.

---

## High-Level Outcomes (Phase 4 Composite)

1. Correlation Engine  
   - Aggregates primitive detector hits via shared entities (contracts, functions, state vars, role-like modifiers).
   - Clusters: e.g. “Oracle Manipulation Chain” linking logic-oracle-mismatch + privilege-escalation-path when feed function influences access predicate.

2. Path Reasoner  
   - Builds reduced CFG slices (entry → sink) for functions flagged by detectors.  
   - On each slice, annotates external calls, state writes, access modifiers, reentrancy gates.  
   - Produces “path fingerprints” (hash of node categories) enabling pattern reuse.

3. Selective Symbolic Exploration (Mythril-lite)  
   - When correlation engine sees a cluster above a heuristic significance threshold OR a single finding severity ≥ HIGH but confidence < 0.8, optionally trigger mythril exploration on implicated function(s).  
   - Hard cap: max_paths, max_time per function (configurable).  
   - Stores summarized trace steps (call sequence + storage diffs) into evidence bundle.

4. Evidence Bundles  
   - Standardized JSON structure attached to each enriched finding:  
     {
       "correlated_raw_ids": [...],
       "paths": [{ "id": "...", "entry": "fn", "external_calls": [...], "state_writes": [...], "guards": [...]}],
       "symbolic_traces": [{ "depth": n, "events": [...], "storage_effects": {...} }],
       "variables_of_interest": [...],
       "explanations": { "correlation": "...", "path_summary": "...", "symbolic_support": "proven/unproven/partial" }
     }

5. Scoring Model v1  
   - severity_base (from original detector) → adjusted by factors (exposure_factor, multiplicity_factor, guard_absence_factor, proven_reachability_factor).  
   - confidence recalculated: combine (original_confidence, correlation_strength, path_coverage_ratio, symbolic_outcome_weight).  
   - Publish sub-score vector for transparency.

6. Config Additions (Phase 4)  
   [correlation] enable=true, max_cluster_span=6  
   [symbolic] enable=false, engine="mythril", max_time_s=25, max_paths=3, trigger_min_severity="HIGH", trigger_min_cluster_size=2  
   [scoring] enable=true, explanation=true, normalization_strategy="sigmoid-v1"  

7. CLI Enhancements  
   - --enable-correlation / --no-enable-correlation (now already exists conceptually; unify with config).  
   - --symbolic / --no-symbolic (shortcut to symbolic.enable toggle).  
   - --evidence-json PATH (emit consolidated evidence separate from findings).  
   - list-detectors gains a column “correlatable” (Yes if participates in correlation taxonomy).  
   - New command: vulnhuntr explain <finding-id> (renders formatted evidence & scoring breakdown).

8. Metadata & Reporting  
   - JSON meta gains: correlation_clusters_count, symbolic_runs_executed, scoring_model_version.  
   - Each finding includes: original_severity, adjusted_severity, original_confidence, adjusted_confidence, scoring_factors.

---

## Detailed Implementation Plan

### A. Data Structures

````python name=src/vulnhuntr/correlation/models.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class PrimitiveFindingRef:
    id: str
    detector: str
    severity: str
    confidence: float
    contract: Optional[str]
    function: Optional[str]

@dataclass
class CorrelationCluster:
    id: str
    kind: str  # e.g. "oracle-manipulation-chain"
    members: List[PrimitiveFindingRef]
    shared_entities: Dict[str, List[str]]  # e.g. {"contracts":["Oracle","Pool"], "state_vars":["price","owner"]}
    significance: float  # heuristic 0..1
    rationale: str
````

````python name=src/vulnhuntr/path/graph.py
@dataclass
class PathSlice:
    id: str
    function: str
    contract: str
    external_calls: List[str]
    state_writes: List[str]
    guards: List[str]
    reentrancy_points: List[str]
    length: int
````

````python name=src/vulnhuntr/symbolic/interface.py
class SymbolicEngine:
    def explore(self, contract: str, function: str, timeout_s: int, max_paths: int) -> List[dict]:
        raise NotImplementedError
````

````python name=src/vulnhuntr/symbolic/mythril_engine.py
# Thin wrapper; handles ImportError gracefully
````

````python name=src/vulnhuntr/scoring/model.py
@dataclass
class ScoreFactors:
    exposure: float
    multiplicity: float
    guard_absence: float
    reachability: float
    correlation_strength: float

def adjust(severity: str, base_conf: float, factors: ScoreFactors) -> (str, float, dict):
    # map severity to numeric, apply weights -> new severity tier & confidence
    ...
````

### B. Correlation Engine Logic (Heuristics)

1. Index primitive findings by (contract, function, category).
2. Define pattern rules:
   - ORACLE_CHAIN: presence of logic-oracle-mismatch + eventless-critical-action sharing same price state var OR function sequence.
   - PRIV_ESC_COMPOSITE: privilege-escalation-path + domain-separator-reuse + access-control-laxity (future) with shared modifier absence.
   - FLASHLOAN_CHAIN: flashloan-invariant-breach + gas-sensitive-branching on same entrypoint or nested external call chain.
3. Each pattern returns cluster with significance = normalized(#members, guard_absence, external_call_density).

### C. Path Slicing

- For each function in any cluster:  
  - Use Slither’s CFG to extract nodes until termination or breadth threshold.  
  - Capture features (external call nodes, writes to cluster-involved variables, modifiers encountered).  
  - Store hashed fingerprint for caching (cfg_hash.json).  

Caching considerations:  
- Cache key: (file_sha256, function_name, slither_version).  
- Skip regeneration if unchanged unless --no-cache flag.

### D. Symbolic Exploration (Optional)

Trigger conditions:  
- cluster.significance ≥ 0.55 OR (primitive severity HIGH/CRITICAL & confidence < 0.8).  
- For each triggered (contract,function) pair not yet symbolically explored in run.  
- Provide exploration budget respecting total runtime guard (symbolic.max_total_time_s maybe added).  

Results distilled to:  
- path_status: proven / partial / inconclusive  
- side_effects: storage writes categories  
- constraints_summary  

### E. Scoring Model

Numeric mapping: INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4  
Compute base_score then apply:  
score' = base + w1*exposure + w2*multiplicity + w3*guard_absence + w4*reachability + w5*correlation_strength  
Thresholds to bump severity tier (e.g. ≥3.4 => CRITICAL).  
Confidence' = sigmoid( α * Σ normalized factors + β * base_conf ).  
Publish detailed factor table.

### F. CLI Additions

- vulnhuntr scan ... --symbolic (toggles symbolic.enable)  
- --evidence-json PATH  
- vulnhuntr explain FINDING_ID  
  - Loads report, locates finding, renders textual + JSON snippet.

### G. Config Additions

````markdown name=vulnhuntr.example.phase4.toml
[correlation]
enable = true
max_cluster_span = 6

[symbolic]
enable = false
engine = "mythril"
max_time_s = 25
max_paths = 3
trigger_min_severity = "HIGH"
trigger_min_cluster_size = 2

[scoring]
enable = true
explanation = true
normalization_strategy = "sigmoid-v1"
````

### H. JSON Report Additions

meta:  
  correlation_clusters_count  
  symbolic_runs_executed  
  scoring_model_version  
findings[i]:  
  original_severity  
  adjusted_severity  
  original_confidence  
  adjusted_confidence  
  scoring_factors: {...}  
  evidence_ref (id pointing to evidence bundle)  

Separate evidence file (if requested) or inline evidence[].  

### I. Tests (Representative)

| Test | Purpose |
|------|---------|
| test_correlation_oracle_chain.py | Validates clustering pattern detection |
| test_path_slice_features.py | Ensures path extraction captures external calls & writes |
| test_symbolic_trigger_conditions.py | Symbolic triggered only under correct thresholds |
| test_scoring_adjustment_bump.py | Severity bump scenario validated |
| test_evidence_bundle_integrity.py | Evidence references resolvable & schema valid |
| test_config_symbolic_graceful_missing.py | Mythril absent -> no crash |
| test_cache_path_fingerprint.py | Cache hit reduces subsequent run time |
| test_explain_command_output.py | CLI explain output correctness |

### J. Performance & Safeguards

- Hard global time budget for correlation + symbolic (e.g. default 40s).  
- Fallback: if symbolic budget exceeded mid exploration, mark as partial.  
- Provide run metrics: correlation_time_ms, path_analysis_time_ms, symbolic_time_ms.

### K. Risks & Mitigation

| Risk | Mitigation |
|------|------------|
| Mythril dependency bloat | Keep under optional extra [symbolic] |
| Over-adjusted severity inflation | Cap single factor contribution; add unit tests |
| Large evidence JSON size | Truncate traces to first/last N steps; optional compression |
| Path explosion | Depth/breadth limits, fingerprint caching |
| User confusion on scoring | Provide scoring_factors with human-readable rationale |

### L. Estimated Timeline

| Week | Deliverables |
|------|--------------|
| 1 | Correlation engine, models, cluster heuristics, basic tests |
| 2 | Path slicing, caching, integration with correlation, evidence bundle skeleton |
| 3 | Symbolic wrapper + triggers, scoring model baseline, CLI flags |
| 4 | Stabilization, docs, extended tests, performance tuning |

(Accelerated schedule possible if symbolic deferred.)

### M. Documentation Upgrades

- docs/correlation.md: Patterns, heuristics, cluster structure.  
- docs/scoring.md: Factor definitions & formulas.  
- docs/symbolic.md: Usage, cost, limitations.  
- README: New flags, config blocks, example workflow screenshot (later).  

### N. Deferrable (Phase 5+)

- Full plugin execution with hook points (pre-scan, post-finding).  
- LLM triage overlay generating natural-language reasoning paragraphs per cluster.  
- SARIF output enriched with correlation & evidence references.  
- Multi-chain context ingestion (if bridging artifacts introduced).  

---

## Acceptance Criteria Summary

1. Correlation clusters produced deterministically (same inputs → same cluster IDs).  
2. Adjusted severity/confidence always supplied with transparent factor breakdown.  
3. Optional symbolic exploration safely skipped if disabled or dependency missing.  
4. Evidence bundles accessible via CLI explain and referenced in findings.  
5. Performance guardrails enforced; no runaway analysis.  
6. All new config keys validated; unknown keys warn (reuse Phase 3 validation path).  
7. No regressions to prior flags; running without new opts behaves as before (no scoring changes if scoring.enable=false).  

++++++++++++++++++++++++++++++++++++++
**Phase 4: proceed with full composite plan.**

You’ve scoped this like a pro. I’d ship A + guarded B + C exactly as proposed, with the tweaks below to keep depth without face-planting on perf or ambiguity:

### Tighten what’s already there

* **Deterministic IDs everywhere.**
  Cluster ID = `sha256("cluster:" + kind + ":" + join(sorted(member_ids),","))`.
  Path fingerprint = `sha256("path:" + contract + ":" + function + ":" + node_category_seq)`.
  Evidence bundle ID = `sha256("evidence:" + finding_id)`. Determinism buys reproducibility and diff-friendly PRs.

* **Explicit correlation taxonomy.**
  Ship a `correlation/patterns.yml` with pattern name, member detectors (by canonical ID), join keys (e.g., `state_vars.price`), and weights. Load at runtime so we can iterate without code changes.

* **Guarded symbolic triggers.**
  Add **two fuses**: `symbolic.max_total_time_s` (global cap) and `symbolic.max_functions= N` (per run cap). If we hit either, annotate symbolic outcome as `skipped:budget`.

* **Solidity/EVM awareness.**
  Put `solc_version`, `evm_version`, and `optimizer` into meta; warn if Mythril target doesn’t match. Use that tuple in cache keys so slices don’t go stale across compilers.

* **Proxy/storage quirks.**
  Add a lightweight detector for `delegatecall`/ERC1967 slots and propagate that as a **risk multiplier** (`exposure` bump) when paths cross upgradeable storage.

### Make the scoring model legible (and testable)

* **Severity math (concrete):** map {INFO:0,LOW:1,MED:2,HIGH:3,CRIT:4}.
  `score' = base + 0.35*exposure + 0.25*multiplicity + 0.25*guard_absence + 0.30*reachability + 0.25*correlation_strength` (clip to \[0,5]).
  Thresholds: `≥4.1→CRITICAL, ≥3.2→HIGH, ≥2.4→MED, ≥1.2→LOW else INFO`.
  Confidence': `sigmoid(1.4*(0.4*base_conf + 0.6*(avg(factors))))`. Publish every input so auditors can redo the math.

* **Explainability first.**
  For each factor, attach a one-liner: e.g., `guard_absence: "noOnlyOwner || missing reentrancy guard on external write"`.

### Evidence bundles that humans actually read

* Add `compilable_min_repro.sol` (optional) when a single function repro is cleanly sliceable; include deps by stub interfaces.
* Collapse long traces into **head … tail** with `elided_steps` count; always include **first external call** and **first state-write to VOI**.

### Path slicing details (accuracy without explosion)

* Slice breadth-first to `length ≤ 80 nodes` and **stop at**: termination, loop backedge seen twice, or cross-contract call (record hop, don’t inline).
* Classify nodes into **stable categories**: `CALL{static,delegate,plain}`, `WRITE{storage,slot}`, `READ{storage}`, `GUARD{modifier,require}`, `XFER{native,erc20,erc721}`, `EVENT`, `LOOP`, `TRY`, `ASM`. That set becomes your fingerprint alphabet.

### CLI & UX polish

* `vulnhuntr explain <finding-id> --markdown` for pastable reports; `--json` keeps raw.
* `--evidence-json` writes a separate file **and** adds `evidence_ref` in findings to that file’s object key.
* `list-detectors` new columns: `correlatable`, `category`, `since_phase`.

### Config & defaults (safer out of the box)

```toml
[symbolic]
enable = false
engine = "mythril"
max_time_s = 25
max_total_time_s = 40
max_paths = 3
max_functions = 3
trigger_min_severity = "HIGH"
trigger_min_cluster_size = 2
```

### Tests to add (beyond your list)

* **Determinism under re-ordering:** shuffling primitive findings yields identical cluster IDs and scores.
* **Budget exhaustion:** craft a corpus that purposely hits `max_total_time_s`; assert graceful `skipped:budget`.
* **Proxy pathing:** delegatecall slice captures storage-write VOIs across logic contracts.
* **Versioned cache:** changing `solc_version` invalidates path cache, verified via metrics.

### Perf rails & metrics

* Emit `phase4_budget_remaining_ms` in meta and per-stage timings; fail *softly* to correlation-only if symbolic asks for more than budget.
* Add a `--profile` flag to dump a flame-style summary (stage, count, time\_ms).

### Small but mighty wins

* **Pattern: Allowlist drift.** Correlate `role-modifier-mismatch` + `eventless-critical-action` + `unchained-initializer` on the same contract — common upgrade gotcha.
* **Pattern: Price-feed footgun.** `stale-oracle-read` + `unchecked-cast` on the same price var → bump `reachability` even without symbolic proof.

---
_______________________________________________________________________________
# Phase 5 Proposal: “Extensible Intelligence, Ecosystem Output & Incremental Precision”

You’ve now got:
- Phase 3: Strong config + gating + reproducibility.
- Phase 4: Correlation, path reasoning, (optional) symbolic exploration, scoring, evidence.

Phase 5 should push toward: ecosystem integration, smart triage & automation, extensibility (true plugin architecture), and tighter developer workflows (incremental scans, diff intelligence, remediation hints). Below is a comprehensive roadmap—modular so you can trim or re-scope.

---

## Strategic Theme Options

| Track | Focus | Primary Value | Maturity Leverage |
|-------|-------|---------------|-------------------|
| T1 | Plugin Execution & Extensibility | Community detectors & enrichers | Builds on Phase 3 config model |
| T2 | AI / LLM Triage & Remediation | Developer-time acceleration | Builds on Phase 4 evidence bundles |
| T3 | Incremental & Diff Scanning | CI speed + signal density | Uses deterministic IDs & fingerprints |
| T4 | Ecosystem Outputs (SARIF, OCSF, GitHub code scanning) | Enterprise adoption | Leverages scoring/metadata |
| T5 | Multi-Chain + Cross-Context (L2 / bridging / price-feed ingestion) | Broader attack surface modeling | Extends correlation engine |
| T6 | Observability & Telemetry (opt-in) | Fleet-scale quality metrics | Stabilizes scoring trust |
| T7 | Rule / Pattern DSL + Hot Reload | Fast iteration on heuristics | Evolves patterns.yml idea |

Recommended Phase 5 composite: T1 + T2 + T3 + core of T4 (SARIF + GitHub code scanning) + lightweight start of T7 (rule DSL foundation). Defer multi-chain heavy-lift to Phase 6 unless urgent.

---

## Phase 5 Goals (Composite)

1. Plugin Runtime:
   - Deterministic, sandbox-friendly plugin loading via entry points (e.g. `vulnhuntr.detectors`, `vulnhuntr.enrichers`, `vulnhuntr.postprocessors`).
   - Plugin manifest contract (`plugin.toml` or `PluginInfo` class) with declared capabilities + version compatibility.
   - Hard execution budget per plugin (time & memory soft guard).
   - Structured error isolation (plugin crash → logged, not fatal).

2. AI / LLM Triage Layer:
   - Optional post-processing pass that consumes final enriched findings (with evidence).
   - Produces: natural-language risk summary, exploit hypothesis, minimal PoC sketch, remediation recommendation template.
   - Ranking: Use scoring + heuristics to select top N “human-attend-now” findings for LLM cost control.
   - Prompt caching: keyed by (finding_id, config_hash, scoring_model_version).
   - Guardrails: Redact secrets / addresses flagged as sensitive.

3. Incremental / Diff Scanning:
   - New mode: `scan --diff-base <git-ref>` analyzing only changed contracts/functions (structural diff).
   - Fingerprint reuse: skip path slicing & symbolic if fingerprint unchanged (compare contract source hash + function signature + compiled IR hash).
   - Output “delta report” tagging findings as {added, removed, persisted, severity_changed}.
   - Generate “regression risk” summary if critical removed finding disappears without code change in relevant region (catch silent detector drift).

4. SARIF + GitHub Advanced Security Integration:
   - SARIF exporter v1 aligning findings + evidence summary.
   - Mapping: severity → SARIF level (note / warning / error) + scoring factors into `properties`.
   - Embed `correlation_clusters_count`, `config_hash`, `scoring_model_version` in SARIF run properties.
   - Option `--sarif out.sarif` and `--gh-code-scanning` mode (print to stdout for GitHub Actions).

5. Rule / Pattern DSL (Foundation):
   - YAML/DSL for correlation/pattern & detector post-rules:
     ```
     pattern:
       name: reentrancy-exposure-burst
       requires:
         - detectors: [reentrancy-basic, proxy-upgrade-surface]
         - path_feature: external_calls >= 2
       effects:
         score.adjust:
           exposure: +0.3
           reachability: +0.2
     ```
   - Hot reload: `vulnhuntr dev watch-patterns` for rule authoring with instant re-evaluation over cached primitive findings.

6. Remediation Knowledge Base:
   - Curate mapping: vulnerability.kind → recommended mitigation bullets (pattern-driven).
   - Include “common pitfalls avoided by fix” and “gas-impact note” where relevant.
   - Provide CLI output: `explain --markdown` embeds remediation section.

7. Structured Output Unification:
   - Introduce canonical internal schema layer (versioned): `schema_version: 0.5.0`.
   - Add compatibility translator for future changes (e.g., severity naming or factor expansion).

8. Performance & Stability:
   - Integrate function-level “cold vs warm scan” metrics.
   - CLI `--profile` upgraded: per-phase breakdown + plugin contributions.

9. Developer Experience Enhancers:
   - `vulnhuntr cache purge` / `cache stats`.
   - `scan --focus finding:<id>` to re-enrich a single finding (useful for iterating plugin logic).
   - Color-coded diff view for `--diff-base`.

---

## Architecture Additions

| Component | Purpose | Key Interfaces |
|-----------|---------|----------------|
| PluginManager | Discovery, lifecycle, budget enforcement | `register(detector|enricher|postprocessor)` |
| Enricher API | Add evidence augmentation (e.g., on-chain slot resolution, ABI significance) | `enrich(finding, context)` |
| PostProcessor API | Re-rank / collapse / escalate findings | `process(findings, run_context)` |
| LLM Triage Service | Summarization & remediation generation | `triage(findings, policy)` |
| Diff Analyzer | Compute structural change set | `diff(base_ref, head_ref)` |
| Fingerprint Store | Persist function & path fingerprints | `lookup(fn_sig)`, `store(fingerprint)` |
| Rule Engine | Load + evaluate DSL rules | `apply_rules(context, findings)` |
| SARIF Exporter | Convert unified schema -> SARIF JSON | `to_sarif(report)` |

---

## Data Model Evolutions

Add to finding entity:
- triage: { highlight: bool, rationale: string }
- remediation: { summary, steps: [..], references: [...] }
- diff_status: added|removed|persisted|changed|null
- rule_hits: [pattern_name]
- plugin_attributions: [ { name, version, contribution: { confidence_delta, evidence_refs } } ]

Add to meta:
- schema_version
- plugins_loaded: list with {name, version, type, load_status}
- diff_base_ref (if diff mode)
- incremental: { functions_scanned, functions_skipped_cache }
- llm_triage: { enabled, tokens_used, findings_processed }
- ruleset_hash

---

## Config Additions (Illustrative)

```toml
[plugins]
enable = true
# optional allow/deny lists
allow = ["*"]
deny = []

[triage]
enable = false
provider = "openai"
model = "gpt-4o-mini"
max_findings = 8
cache = true
timeout_s = 40

[diff]
enable = true
strategy = "structural"  # or "text"
fallback_full_scan = true

[sarif]
enable = false
logical_locations = true
embed_evidence = "summary"  # none|summary|full

[rules]
enable = true
paths = ["rules/*.yml"]
strict = false  # if true, unknown detectors in rules cause failure
```

Environment variable overrides continue with `VULNHUNTR_TRIAGE_ENABLE`, etc.

---

## CLI Enhancements

| Command / Flag | Description |
|----------------|-------------|
| `vulnhuntr scan --diff-base <ref>` | Incremental scan vs git ref |
| `vulnhuntr scan --sarif report.sarif` | Emit SARIF |
| `vulnhuntr scan --triage` | Enable LLM triage |
| `vulnhuntr scan --ruleset-hash` | Print active ruleset hash |
| `vulnhuntr explain <finding-id> --refresh-triage` | Re-run triage for that finding |
| `vulnhuntr plugins list` | Show discovered plugins & status |
| `vulnhuntr rules test <file.yml>` | Validate single rule file |
| `vulnhuntr diff <base> <head>` | Standalone diff + classification |
| `vulnhuntr cache stats|purge` | Cache management |
| `vulnhuntr triage simulate --top 5` | Dry-run triage selection logic |

---

## LLM Triage Flow (Selective)

1. Select candidate findings:
   - Sort by adjusted_severity desc, then (adjusted_confidence < 0.92) to prioritize ambiguous / high impact.
   - Filter max N (triage.max_findings).
2. Compose prompt:
   - Provide normalized evidence (paths compressed, symbolic outcome, risk factors).
   - Provide scoring factors & rule hits.
3. Output parsed into:
   - risk_summary
   - plausible_exploit (if meaningful)
   - remediation_actions (list)
   - false_positive_likelihood (model self-estimate thresholded)
4. Validation:
   - Reject output if hallucination detector triggers (e.g., references unknown state vars); fallback to internal template.

Caching key: `sha256(finding_id + scoring_model_version + evidence_hash + triage.model)`.

---

## Diff & Incremental Mechanics

1. Resolve base ref: gather contract sources at base and head (git show).
2. Map functions: by signature + normalized AST hash (strip whitespace, comments).
3. Changed set = new_or_modified_functions.
4. Only run detectors / slicing / symbolic on changed set unless correlation requires context; correlation engine:
   - Pull persisted fingerprints for unchanged functions as “context-only.”
5. Final report annotates unchanged persisted findings (carryover) vs new.

Edge case: a previously reported finding disappears but underlying function unchanged → mark as “removed_unexpected” and warn (potential detector regression).

---

## Rule / DSL Implementation (Phase 5 Scope)

Minimal evaluator:
- Load YAML definitions into an internal AST.
- Provide selectors:
  - detectors: name or glob.
  - path_feature: e.g., `external_calls >= 2`.
  - factor_threshold: `reachability > 0.5`.
- Effects:
  - score.adjust.{exposure|multiplicity|guard_absence|reachability|correlation_strength} += delta
  - annotate: add tag to finding.
- Order: Apply deterministic sorted by rule name; no conflicts resolution (sum deltas). Provide conflict warning if two rules adjust same factor in opposite directions > threshold.

Ruleset hash: sha256(sorted(serialized rule bodies)).

---

## Testing Matrix

| Category | Key Tests |
|----------|-----------|
| Plugins | Load success/failure isolation, time budget, memory abuse simulation |
| Triage | Deterministic selection set, cache hit vs miss, hallucination guard |
| Diff Mode | Unchanged = skipped; added/removed classification; regression detection |
| SARIF | Valid against schema; round-trip GitHub code scanning ingestion smoke test |
| Rules | Hot reload (modify file mid-run); conflict warnings |
| Incremental Performance | Time reduction > X% on controlled corpus |
| Determinism | Same inputs + ruleset hash → identical triage outputs (when cached) |
| Security | Plugin sandbox: no unauthorized file writes outside allowed temp path |
| Fallbacks | Triage provider unavailable → graceful skip; rule parse error with strict=false logs warning |

---

## Performance Targets

| Phase Component | Target |
|-----------------|--------|
| Plugin overhead (no plugins) | < 50 ms added |
| Diff scan speedup on 10% change | ≥ 55% faster vs full |
| Triage LLM (top 5) | ≤ 12s wall time (parallel batching optional) |
| SARIF generation | O(number_of_findings) linear, < 150 ms for 500 findings |

---

## Risk & Mitigation

| Risk | Mitigation |
|------|------------|
| Plugin security | Document trust model; later consider WASI sandbox or subprocess isolation |
| LLM hallucinations | Structured output schema + variable name whitelist + fallback templates |
| Diff misclassification | Dual hash (AST + bytecode) to reduce false same detection |
| Rules layering chaos | Provide `--rules dry-run` visual diff of factor deltas before applying |
| SARIF field bloat | Use summary embedding only; full evidence under separate file pointer |
| Cost escalation (LLM) | Hard cap tokens; budget report in meta |
| Complexity creep | Feature flags: each subsystem behind `enable` config key |

---

## Timeline (Indicative 4–5 Weeks)

| Week | Deliverables |
|------|--------------|
| 1 | PluginManager + detector/enricher interface + basic tests |
| 2 | Diff engine + fingerprint store + incremental scan integration |
| 3 | Rule DSL loader + evaluator + SARIF exporter v1 |
| 4 | LLM triage integration + remediation knowledge base + explain enhancements |
| 5 | Hardening, performance profiling, docs, regression tests, adoption examples |

(Parallelization possible: one track handles diff + SARIF while another builds plugin + triage.)

---

## Documentation Additions

- docs/plugins.md (API, lifecycle, constraints, examples)
- docs/diff-mode.md
- docs/triage.md (prompt strategy, caching, cost)
- docs/rules-dsl.md (schema, examples, gotchas)
- docs/integration/github-code-scanning.md (workflow yaml snippet)
- Updated README quickstart with: “Incremental scanning in CI,” “Enable triage,” “Export SARIF.”

---

## Acceptance Criteria Summary

1. With all new toggles disabled, output matches Phase 4 (except meta additions).
2. Enabling diff mode demonstrably reduces run time on changed-only workload.
3. Plugins can add a synthetic detector whose finding flows through correlation & scoring.
4. SARIF passes official schema validation; GitHub code scanning example works.
5. Rules adjust scoring deterministically; disabling rules resets to original scoring.
6. Triage summaries available for selected findings with reproducible caching.
7. No fatal crash if any subsystem (plugin, triage, rules) fails—warnings only.
8. Deterministic IDs preserved across all new layers.

---

## Decision Points (Need Your Input Before Scaffold)

Please choose / clarify:
1. Include multi-chain sniff (basic bridging patterns) now or defer? (Recommend defer.)
2. Preferred LLM provider priority list (openai / anthropic / local-ggml fallback?).
3. Do we require plugin signature / integrity check in Phase 5 (hash manifest) or postpone?
4. Should SARIF embed adjusted severity or both original + adjusted? (Recommend both.)
5. Diff detection granularity: function-level only, or also variable-level rename tracking? (Recommend function-level for Phase 5.)
_____________________________________________________________________________________
# Phase 6 Proposal: “Cross‑Domain Intelligence, Continuous Assurance & Autonomous Hardening”

You now have:
- Phase 4: Correlation, path reasoning, optional symbolic, scoring, evidence
- Phase 5 (in progress): Plugins, diff/incremental scans, SARIF, LLM triage, rule DSL seed, remediation KB

Phase 6 should shift from “deep static + enriched reporting” to “holistic, cross-domain, continuously validating security platform” with:
1. Multi-chain & bridging context modeling
2. Runtime + historical on-chain intelligence fusion
3. Formal / invariant / fuzz synergy
4. Autonomous exploit hypothesis simulation
5. Stronger trust + provenance (attestation & plugin integrity)
6. Policy governance & continuous assurance loops

---

## Strategic Theme Tracks

| Code | Track | Core Value |
|------|-------|------------|
| MCX | Multi-chain & Cross-Domain Modeling | Unified view of assets & attack paths across chains/bridges |
| BRI | Bridging & Oracle Risk Correlation | Detect economic manipulation windows |
| FVF | Formal + Fuzz + Differential Hybrid | Higher assurance with prioritized budget usage |
| INV | Invariant DSL & Auto-Generation | Declarative trust boundary + state safety constraints |
| SIM | Exploit Scenario Simulation & Economic Feasibility | Practical risk ranking beyond structural severity |
| RTA | Runtime Telemetry & Drift Detection (opt-in) | Catch config / upgrade deltas altering risk posture |
| KGX | Knowledge Graph (Contracts / Roles / Assets / Data Flows) | Queryable security ontology; fuel correlation & triage |
| SEC | Supply Chain & Plugin Trust / Attestation | Reduce tampering / malicious plugin risk |
| GOV | Policy Governance & Compliance | Org-/repo-level baselines & enforcement |
| AI2 | Multi-Model Reasoning & Cross-Validator | Reduced hallucination + consensus scoring |
| RSK | Probabilistic Risk & Loss Modeling | Translate technical findings → monetary exposure bands |
| PERF | Horizontal Scaling & Parallel Execution Framework | Large codebases / many chains performance |
| UX2 | Developer Workflow Maturity | GitOps policies, PR inline invariant diff hints |

Recommended composite for Phase 6: MCX + BRI + INV + SIM + FVF (core) + SEC (minimal) + GOV (baseline) + KGX foundation + selective AI2 improvements. Defer full RTA (continuous runtime ingestion) or advanced probabilistic modeling if bandwidth constrained; can partially seed.

---

## Phase 6 High-Level Objectives

1. Multi-Chain Context Layer  
   - Ingest contract artifacts from multiple chains (EVM variants + L2).  
   - Normalize addresses with chain identifiers (e.g., chainId:address).  
   - Cross-chain asset path inference (ERC20 canonical → wrapped tokens → bridge escrows).  
   - Correlate vulnerabilities spanning chain boundaries (e.g., stale oracle feed on Chain A influencing liquidation logic on Chain B).

2. Bridge & Oracle Risk Correlator  
   - Pattern rules for: delayed finality windows, oracle update lag, price feed divergence thresholds.  
   - Temporal model (simple sliding window ingest of historical observations—either user-provided dumps or adapter).  
   - “Exploit timing window” estimation attached to finding.

3. Invariant DSL v1  
   - Declarative spec file (YAML or concise DSL) describing state safety & role constraints:  
     ```
     invariant balance_equivalence:
       scope: contract:Vault
       expr: totalShares * pricePerShare == totalAssets
       tolerance: 0.005
     ```  
   - Supports categories: arithmetic relations, role gating, monotonicity, non-negativity, conservation.  
   - Automatic candidate invariant generation from:  
     - Detected repeated expressions in code  
     - Path-sliced symbolic states  
     - Detected storage variable deltas (heuristics)  
   - Classification: user-declared vs auto-suggested (confidence score).  
   - Execution backends: symbolic quick-check, targeted fuzz harness, optional external formal tools (e.g., Certora, hevm) via plugin layer.

4. Hybrid Formal + Fuzz + Differential (FFusion)  
   - Smart scheduler: allocate fuzz budget preferentially to high-impact invariants or low-confidence correlation clusters.  
   - Differential mode: baseline vs modified commit; highlight invariant regressions even if detectors silent.  
   - Artifact caching: store PC hit maps + mutated input seeds keyed by (contract_hash, invariant_fingerprint).

5. Exploit Scenario Simulation (Economic Feasibility)  
   - Construct simplified attack execution graphs combining: path slices + invariant violation candidate + price/oracle manipulation cost.  
   - Compute economic viability metrics:  
     - required_capital_estimate  
     - expected_payoff_range  
     - breakeven_latency (blocks)  
   - Adjust risk scoring with “economic amplification factor” (bounded).  
   - Flag findings that are severe structurally but economically implausible (explicit annotation, not downgrade unless policy configured).

6. Knowledge Graph Foundation (KGX)  
   - Nodes: Contracts, Functions, StateVars, Roles, Tokens, Bridges, Oracles, Invariants.  
   - Edges: calls, reads, writes, guards, delegates, supplies_price_to, bridges_to, invariant_depends_on.  
   - Expose internal query API + optional `vulnhuntr kg query 'MATCH ...'` (Phase 6 simple pattern engine, not full Cypher).  
   - Feed correlation engine with KG patterns (e.g., “function modifies token that is bridged with ≥2 delegatecall hops”).

7. Supply Chain & Plugin Trust (SEC minimal)  
   - Plugin signature manifest (SHA256 hash + optional PGP signature).  
   - Warn if plugin hash not pinned in `plugins.lock`.  
   - Provide `vulnhuntr plugins attest` to generate lock file.  
   - Execution provenance: record plugin hash & signature status in meta.

8. Governance & Policy (GOV baseline)  
   - Policy file (org/repo-level):  
     ```
     policy:
       min_confidence_for_block: 0.75
       block_on: [CRITICAL, HIGH]
       require_invariants: ["balance_equivalence","ownership_guard"]
       forbid_plugin_hash_mismatch: true
     ```  
   - CI exit codes determined by policy evaluation result set.  
   - Policy evaluation report separate artifact.

9. Multi-Model Triage (AI2)  
   - Consensus mode: run two cheaper models + one higher-quality (if enabled).  
   - Divergence metric: semantic distance between summaries; if > threshold mark as “triage_disputed”.  
   - Cross-check variable names & invariants referenced; flag hallucinations.

10. Risk Modeling (RSK seed)  
    - Basic probability scoring: P(exploit) = f(reachability_confidence, economic_viability, invariant_violation_rate).  
    - Expected Loss (optional) = P(exploit) * asset_value (user-provided or heuristic).  
    - Provide a CSV export: `finding_id, severity, p_exploit, expected_loss_estimate`.

11. Performance & Scaling (PERF)  
    - Concurrency pool abstraction: detectors, fuzzers, symbolic tasks scheduled via weighted queue.  
    - Adaptive time-slicing: if total runtime > budget, degrade dimension order: (fuzz > symbolic > triage > simulation).  
    - Metrics on parallel efficiency (speedup ratio, stall reasons).

12. Advanced Explainability & Drilldown  
    - `explain --graph` emits DOT/Graphviz snippet for cluster + invariant dependency subgraph.  
    - Markdown risk narrative integrating: structural path + invariant + economic simulation + policy evaluation.

---

## Data Model Additions

Finding additions:
- multi_chain: { chains: [id...], cross_domain_paths: [{source_chain, target_chain, asset, hop_count}] }
- economic: { capital_required_estimate, payoff_upper_bound, payoff_lower_bound, feasibility: plausible|improbable|unknown }
- invariants: [ { name, status: proven|violated|inconclusive|suggested, method: symbolic|fuzz|formal, confidence } ]
- risk_model: { p_exploit, expected_loss_estimate, modeling_version }
- policy: { violations: [...], compliant: bool }

Meta additions:
- chains_processed
- bridge_patterns_matched
- invariant_stats: { declared, suggested, proven, violated }
- fuzz: { executions, unique_paths, seeds_reused }
- simulation_runs
- kg: { nodes, edges, build_time_ms }
- plugins_attested
- policy_file_hash
- risk_model_version
- consensus_triage: { enabled, disputed_count }
- economic_model_version

---

## Invariant DSL (Draft Syntax)

````markdown name=invariants.example.dsl
invariant total_supply_sane:
  scope: contract:Token
  expr: totalSupply >= circulatingSupply
  category: conservation
  severity_hint: HIGH

invariant shares_asset_equivalence:
  scope: contract:Vault
  expr: shares * pricePerShare ~= totalAssets
  tolerance: 0.003  # relative difference

invariant role_guard:
  scope: function:Vault::setFee
  expr: onlyOwner
  type: access

auto-generate:
  enable: true
  heuristics:
    - arithmetic_conservation
    - monotonic_non_decreasing: depositCount
````

Auto-suggest pipeline:
1. Extract candidate expressions (AST pattern match + repeated arithmetic forms).
2. Validate symbolic feasibility (no unsupported ops).
3. Score (frequency + variable criticality + path centrality).
4. Present as suggested invariants.

---

## Exploit Simulation Outline

Steps per candidate:
1. Select cluster or invariant violation candidate.
2. Build state transition skeleton from path slices.
3. If oracle / price manipulation involved: apply deviation bounds (user-provided or heuristics).
4. Estimate capital:
   - Collateral requirements (read storage initial state if available or user-supplied snapshot).
   - Gas cost approximation (per external call categories).
5. Compute payoff differential if invariant violation leads to asset withdrawal or mispricing.
6. Mark feasibility tiers:
   - Feasible: capital_required < payoff_upper_bound * 0.6 and steps <= threshold.
   - Improbable: capital_required > payoff_upper_bound * 1.5 or path breadth too high.
   - Unknown: insufficient data (lack of oracle context or missing invariant).

---

## Scoring Adjustments (Phase 6 Integration)

Add new factors (bounded contributions):
- chain_complexity_factor (0–0.4)
- cross_domain_attack_surface (0–0.5)
- invariant_violation_weight (0–0.6)
- economic_feasibility_factor (0–0.4) (positive if feasible, negative slight if improbable)
- consensus_dispute_penalty (0–0.3 penalty if triage disputed)

Ensure previous severity mapping remains reproducible; new factors only if feature flags enable.

---

## Policy Engine

Evaluation order:
1. Collect all violations (severity gating, missing required invariants, plugin attestation failures).
2. If any block condition triggered → exit code non-zero (distinct policy code).
3. Provide structured policy report: JSON + optional Markdown summary.

---

## CLI Enhancements

| Command | Purpose |
|---------|---------|
| vulnhuntr invariants generate | Produce suggested invariants file |
| vulnhuntr invariants test <file> | Validate DSL expressions |
| vulnhuntr simulate <finding-id> | Force exploitation simulation |
| vulnhuntr kg stats | Print knowledge graph metrics |
| vulnhuntr policy eval | Dry-run policy outcome |
| vulnhuntr risk export --csv risk.csv | Export risk model outputs |
| vulnhuntr attest plugins | Create/update plugins.lock |
| vulnhuntr explain <finding> --graph | Show DOT subgraph |

Flags:
- --multi-chain-config chains.yaml
- --invariants invariants.dsl
- --simulate
- --economic-model conservative|balanced|aggressive

---

## Sample multi-chain config (chains.yaml)

````markdown name=chains.yaml
chains:
  - id: 1
    name: ethereum
    role: primary
  - id: 42161
    name: arbitrum
    role: l2
  - id: 137
    name: polygon
    role: satellite
bridges:
  - name: l1-l2-gateway
    type: canonical
    contracts:
      - chain: 1
        address: 0xabc...
      - chain: 42161
        address: 0xdef...
oracles:
  - name: eth-usd-chainlink
    feeds:
      - chain: 1
        address: 0xfeed...
    heartbeat_seconds: 300
````
____________________________________________________________________________
Here’s a clear “what’s next” roadmap split into Immediate, Pre‑Merge, Hardening, and Forward (Phase 7 seeding) so you can keep momentum without scope creep.

## 1. Immediate (Next 1–2 Working Sessions)

1. Phase 5 PR Triage
   - Verify: all new subsystems (plugins, diff, rules, triage, SARIF) are disabled by default and produce identical core finding list vs Phase 4 on a known corpus.
   - Add a golden baseline fixture (e.g., tests/fixtures/baseline/phase4_report.json) and an assertion test that Phase 5 (features off) diff is empty except meta fields.

2. Phase 6 Scaffold Sanity Pass
   - Confirm directory/module names you truly want to “freeze” (renames later cause churn): multi_chain, invariants, simulation, kg, policy, attestation, risk.
   - Decide on schema_version embedding strategy (0.6.0 already planned). If you want invariant hash stability independent of schema evolution, lock now.

3. Lock Exit Codes & Policy Keys
   - Document final exit codes in docs/policy.md early; CI consumers hate churn. Add a constants module (e.g., policy/exit_codes.py).

4. Approve / Adjust Risk Coefficients
   - If you think coefficients may need a scaling pass, add config “normalize = true” now to allow dynamic normalization later without breaking expectations.

5. Generate Example Artifacts
   - Provide a sample chains.yaml, invariants.yml, policy.yml, valuation.json inside examples/ to guide early adopters.

## 2. Pre‑Merge Checklist (Before Merging Phase 5, Then Phase 6)

Phase 5:
- Tests: plugin isolation, diff classification, SARIF schema validation, rules scoring determinism, triage caching.
- Docs pass: Ensure each new feature has a “Disabled by default” statement at top.
- Developer ergonomics: “quickstart incremental scan” snippet in README.
- Confirm no vendored large dependencies accidentally added (keep footprint lean).

Phase 6 (scaffold stage):
- Add placeholder tests that simply assert feature flags parse & no-op cleanly.
- Add TODO markers for every not-yet-implemented scoring factor (grep-able tag e.g., TODO:PH6).
- Ensure schema translator gracefully imports a Phase 5 report (simulate with a fixture).

## 3. Hardening & Quality Gates (Early Implementation Phase 6)

1. Determinism Harness
   - Introduce a deterministic test run seed (env: VULNHUNTR_SEED) used by any stochastic heuristic (auto-suggest ranking).
   - Run CI twice (matrix: run=1, run=2) and compare reports (excluding timestamps) to catch hidden nondeterminism.

2. Performance Envelope Tests
   - Create a synthetic “large” project (e.g., duplicate contract set 30–50x) to measure baseline overhead when Phase 6 features are OFF so regressions are obvious.

3. Hash Provenance Strategy
   - Add meta.hashes: { report_body_sha256, config_sha256, chains_config_sha256? } to aid reproducibility claims.

4. Plugin Lock Integrity
   - Provide a test that intentionally modifies a plugin file after lock generation and asserts a mismatch warning appears (policy fail when configured).

5. Risk Model Guardrails
   - Enforce: 0 ≤ p_exploit ≤ 0.99 with explicit clipping & log if clipping occurs (signals coefficient explosion).

6. Economic Simulation Safety
   - Add sanity constraints (e.g., if payoff_upper_bound < 0 -> set unknown; if capital_required_estimate extremely high relative to typical supply numbers → mark improbable with assumption).

## 4. Developer Workflow Enhancements (Quick Wins)

- Add a unified command: vulnhuntr doctor
  - Prints: feature flags state, cache stats, plugin attestation status, ruleset hash, schema_version.
- Provide a minimal GitHub Actions workflow example for:
  - Phase 5 only (baseline)
  - Phase 6 experimental (multi-chain + invariants + policy gating)

## 5. Metrics & Observability Early Hooks

Implement lightweight counters first (no heavy tracing):
- Invariants suggestion timing (ms)
- Scheduler task queue depth max
- Economic simulation runs vs skipped
- Consensus triage divergence ratio (#disputed / #triaged)

Expose via: vulnhuntr stats (prints JSON snapshot from last run’s meta).

## 6. Risk & Regression Early Detection

- Add regression sentinel tests: If a previously HIGH severity canonical known vulnerability example shifts severity or disappears with all new features OFF, fail CI.
- Maintain a small curated canonical-vulns/ set (e.g., reentrancy, unchecked call, price manipulation skeleton) as “sentinel corpus.”

## 7. Documentation Sequencing

Write docs in this order (reduces reviewer uncertainty):
1. policy.md
2. invariants.md
3. multi-chain.md
4. exploit-simulation.md (clearly label “heuristic – not financial advice”)
5. risk-model.md (math + assumptions)
6. knowledge-graph.md
7. attestation.md

Each doc should start with:
Status: Experimental (Phase 6). Disabled by default. Backward compatibility not guaranteed yet.

## 8. Phase 7 
If you want to accelerate Phase 7 later without commitment:
- Add empty directories or stub interfaces for:
  - runtime/ (for telemetry ingestion)
  - probabilistic/ (loss distribution modeling)
  - feeders/ (external price/oracle connectors)
- Mark with README stubs stating “Reserved for Phase 7”.

High Priority 
- Merge Phase 5 after baseline parity tests green.
- Finalize policy exit code constants.
- Add translator for 0.5.x → 0.6.0 reports.

Medium 
- Implement invariant parser & validation (declared invariants only).
- Implement knowledge graph skeleton builder (nodes: Contract/Function/StateVar; edges: calls, reads, writes).
- Implement plugin attestation hash comparison logic.

- Auto-suggest invariants heuristic pass.
- Consensus triage divergence scoring (start lexical diff, add embedding later).
- Economic simulation heuristic (capital & payoff estimators).

## 10. Open Clarifications (Worth Answering Soon)

If you can clarify these now, it reduces rework:
- Preferred rounding precision for p_exploit (suggest 4 decimal places).
- Should economic assumptions be exported in SARIF (properties.economic.assumptions)? (Likely yes for transparency.)
- Policy fail on hash mismatch: should it also remove plugin-contributed findings from final output or just block? (Recommend: do not mutate; only block & mark trust_issue.)

## 11. Minimal “Next Step” Command Sequence (Example)

```bash
# 1. Run baseline (features off)
vulnhuntr scan --profile > reports/baseline_phase5.json

# 2. Generate plugins lock after approving existing plugins
vulnhuntr attest plugins

# 3. Try enabling invariants (declared only)
vulnhuntr scan --config config-with-invariants.toml --invariants invariants.yml

# 4. 
vulnhuntr policy eval --policy policy.yml --report reports/latest.json

# 5. Stats summary
vulnhuntr stats
```

## 12. Phase 7 

- External oracle data ingestion + temporal anomaly detection
- Autonomous remediation PR suggestions (structured code patches)
- On-chain runtime diffs & drift watch (post-deployment monitors)
- Advanced probabilistic loss distributions (Monte Carlo)
- WASI or container sandbox for untrusted plugins
---

## Performance & Budget Strategy

Priority tiers if time budget constrained:
1. Core detection + correlation
2. Invariants (declared) quick-check symbolic
3. Diff + reuse caches
4. Economic simulation (top K critical)
5. Suggested invariants generation
6. Fuzz & extended formal
7. Multi-model triage consensus

Dynamic scheduler demotes lower tiers as elapsed_time / total_budget rises.

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Over-complexity in one release | Feature flags & progressive enablement docs |
| False precision in economic modeling | Attach confidence & highlight assumptions; no auto-downgrade solely on “improbable” |
| Invariant noise explosion | Cap suggestions, rank by composite priority, require explicit user acceptance |
| Plugin signature spoofing (basic PGP) | Document advisory: not tamper-proof; plan stronger attestation Phase 7 |
| Cross-chain partial data | Allow stub placeholders with explicit “partial-context” annotation |
| Scheduler starvation | Minimum guaranteed slice for each enabled tier |
| LLM divergence complexity | Threshold gating; fallback to single-model if persistent disagreement |

---

## Documentation Additions

- docs/multi-chain.md (architecture, config, limitations)
- docs/invariants.md (DSL, generation heuristics)
- docs/exploit-simulation.md (models & equations)
- docs/policy.md (syntax, exit codes)
- docs/knowledge-graph.md (schema & query examples)
- docs/attestation.md (plugins.lock usage)
- docs/risk-model.md (probability derivation, disclaimers)
- Updated README advanced section

---

## Proposed Timeline (6–7 Weeks)

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Multi-chain foundation & KGX skeleton | chain config parser, KG builder, nodes/edges minimal |
| 2 | Invariant DSL + declared invariant engine | parser, symbolic quick-check, evidence attach |
| 3 | Auto-suggest invariants + hybrid scheduler seed | generation heuristics, ranking, scheduling core |
| 4 | Exploit simulation engine (MVP) + economic factors | capital/payoff estimation, risk adjustments |
| 5 | Bridge/oracle correlation + policy engine + plugin attestation | patterns, policy parse/eval, lock file |
| 6 | Risk model seed + multi-model triage consensus + SARIF augmentation | p_exploit calc, consensus divergence marking |
| 7 | Hardening, docs, performance tuning, acceptance suite, example repos |

(Parallelization possible: invariants + simulation vs multi-chain + policy.)

---

## Acceptance Criteria (Draft)

1. All new features disabled → parity with Phase 5 outputs (except new meta fields).
2. Invariants: declared invariants produce proven/violated/inconclusive statuses with reproducible outcomes for fixed seeds.
3. Auto-suggest invariants produce ≤ configured max suggestions with ranking metadata.
4. Exploit simulation attaches economic summary to ≥80% of applicable high-severity cross-domain findings (or marks unknown gracefully).
5. Multi-chain correlation demonstrates at least one sample bridging pattern cluster in test corpus.
6. Policy engine enforces severity gating & required invariants; correct exit codes.
7. Plugin attestation warns on hash mismatch; lock file reproducibly generated.
8. Knowledge graph built & exposes node/edge counts; query interface returns deterministic results.
9. Risk model outputs p_exploit & expected_loss_estimate with documented assumptions.
10. Consensus triage marks disputes & does not regress baseline triage when disabled.
11. All new IDs/hash outputs deterministic given identical inputs/config.
## Decision Points 
 the following to finalize scaffold:

1. Economic Modeling Depth: Basic heuristic (default) vs include optional external price feed ingestion adapter this phase?
2. Formal Tool Integration: Integrate one external (e.g., hevm / Certora hook) now or leave pluggable stubs only?
3. Invariant DSL Syntax: YAML + expr strings (recommended) or custom concise DSL (slightly higher parsing effort)?
4. Multi-Model Triaging: Start with 2-model consensus or full 3-model (cost heavier)?
5. Attestation Mechanism: PGP signature support now or just hash lock file (faster)?
6. Risk Model: Include expected_loss only if user supplies asset valuation map, else omit or mark “unknown”?  
7. Knowledge Graph Query: Limited built-in filter language or lightweight embedded GraphQL schema?
8. Fuzz Engine: Integrate existing external fuzz harness plugin interface now or implement internal minimal harness?

 e.g.:
1. Basic heuristic only
2. Stub only
3. YAML
4. 2-model
5. Hash only
6. Conditional
7. Filter language
8. Plugin interface first






Awesome—momentum locked in. Here’s a focused roadmap for the next push so we convert the new architecture into a fully operational engine.

Phase 1b Follow‑Through (Right Now)
1. Review PR #10  
   - Validate detector class names match naming convention (they do: *Detector suffix optional*).  
   - Confirm no namespace collisions.  
   - Decide whether to keep mock parsing in CLI until real Slither integration (recommended: merge now, integrate parser in next PR).  
2. Merge Strategy  
   - Merge Phase 1 (scaffolding PR) first if still open, then Phase 1b.  
   - After merging, cut a tag: v0.1.0-alpha.

Immediate Next Phase (Phase 2: Static Analysis Integration)
Goal: Replace mock contract objects with real parsed metadata.
Tasks:
- Add dependency on Slither (and optionally Mythril later behind an extra).
- Implement a parser module: slither_adapter.py that:
  - Runs Slither programmatically.
  - Extracts: contract names, vars, function name, source, file path, line start.
- Inject Slither artifacts into ScanContext.tool_artifacts for detectors that may evolve to need CFG / SSA.
- Add a --slither-json option to dump raw Slither output for debugging.

Deliverables for Phase 2 PR:
- src/vulnhuntr/parsing/slither_adapter.py
- Modified cli.scan to call the adapter.
- Detector minor adjustments (if any) to rely on richer metadata.
- Basic test corpus: minimal solidity samples in tests/fixtures/.

Phase 3: Config + Extensibility
Goal: User‑tunable scanning.
Tasks:
- Add pyproject optional dependency groups: [detectors-extra], [llm].
- New config loader (toml): vulnhuntr.toml with sections:
  [run]
  enable_llm = false
  [detectors]
  enable = ["*"]    # or explicit list
  disable = ["gas-sensitive-branching"]
  [llm]
  provider = "openai"
  model = "gpt-4o-mini"
- Implement config precedence: CLI flag > env var > toml default.
- Add --list-detectors command.

Phase 4: Reporting & CI Output
Goal: Usable outputs for pipelines & triage.
Outputs:
- JSON (already there, refine schema version).
- Markdown report (group by severity, include correlation clusters).
- SARIF emitter for GitHub code scanning integration.
- Optional HTML (static single-page with collapsible findings).

Phase 5: LLM Enhancements (Optional if you enable now)
Goal: Make LLM layer production-safe.
Tasks:
- Abstraction: LLMClient protocol with adapters (OpenAI, Anthropic, local).
- Deterministic/offline mode: if no key set, skip gracefully.
- Rate limiting + caching (hash prompt → response).
- Guardrails: JSON mode for remediation & invariants (retry on parse error).

Phase 6: Fuzz & PoC Deepening
Goal: Turn suggestions into runnable artifacts.
Tasks:
- Emit Foundry invariant test scaffolds for each invariant_suggestions entry.
- Add a command: vulnhuntr fuzz --emit-foundry ./out/foundry
- Optionally integrate Echidna property format.

Phase 7: Advanced Correlation
Goal: Reduce noise.
Ideas:
- Graph-based clustering: similarity over (tags ∪ token shingles of description).
- Confidence recalibration using Bayesian update if multiple detectors align.
- Duplicate suppression across commits (persist baseline file with IDs).

Phase 8: Performance & Caching
Goal: Speed for large codebases.
Tasks:
- Cache Slither parse results keyed by (file hash set).
- Parallel detector execution (ThreadPool for I/O-light, ProcessPool if CPU-heavy later).
- Warm-up registry only once per run.
________________________________________________________________________________________
# vulnhuntr2 – Strategic Roadmap Summary  
Status Date: 2025-09-16  
Owner: @avaloki108  

This document captures:  
1. Road Traveled (Phases completed / in-progress with delivered capabilities)  
2. Current Work-in-Flight (Phase 5 & Phase 6 scaffolds)  
3. Road Left (Remaining implementation items per phase + future phases)  
4. Cross‑phase Risks & Mitigations  
5. Metrics & Quality Baselines  
6. Decision Log & Outstanding Decisions  
7. Forward Vision (Phase 7+ thematic expansion)  

---

## 1. Road Traveled (Foundations → Intelligence)

| Phase | Status | Core Theme | Key Delivered / Scaffolded Capabilities | Backward Compatibility |
|-------|--------|------------|------------------------------------------|------------------------|
| Phase 1 | Complete | Core Static Skeleton | Basic scanning pipeline, parsing, primitive finding emission | Stable |
| Phase 2 | Complete | Enrichment & Normalization | Finding normalization, early scoring seeds, structured output | Stable |
| Phase 3 | Complete | Correlation Foundations | Grouping, clustering logic, early evidence aggregation | Stable |
| Phase 4 | Complete | Advanced Correlation & Scoring | Path reasoning, (optional) symbolic exploration, confidence factors, deterministic scoring; Explain command v1 | Golden baseline for parity |
| Phase 5 | WIP (PR #14) | Extensibility & Ecosystem Output | Plugin runtime (detectors/enrichers/postprocessors), diff/incremental scanning, SARIF export, LLM triage (gated), Rule/Pattern DSL seed, remediation KB, schema translator 0.5.x | Designed to produce Phase 4-equivalent core findings when new features disabled |
| Phase 6 | Scaffold (PR #15) | Cross-Domain Intelligence & Assurance | Multi-chain modeling, bridge/oracle correlation, Invariant DSL + auto-suggest (planned), exploit economic simulation (heuristic), risk probability model (seed), policy engine, plugin attestation, knowledge graph, two-model triage consensus | All feature-flagged off by default (schema version → 0.6.0) |

---

## 2. Phase-by-Phase Detail

### Phase 4 (Baseline Intelligence Stabilized)
Delivered:
- Evidence-rich correlation (path fingerprints, cluster representation)
- Scoring model (severity adjustment + confidence factors)
- Optional symbolic reasoning (gated)
- Deterministic report hashing
- Explain command (structural + reasoning summary)

KPIs (Targets vs Achieved – illustrative):
- Determinism Re-runs: 100% parity across 5 seeded runs ✔
- Average scan time (baseline corpus): Within target threshold ✔
- False positive review set: Baseline established (for longitudinal improvement)

### Phase 5 (Extensibility & Incremental Precision) – PR #14
Delivered (Scaffold / Partial Implementation):
- Plugin framework (manifest, load ordering, fault isolation)
- Diff / incremental scanning strategy (--diff-base)
- SARIF exporter with embedded adjusted severity metadata
- Rule DSL (YAML) seed: scoring adjustments, tags, escalation, conflicts
- LLM Triage layer (gated, caching mechanism)
- Remediation knowledge base stub
- Extended CLI (plugins, rules, triage simulate, explain enhancements)
- Schema version 0.5.0 + translator foundation

Remaining Implementation (Phase 5):
- Full test coverage (diff regression detection, rule conflict warnings)
- Performance guard rails (plugin time & memory soft budgets active assertions)
- SARIF validation harness against GitHub Code Scanning action
- Triage deterministic fallback & redaction heuristics finalization
- Rules hot-reload command runtime (watch-rules)
- Remediation KB integration into explain & triage enrichment
- Documentation: plugins.md, diff.md, rules.md, triage.md, sarif.md

Exit Criteria (Phase 5):
- Parity test: Phase 4 vs Phase 5 (all features disabled) → identical finding set
- SARIF accepted by an example GitHub Actions workflow
- Plugin-induced synthetic finding persists end-to-end
- Rule toggling causes reversible scoring adjustments

### Phase 6 (Cross-Domain & Assurance Layer) – PR #15
Delivered (Scaffold Commit Scope):
- Directory & module scaffolds (multi_chain/, invariants/, simulation/, kg/, policy/, attestation/, risk/)
- Config expansions (multi_chain, invariants, simulation, risk_model, policy, attestation, kg)
- Data model specification (multi-chain fields, invariants array, economic & risk_model sections)
- Policy engine design & exit code mapping (proposed)
- Invariant hashing strategy (design note)
- Risk model formula & coefficients (default set)
- Consensus triage (two-model) conceptual pipeline

Planned Implementation Tasks:
1. Multi-chain parser + address normalization (chainId:address)
2. Knowledge graph builder MVP (nodes/edges, metrics, filter query engine)
3. Invariant DSL parser & validator (declared invariants first)
4. Auto-suggest invariants heuristic (ranking & confidence)
5. Symbolic quick-check execution (timeouts, status states)
6. Fuzz plugin interface stub (no internal harness)
7. Economic simulation heuristic module (capital estimate, payoff range, feasibility classification)
8. Policy evaluator & artifact emission
9. Attestation (plugins.lock create, verify, policy integration)
10. Consensus triage divergence metric (lexical diff first; embeddings later)
11. Risk model calculator (coefficient weighting + sigmoid + bounding)
12. Schema translator: ingest 0.5.x → 0.6.0 for diff/regression mode consistency
13. CLI expansions (invariants generate/test/list, kg query, simulate, risk export, policy eval, attest)
14. Explain --graph DOT subgraph generator
15. Documentation set (multi-chain, invariants, auto-suggest, exploit-simulation, risk-model, policy, attestation, knowledge-graph)

Acceptance Criteria Re-stated (Key):
- All features off → Phase 5 parity
- Invariants produce reproducible statuses
- Auto-suggest limited by max_suggested & deterministic ordering under fixed seed
- Economic feasibility never silently suppresses severity (annotation-only unless policy enables gating)
- Policy gating exit codes stable & documented
- Attestation mismatch flagged clearly without altering raw findings

---

## 3. Road Left (Execution Backlog Snapshot)

### Phase 5 Outstanding Backlog (High → Low Priority)
1. Baseline Parity Regression Test (Phase4 vs Phase5)
2. Diff Regression Detector (removed CRITICAL/HIGH unchanged function)
3. Rule Engine conflict detection & warnings
4. SARIF integration test pipeline (validate JSON schema + GitHub acceptance)
5. Plugin isolation tests (fault injection)
6. Triage caching determinism test harness
7. Remediation KB integration & fallback logic
8. Performance measurement harness (plugins off vs on no-op)
9. Documentation finalization & examples

### Phase 6 Core Implementation Sequence (Recommended Order)
1. Translator 0.5.x → 0.6.0 + invariants declared parser
2. Knowledge graph minimal (Contract/Function/StateVar + calls/reads/writes)
3. Multi-chain config ingestion & node augmentation
4. Invariant execution symbolic quick-check (proven/violated/inconclusive)
5. Auto-suggest invariants (heuristics + ranking)
6. Economic simulation heuristics (attach feasibility classification)
7. Risk model implementation & CSV export
8. Policy engine + exit code tests
9. Plugin attestation (lock generation, mismatch handling)
10. Consensus triage divergence (lexical diff)
11. DOT graph explain integration
12. Extended docs + example artifacts
13. Performance & determinism CI matrices

### Seeding for Phase 7 (Optional Now)
- runtime/ telemetry ingestion stubs
- feeders/ (oracle/price ingestion interface)
- probabilistic/ (Monte Carlo risk model placeholder)

---

## 4. Risk Register & Mitigations

| Risk | Phase Affected | Impact | Probability | Mitigation |
|------|----------------|--------|-------------|------------|
| Feature creep in Phase 6 reduces quality | 6 | High | Medium | Strict feature flag gating + task cut lines |
| Non-deterministic auto-suggest ordering | 6 | Medium | Medium | Global seed + stable sort (confidence, name) |
| Economic heuristic misinterpretation as precise | 6 | Medium | High | Clear disclaimer in docs & report assumptions array |
| Performance regression (multi-chain + invariants) | 6 | High | Medium | Early synthetic large-corpus benchmark & budget scheduler |
| Attestation false sense of security (hash only) | 6 | Medium | High | Docs disclaim “not cryptographic provenance” |
| Policy exit code churn disrupts CI | 5/6 | Medium | Low | Freeze codes now; constants file + doc reference |
| Consensus triage overhead vs value | 6 | Low | Medium | Provide metrics (divergence ratio) & easy disable toggle |
| Invariant explosion (too many suggestions) | 6 | Medium | Medium | Cap max_suggested + ranking threshold |

---

## 5. Metrics & Quality Baselines (Targets)

| Metric | Baseline / Target | Phase Applicability |
|--------|-------------------|---------------------|
| Scan determinism (hash-equal runs) | 100% excluding timestamps | 4–6 |
| Incremental scan runtime reduction (10% diff) | ≥55% | 5 |
| Plugin overhead (no external) | <50ms | 5 |
| SARIF generation (<500 findings) | <150ms | 5 |
| Invariant symbolic timeout | ≤6s per batch | 6 |
| Auto-suggest acceptance ratio | <25% suggestions kept (signal > noise) | 6 |
| Economic simulation per target | <350ms heuristic path | 6 |
| Knowledge graph build overhead | <12% total runtime when enabled | 6 |
| Policy evaluation overhead | <40ms | 6 |
| p_exploit numeric stability (re-runs) | Std dev ≈ 0 (deterministic) | 6 |
| Consensus triage divergence rate | Measured & logged (no target first iteration) | 6 |

---

## 6. Decision Log & Outstanding Decisions

| Decision | Status | Notes |
|----------|--------|-------|
| Phase 5 all new subsystems disabled by default | Decided | Ensures backward compatibility |
| Triaging provider (single-model base) | Decided | OpenAI initial; abstraction prepared |
| Rule DSL YAML seed | Decided | Deterministic name sort |
| Phase 6 economic modeling heuristic only | Decided | External feeds Phase 7 candidate |
| Invariant DSL: YAML w/ expr strings | Decided | Leaves door open for richer DSL later |
| Multi-model triage: 2-model consensus | Decided | Cost control |
| Attestation: hash-only | Decided | PGP Phase 7 candidate |
| Risk model expected_loss conditional | Decided | Output 'unknown' if valuations absent |

Outstanding (Need Resolution):
1. p_exploit precision (suggest 4 decimal places).  
2. Include economic assumptions in SARIF export? (Recommended: yes under properties.vulnhuntr.economic.assumptions).  
3. Plugin hash mismatch behavior: block only vs also remove plugin-originated findings. (Recommended: block with policy exit, DO NOT mutate findings for audit traceability).  

---

## 7. Forward Vision (Phase 7+ Themes)

| Phase 7 Candidate | Description | Dependencies |
|-------------------|-------------|--------------|
| Runtime Telemetry Integration | Post-deploy event / state drift ingestion | Knowledge graph stable |
| External Oracle / Price Feeders | Real-time / historical data ingestion for economic risk | Feeders interface stubs |
| Advanced Formal Integration | hevm / Certora / SMT pipeline | Invariant DSL maturity |
| Autonomous Patch Suggestions | Structured remediation PR diffs | Stable finding classification + rule actions |
| Monte Carlo Loss Modeling | Distributional expected loss & VaR estimates | Valuation map + risk model seed |
| Sandbox Hardening (WASI/Containers) | Strong plugin isolation | Plugin framework stable |
| Multi-provider triage consensus (3+ models) | Reduce hallucination, increase confidence | 2-model consensus base |
| Supply Chain Provenance (Signatures) | Plugin signing + policy enforcement | Attestation hash baseline |
| Multi-tenant Org Governance | Org-level policy inheritance | Policy engine baseline |
| Runtime-to-Static Feedback Loop | Dynamic traces flag new invariants or vulnerabilities | Invariants engine baseline |

---

## 8. Recommended Immediate Next Actions

1. Resolve outstanding decisions (precision, SARIF economic assumptions, plugin mismatch behavior).  
2. Finalize and merge Phase 5 after parity & core test suite is green.  
3. Implement Phase 6 translator + invariant declared parser first (unblocks many dependent tasks).  
4. Add baseline determinism CI job (two-run diff).  
5. Introduce example artifacts (chains.yaml, invariants.yml, policy.yml, valuation.json).  
6. Begin knowledge graph minimal builder (foundation for multi-chain + simulation).  

---

## 9. Example Artifacts (Draft Skeletons)

````markdown name=examples/invariants.yml
invariants:
  - name: shares_asset_equivalence
    scope: contract:Vault
    expr: shares * pricePerShare ~= totalAssets
    tolerance: 0.003
    category: conservation
    severity_hint: HIGH
  - name: role_only_owner_setFee
    scope: function:Vault::setFee
    expr: onlyOwner
    category: access
````

````markdown name=examples/policy.yml
policy:
  block_on_severity: [CRITICAL, HIGH]
  min_confidence_for_block: 0.75
  required_invariants: ["shares_asset_equivalence"]
  fail_on_plugin_hash_mismatch: true
  economic_feasibility_gate: false
````

````markdown name=examples/chains.yaml
chains:
  - id: 1
    name: ethereum
    role: primary
  - id: 42161
    name: arbitrum
    role: l2
bridges:
  - name: l1-l2-gateway
    type: canonical
    contracts:
      - chain: 1
        address: 0xabc...
      - chain: 42161
        address: 0xdef...
oracles:
  - name: eth-usd-chainlink
    heartbeat_seconds: 300
    feeds:
      - chain: 1
        address: 0xfeed...
````

````markdown name=examples/valuation.json
{
  "tokens": {
    "WETH:1": 2680.45,
    "USDC:1": 1.00
  }
}
````

---

## 10. TL;DR Snapshot

- Phase 4: Stable baseline – correlation & scoring done.  
- Phase 5: Extensibility & ecosystem integration in PR – needs parity + validation wrap-up.  
- Phase 6: Intelligence & assurance scaffolding landed – implement invariants → KG → simulation → risk/policy.  
- Future: Runtime, external data, advanced formal & remediation automation (Phase 7+).  

---
Of course! I'm ready to help you bring `vulnhuntr2` to the finish line. This is an ambitious and well-structured project, and I'm excited to be a part of it.

Based on the detailed roadmap, I've broken down the remaining work into four major parts. This will allow us to tackle development in a structured and incremental way.

### The Plan to Complete `vulnhuntr2`

Here’s the proposed breakdown:

*   **Part 1: Solidify the Foundation (Finalize Phase 5)**
    *   **Goal:** Get the extensibility and ecosystem features (PR #14) production-ready.
    *   **What this involves:** We'll focus on the "Phase 5 Outstanding Backlog," which includes writing the critical tests (parity regression, diff regression), implementing performance guards, finalizing SARIF validation, and writing the documentation. This ensures the new plugin architecture is stable and reliable before we build on top of it.

*   **Part 2: Build the Intelligence Core (Phase 6 - Part A)**
    *   **Goal:** Implement the foundational components for cross-domain intelligence.
    *   **What this involves:** Following the recommended sequence, we'll start with the most critical pieces of Phase 6:
        1.  **Invariant Analysis Engine:** Implement the Invariant DSL parser, the symbolic quick-checker, and the auto-suggest heuristics.
        2.  **Knowledge Graph & Multi-Chain Support:** Build the minimal viable Knowledge Graph and integrate the multi-chain configuration and address normalization.

*   **Part 3: Layer on Advanced Analysis & Assurance (Phase 6 - Part B)**
    *   **Goal:** Implement the sophisticated risk, economic, and policy features.
    *   **What this involves:** With the core from Part 2 in place, we'll build:
        1.  **Economic & Risk Models:** Implement the economic simulation heuristics and the risk probability calculator.
        2.  **Policy & Attestation:** Build the policy engine and the plugin attestation mechanism for creating and verifying lockfiles.

*   **Part 4: Documentation, CI & Examples (Ongoing)**
    *   **Goal:** Ensure the project is maintainable, well-documented, and easy to use.
    *   **What this involves:** This is a continuous effort throughout all parts. We will create the example artifacts (`invariants.yml`, `policy.yml`, etc.), add the new CI jobs (like the determinism check), and write comprehensive documentation for every feature we ship.


