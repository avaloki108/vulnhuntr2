# VulnHuntr2 Smart Scan - Enhanced Ollama-Powered Analysis

## Overview

VulnHuntr2 Smart Scan is an enhanced vulnerability analysis system that uses local Ollama models to perform intelligent, holistic smart contract analysis. Unlike traditional tools that analyze contracts in isolation, Smart Scan understands how contracts work together to find complex logic errors and novel attack vectors.

## Key Features

### 🧠 Holistic Contract Analysis
- **Contract Relationship Mapping**: Automatically discovers dependencies, inheritance, and interaction patterns
- **Cross-Contract Logic Analysis**: Identifies vulnerabilities that span multiple contracts
- **Economic Impact Assessment**: Evaluates real-world exploitability and profit potential
- **Novel Attack Vector Discovery**: Finds creative attack patterns that combine multiple vulnerabilities

### 🏠 Local & Private
- **Ollama Integration**: Uses local models - no data leaves your machine
- **No API Keys Required**: Works entirely offline once models are downloaded
- **Privacy First**: Your smart contracts remain completely private

### 🎯 Intelligence-Driven
- **Foundation Model Reasoning**: Leverages large language models trained on code
- **Context-Aware Analysis**: Understands business logic and protocol mechanics
- **Attack Pattern Recognition**: Identifies sophisticated attack vectors

## Quick Start

### 1. Install Ollama
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve
```

### 2. Pull Recommended Model
```bash
# For best results (requires ~20GB RAM)
ollama pull qwen2.5-coder:32b

# For lighter systems (requires ~8GB RAM)
ollama pull codegemma:7b
```

### 3. Install VulnHuntr2 with Smart Scan Support
```bash
# Install with Ollama support
pip install -e .[smart]

# Or install full feature set
pip install -e .[full]
```

### 4. Run Smart Scan
```bash
# Scan a project directory
vulnhuntr smart-scan /path/to/contracts/

# Scan with custom model
vulnhuntr smart-scan /path/to/contracts/ --model codegemma:7b

# Save results to JSON
vulnhuntr smart-scan /path/to/contracts/ --output results.json

# Use custom configuration
vulnhuntr smart-scan /path/to/contracts/ --config vulnhuntr_smart.toml
```

## Configuration

### Sample Configuration (`vulnhuntr_smart.toml`)
```toml
[ollama]
enabled = true
model = "qwen2.5-coder:32b"
base_url = "http://localhost:11434"
temperature = 0.1
max_tokens = 4096

[cross_contract]
enabled = true
max_contracts_per_analysis = 10
detect_proxy_patterns = true

[analysis]
enable_correlation = true
enable_poc_generation = true
enable_scoring = true
```

## Recommended Models

### For Maximum Capability
- **qwen2.5-coder:32b** (Recommended) - Excellent code understanding and security analysis
- **codellama:34b** - Strong code analysis capabilities
- **deepseek-coder:33b** - Good balance of performance and resource usage

### For Resource-Constrained Systems
- **starcoder2:15b** - Lighter weight, still effective
- **codegemma:7b** - Minimal resource requirements

### Model Selection Guide
| Model | RAM Required | Best For |
|-------|-------------|----------|
| qwen2.5-coder:32b | ~20GB | Maximum analysis capability |
| codellama:34b | ~20GB | Strong vulnerability detection |
| deepseek-coder:33b | ~20GB | Balanced performance |
| starcoder2:15b | ~10GB | Good compromise |
| codegemma:7b | ~8GB | Resource-constrained environments |

## Example Output

```
🧠 VulnHuntr2 Smart Scan - Powered by Ollama
Model: qwen2.5-coder:32b | URL: http://localhost:11434

✅ Ollama connected: qwen2.5-coder:32b
Found 3 contract files

🔍 Starting enhanced vulnerability scan...
Building contract relationship graph...
Built contract graph with 3 contracts
Performing standard vulnerability scanning...
Performing cross-contract vulnerability analysis...

✅ Scan complete! Found 8 vulnerabilities
🔗 Cross-contract analysis found 2 complex vulnerabilities
📊 Ecosystem analysis: 3 contracts analyzed

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Detector            ┃ Severity ┃ Title                                             ┃ Contract              ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ reentrancy_detector │ HIGH     │ Reentrancy vulnerability in swap function        │ DEX                   │
│ access_control      │ HIGH     │ Missing access control on setReserves            │ DEX                   │
│ cross_contract      │ CRITICAL │ Flash loan governance attack vector              │ Governance,Token      │
│ price_manipulation  │ MEDIUM   │ AMM price manipulation vulnerability             │ DEX                   │
└─────────────────────┴──────────┴───────────────────────────────────────────────┴───────────────────────┘
```

## Advanced Usage

### Custom Analysis Focus
```bash
# Focus on specific contract types
vulnhuntr smart-scan contracts/ --model qwen2.5-coder:32b --no-cross-contract

# Enable detailed PoC generation
vulnhuntr smart-scan contracts/ --config vulnhuntr_smart.toml
```

### Programmatic Usage
```python
from vulnhuntr.core.enhanced_orchestrator import EnhancedVulnHuntrOrchestrator
from vulnhuntr.config.settings import Settings, OllamaConfig, CrossContractConfig
from pathlib import Path

# Configure enhanced analysis
settings = Settings()
settings.ollama = OllamaConfig(
    enabled=True,
    model="qwen2.5-coder:32b"
)
settings.cross_contract = CrossContractConfig(enabled=True)

# Run analysis
orchestrator = EnhancedVulnHuntrOrchestrator(settings)
results = orchestrator.scan_contracts([Path("contracts/MyContract.sol")])

# Access results
findings = results['findings']
cross_analysis = results.get('cross_contract_analysis', {})
ecosystem = results.get('contract_analysis', {})
```

## What Makes Smart Scan Different

### Traditional Tools
- Analyze contracts in isolation
- Focus on simple pattern matching
- Miss complex cross-contract vulnerabilities
- Limited understanding of business logic

### VulnHuntr2 Smart Scan
- ✅ **Holistic Analysis**: Understands contract ecosystems
- ✅ **AI-Powered Reasoning**: Uses foundation models for deep analysis
- ✅ **Economic Context**: Evaluates real-world exploitability
- ✅ **Novel Discovery**: Finds creative attack vectors
- ✅ **Cross-Contract Logic**: Identifies vulnerabilities spanning multiple contracts
- ✅ **Privacy First**: Everything runs locally

## Types of Vulnerabilities Discovered

### Cross-Contract Vulnerabilities
- Flash loan governance attacks
- Cross-contract reentrancy chains
- Proxy upgrade manipulation
- Multi-step oracle manipulation

### Economic Attack Vectors
- MEV extraction opportunities
- Arbitrage manipulation
- Liquidity manipulation
- Governance token attacks

### Novel Attack Patterns
- Contract interaction chains
- State dependency exploits
- Timing-based attacks
- Upgrade mechanism bypasses

## Troubleshooting

### Ollama Not Available
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Pull model if needed
ollama pull qwen2.5-coder:32b
```

### Memory Issues
- Use smaller models: `codegemma:7b` or `starcoder2:15b`
- Reduce `max_tokens` in configuration
- Close other applications to free RAM

### Slow Analysis
- Use faster models: `codegemma:7b`
- Reduce `max_contracts_per_analysis` in config
- Disable cross-contract analysis for initial scans

## Best Practices

1. **Start with Standard Scan**: Run basic vulnhuntr scan first to identify obvious issues
2. **Use Smart Scan for Deep Analysis**: Apply Smart Scan for complex protocols and multi-contract systems
3. **Model Selection**: Balance capability vs. speed based on your needs
4. **Privacy**: Keep sensitive contracts local - Smart Scan never sends data externally
5. **Iterative Analysis**: Use findings to guide manual review and additional testing

## Integration with Bug Bounty Programs

Smart Scan is designed to discover vulnerabilities that are valuable for:
- **Immunefi**: High-impact protocol vulnerabilities
- **HackerOne**: Complex cross-contract exploits
- **Sherlock**: Novel attack vectors in DeFi protocols
- **Hats Finance**: Economic attack opportunities

The tool focuses on findings that demonstrate:
- Real economic impact
- Novel attack techniques
- Cross-protocol vulnerabilities
- Complex exploit chains

---

**Remember**: Smart Scan is a powerful tool that augments but doesn't replace human expertise. Always combine automated analysis with manual review and testing.