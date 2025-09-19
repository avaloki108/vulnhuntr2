# Elite Web3 Vulnerability Hunter - Usage Guide

## 🎯 Overview

The Elite Web3 Vulnerability Hunter is a sophisticated smart contract auditing tool that combines Slither's static analysis with advanced LLM intelligence to discover novel, high-impact vulnerabilities worth $10k+ bug bounties.

**Operational Mode**: John Wick style - silent, precise, relentless

## 🚀 Quick Start

### Basic Usage

```bash
# Analyze a single contract
python -m vulnhuntr elite ./path/to/contract.sol

# Analyze a project directory
python -m vulnhuntr elite ./path/to/project/

# With specific LLM provider
python -m vulnhuntr elite ./contracts/ --llm ollama

# Save results to JSON
python -m vulnhuntr elite ./contracts/ --output results.json
```

## 🤖 LLM Configuration

### Supported Providers

1. **OpenAI** (GPT-4)
   ```bash
   export OPENAI_API_KEY=sk-...
   python -m vulnhuntr elite ./contracts/ --llm openai
   ```

2. **Anthropic** (Claude)
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   python -m vulnhuntr elite ./contracts/ --llm anthropic
   ```

3. **Ollama** (Local LLMs)
   ```bash
   # Start Ollama server
   ollama serve

   # Pull a model (e.g., llama3:70b)
   ollama pull llama3:70b

   # Run analysis
   python -m vulnhuntr elite ./contracts/ --llm ollama --model llama3:70b
   ```

4. **LM Studio** (Local LLMs)
   ```bash
   # Start LM Studio server on port 1234
   # Then run:
   python -m vulnhuntr elite ./contracts/ --llm lmstudio
   ```

5. **All Available** (Default)
   ```bash
   # Uses all configured providers in parallel
   python -m vulnhuntr elite ./contracts/ --llm all
   ```

## 📊 Command Options

```bash
python -m vulnhuntr elite [OPTIONS] TARGET

Arguments:
  TARGET                Path to smart contract or project directory

Options:
  --llm TEXT           LLM provider: openai, anthropic, ollama, lmstudio, all [default: all]
  --model TEXT         Specific model to use (e.g., gpt-4, claude-3-opus)
  --min-score INT      Minimum vulnerability score threshold [default: 200]
  --output, -o PATH    Output file for results (JSON format)
  --verbose, -v        Verbose output
  --deep-mode          Enable deep persistence hunting mode
  --api-key TEXT       API key for LLM provider
  --api-url TEXT       API URL for local LLM (Ollama/LM Studio)
  --help               Show this message and exit
```

## 🎭 Multi-Agent System

The tool deploys 15+ parallel agents in different phases:

### Phase 1: Reconnaissance Swarm (5 agents)
- **RECON_ALPHA**: Architecture Intelligence
- **RECON_BETA**: Financial Flow Reasoning
- **RECON_GAMMA**: Access Control Reasoning
- **RECON_DELTA**: Integration Intelligence
- **RECON_EPSILON**: Protocol Classification

### Phase 2: Vulnerability Hunters (10 agents)
- **HUNTER_ALPHA**: Reentrancy Reasoning Master
- **HUNTER_BETA**: Access Control Reasoning Master
- **HUNTER_GAMMA**: Mathematical Reasoning Master
- **HUNTER_DELTA**: Oracle Reasoning Master
- **HUNTER_EPSILON**: Flash Loan Reasoning Master
- **HUNTER_ZETA**: MEV Extraction Specialist
- **HUNTER_ETA**: Storage Reasoning Master
- **HUNTER_THETA**: Signature Reasoning Master
- **HUNTER_IOTA**: Edge Case Reasoning Master
- **HUNTER_KAPPA**: Novel Attack Reasoning Master

### Phase 3: Adversarial Validation Council (5 validators)
- Protection Checker
- Execution Path Verifier
- Economic Feasibility Checker
- State Requirement Analyzer
- Mainnet Condition Verifier

## 📈 Scoring System

Vulnerabilities are scored using the formula:
```
Score = Novelty (1-10) × Exploitability (1-10) × Impact (1-10)
```

**Minimum Threshold**: 200 points

### Severity Levels
- **LEGENDARY** (≥500): Never-seen-before vulnerabilities
- **CRITICAL** (≥300): Direct fund theft, protocol shutdown
- **HIGH** (≥200): Significant impact, funds at risk
- **MEDIUM** (≥100): Limited impact, edge cases
- **LOW** (<100): Minor issues

## 💰 Bug Bounty Estimates

The tool provides automatic bounty estimates based on:
- Vulnerability severity
- Protocol TVL
- Historical payouts
- Novelty factor

Typical ranges:
- **LEGENDARY**: $50,000 - $500,000
- **CRITICAL**: $10,000 - $100,000
- **HIGH**: $5,000 - $50,000

## 🔍 Deep Persistence Mode

When initial scans yield no results, enable deep mode:

```bash
python -m vulnhuntr elite ./contracts/ --deep-mode
```

This activates:
- Extended code analysis
- Complex attack chain discovery
- Edge case exploration
- Cross-contract vulnerability hunting

## 📝 Output Format

Results are provided in multiple formats:

### Console Output
- Beautiful formatted vulnerability cards
- Score breakdowns
- Severity indicators
- Bounty estimates

### JSON Output
```json
{
  "timestamp": "2024-01-01 12:00:00",
  "total_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "title": "Critical Reentrancy in Withdraw Function",
      "severity": "critical",
      "score": 324.5,
      "novelty": 8.5,
      "exploitability": 7.6,
      "impact": 5.0,
      "estimated_bounty": [25000, 75000],
      "description": "...",
      "location": {...},
      "proof_of_concept": "...",
      "fix_recommendation": "..."
    }
  ]
}
```

## 🛠️ Prerequisites

### Required
- Python 3.8+
- Solidity contracts or project

### Optional (but recommended)
- Slither (`pip install slither-analyzer`)
- At least one LLM provider configured
- Foundry/Hardhat for compilation

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnhuntr2
cd vulnhuntr2

# Install dependencies
pip install -e .
pip install aiohttp click

# Install Slither (recommended)
pip install slither-analyzer

# Configure LLM (choose one)
export OPENAI_API_KEY=your-key
# OR
export ANTHROPIC_API_KEY=your-key
# OR
ollama serve && ollama pull llama3:70b
```

## 📚 Examples

### Example 1: Analyze a DEX Protocol
```bash
python -m vulnhuntr elite ./uniswap-v3-core/ \
  --llm openai \
  --model gpt-4-turbo-preview \
  --output uniswap-audit.json \
  --verbose
```

### Example 2: Quick Local Analysis
```bash
python -m vulnhuntr elite ./contracts/Token.sol \
  --llm ollama \
  --model llama3:70b
```

### Example 3: Deep Audit with All Providers
```bash
python -m vulnhuntr elite ./compound-protocol/ \
  --llm all \
  --deep-mode \
  --min-score 150 \
  --output compound-audit.json
```

## ⚡ Performance Tips

1. **Use local LLMs for speed**: Ollama or LM Studio
2. **Use cloud LLMs for quality**: OpenAI GPT-4 or Anthropic Claude
3. **Parallel processing**: Use `--llm all` to leverage multiple providers
4. **Focus scope**: Analyze specific contracts rather than entire codebases
5. **Adjust threshold**: Lower `--min-score` for more findings

## 🚨 Responsible Disclosure

This tool is designed for:
- Legitimate bug bounty programs
- Authorized security audits
- Educational purposes
- Defensive security research

Always:
- Get permission before auditing
- Follow responsible disclosure
- Respect bug bounty rules
- Never exploit vulnerabilities

## 📞 Support

For issues or questions:
- GitHub Issues: [Report bugs](https://github.com/yourusername/vulnhuntr2/issues)
- Documentation: This file
- Community: Join our Discord

## 🎯 Mission

**Find the ONE vulnerability that everyone else missed.**

Silent. Precise. Relentless.