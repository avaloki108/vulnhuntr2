#!/usr/bin/env python3
"""
Elite Web3 Audit CLI - The ultimate vulnerability hunting command
Implements the /elite-web3-audit functionality as a standalone CLI tool
"""

import asyncio
import sys
import os
import json
import logging
from pathlib import Path
from typing import Optional, List
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
import time

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnhuntr.detectors.elite_web3_detector import EliteWeb3Detector
from vulnhuntr.core.elite_llm import LLMConfig, LLMProvider, create_default_configs
from vulnhuntr.core.elite_scoring import EliteScoringEngine

# Setup rich console
console = Console()

# Setup logging with rich handler
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("elite-web3-audit")


@click.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--llm',
              type=click.Choice(['openai', 'anthropic', 'ollama', 'lmstudio', 'all']),
              default='all',
              help='LLM provider to use')
@click.option('--model',
              default=None,
              help='Specific model to use (e.g., gpt-4, claude-3-opus)')
@click.option('--min-score',
              type=int,
              default=200,
              help='Minimum vulnerability score threshold (default: 200)')
@click.option('--output',
              type=click.Path(),
              default=None,
              help='Output file for results (JSON format)')
@click.option('--verbose', '-v',
              is_flag=True,
              help='Verbose output')
@click.option('--parallel-agents',
              type=int,
              default=15,
              help='Number of parallel agents to deploy')
@click.option('--deep-mode',
              is_flag=True,
              help='Enable deep persistence hunting mode')
@click.option('--api-key',
              default=None,
              help='API key for LLM provider')
@click.option('--api-url',
              default=None,
              help='API URL for local LLM (Ollama/LM Studio)')
def elite_audit(target: str,
                llm: str,
                model: Optional[str],
                min_score: int,
                output: Optional[str],
                verbose: bool,
                parallel_agents: int,
                deep_mode: bool,
                api_key: Optional[str],
                api_url: Optional[str]):
    """
    ELITE WEB3 VULNERABILITY RESEARCH SYSTEM v4.0

    The ultimate smart contract vulnerability hunter - combining Slither's analysis
    with advanced LLM intelligence to discover novel, high-impact vulnerabilities
    worth $10k+ bug bounties.

    Operational mindset: John Wick style - silent, precise, relentless.
    """

    # Print epic banner
    console.print(Panel.fit("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     ELITE WEB3 VULNERABILITY RESEARCH SYSTEM v4.0           ║
    ║                                                              ║
    ║     🎯 Minimum Score: (N × E × I) ≥ 200                     ║
    ║     🤖 Multi-Agent Intelligence: 15+ Parallel Agents        ║
    ║     💰 Target: $10k+ Bug Bounties                          ║
    ║     🔍 Mode: John Wick - Silent, Precise, Relentless       ║
    ╚══════════════════════════════════════════════════════════════╝
    """, style="bold cyan"))

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Configure LLM providers
    llm_configs = configure_llm_providers(llm, model, api_key, api_url)

    if not llm_configs:
        console.print("[red]No LLM providers configured![/red]")
        console.print("Please set API keys or ensure local LLMs are running:")
        console.print("  - OpenAI: export OPENAI_API_KEY=...")
        console.print("  - Anthropic: export ANTHROPIC_API_KEY=...")
        console.print("  - Ollama: ollama serve")
        console.print("  - LM Studio: Start server on port 1234")
        sys.exit(1)

    # Show configured providers
    console.print("\n[bold cyan]Configured LLM Providers:[/bold cyan]")
    for config in llm_configs:
        console.print(f"  • {config.provider.value}: {config.model}")

    # Initialize detector
    detector = EliteWeb3Detector(llm_configs)

    # Set configuration
    if min_score != 200:
        console.print(f"[yellow]Custom score threshold: {min_score}[/yellow]")

    # Run the audit
    console.print(f"\n[bold green]🎯 Target:[/bold green] {target}")
    console.print(f"[bold green]🤖 Agents:[/bold green] {parallel_agents} parallel")
    console.print(f"[bold green]🔍 Mode:[/bold green] {'Deep Persistence' if deep_mode else 'Standard'}")

    # Execute with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing elite audit system...", total=None)

        # Run async analysis
        findings = asyncio.run(run_analysis(detector, target, progress, task))

    # Display results
    display_results(findings, console)

    # Save results if requested
    if output:
        save_results(findings, output)
        console.print(f"\n[green]Results saved to:[/green] {output}")

    # Exit with appropriate code
    if findings:
        console.print(f"\n[bold green]✅ Found {len(findings)} elite vulnerabilities![/bold green]")
        sys.exit(0)
    else:
        console.print("\n[yellow]⚠️ No vulnerabilities meeting elite threshold found.[/yellow]")
        console.print("[yellow]Consider running with --deep-mode for persistence hunting.[/yellow]")
        sys.exit(1)


def configure_llm_providers(llm: str,
                           model: Optional[str],
                           api_key: Optional[str],
                           api_url: Optional[str]) -> List[LLMConfig]:
    """Configure LLM providers based on CLI options"""
    configs = []

    # Override environment with CLI args if provided
    if api_key:
        if llm == 'openai':
            os.environ['OPENAI_API_KEY'] = api_key
        elif llm == 'anthropic':
            os.environ['ANTHROPIC_API_KEY'] = api_key

    if llm == 'all':
        # Try all available providers
        configs = create_default_configs()
    elif llm == 'openai':
        if os.getenv('OPENAI_API_KEY') or api_key:
            configs.append(LLMConfig(
                provider=LLMProvider.OPENAI,
                model=model or 'gpt-4-turbo-preview',
                api_key=api_key or os.getenv('OPENAI_API_KEY')
            ))
    elif llm == 'anthropic':
        if os.getenv('ANTHROPIC_API_KEY') or api_key:
            configs.append(LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model=model or 'claude-3-opus-20240229',
                api_key=api_key or os.getenv('ANTHROPIC_API_KEY')
            ))
    elif llm == 'ollama':
        configs.append(LLMConfig(
            provider=LLMProvider.OLLAMA,
            model=model or 'llama3:70b',
            api_url=api_url or 'http://localhost:11434/api/generate'
        ))
    elif llm == 'lmstudio':
        configs.append(LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            model=model or 'local-model',
            api_url=api_url or 'http://localhost:1234/v1/chat/completions'
        ))

    return configs


async def run_analysis(detector: EliteWeb3Detector,
                       target: str,
                       progress: Progress,
                       task) -> List:
    """Run the elite analysis"""
    phases = [
        "Phase 0: Build & Test System",
        "Phase 1: Comprehensive Codebase Analysis",
        "Phase 2: Deploying Multi-Agent System",
        "Phase 3: Adversarial Validation Council",
        "Phase 4: Elite Scoring & Synthesis",
        "Phase 5: Professional Report Generation"
    ]

    for phase in phases:
        progress.update(task, description=f"[cyan]{phase}[/cyan]")
        await asyncio.sleep(0.5)  # Brief pause for visual effect

    # Run actual analysis
    findings = await detector.analyze(target)

    progress.update(task, description="[bold green]Analysis complete![/bold green]")
    return findings


def display_results(findings: List, console: Console):
    """Display analysis results in a beautiful format"""
    if not findings:
        console.print("\n[yellow]No vulnerabilities meeting elite criteria found.[/yellow]")
        return

    console.print(f"\n[bold cyan]═══ ELITE VULNERABILITIES DISCOVERED ═══[/bold cyan]\n")

    for i, finding in enumerate(findings, 1):
        # Extract metadata
        metadata = finding.metadata
        score = metadata.get('score', 0)
        category = metadata.get('category', 'unknown')
        bounty = metadata.get('estimated_bounty', (0, 0))
        report = metadata.get('report', {})

        # Create vulnerability panel
        panel_content = f"""
[bold white]{finding.title}[/bold white]

[cyan]Score:[/cyan] [bold yellow]{score:.1f}[/bold yellow] (N×E×I)
[cyan]Category:[/cyan] {category}
[cyan]Severity:[/cyan] [bold red]{finding.severity.value.upper()}[/bold red]
[cyan]Confidence:[/cyan] {finding.confidence:.1%}
[cyan]Estimated Bounty:[/cyan] [bold green]${bounty[0]:,.0f} - ${bounty[1]:,.0f}[/bold green]

[dim]{finding.description[:300]}...[/dim]
        """

        console.print(Panel(panel_content,
                          title=f"[bold]Vulnerability #{i}[/bold]",
                          border_style="cyan"))

    # Summary table
    table = Table(title="Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    total_min = sum(f.metadata.get('estimated_bounty', (0, 0))[0] for f in findings)
    total_max = sum(f.metadata.get('estimated_bounty', (0, 0))[1] for f in findings)
    avg_score = sum(f.metadata.get('score', 0) for f in findings) / len(findings) if findings else 0

    table.add_row("Total Vulnerabilities", str(len(findings)))
    table.add_row("Average Score", f"{avg_score:.1f}")
    table.add_row("Total Bounty Estimate", f"${total_min:,.0f} - ${total_max:,.0f}")

    console.print("\n")
    console.print(table)


def save_results(findings: List, output_path: str):
    """Save results to JSON file"""
    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": len(findings),
        "vulnerabilities": []
    }

    for finding in findings:
        vuln_data = {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "location": finding.location,
            "metadata": finding.metadata
        }
        results["vulnerabilities"].append(vuln_data)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    elite_audit()