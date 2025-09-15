"""
Command-line interface for vulnhuntr2.
"""
from pathlib import Path
from typing import Optional
import typer
import json
from rich.console import Console
from rich.table import Table
from rich import box

# Import detectors package to trigger registration
from . import detectors  # noqa: F401

from .core.orchestrator import Orchestrator
from .core.registry import get_registered_detectors
from .core.models import ScanContext

app = typer.Typer(help="Advanced smart contract vulnerability hunting with heuristic and LLM synthesis")
console = Console()


@app.command()
def list_detectors():
    """List all available detectors."""
    detectors = get_registered_detectors()
    
    table = Table(title="Available Detectors", box=box.ROUNDED)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Category", style="green")
    
    for detector in detectors:
        severity = getattr(detector, 'severity', 'UNKNOWN')
        category = getattr(detector, 'category', 'unknown')
        
        # Handle both string and Severity enum
        if hasattr(severity, 'value'):
            severity_str = severity.value
        else:
            severity_str = str(severity)
            
        table.add_row(
            detector.name,
            detector.description,
            severity_str,
            category
        )
    
    console.print(table)
    console.print(f"\n[bold green]Total detectors registered: {len(detectors)}[/bold green]")


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to analyze (Solidity)"),
    output_json: Optional[Path] = typer.Option(None, "--json", help="Write findings as JSON to path"),
    correlated_json: Optional[Path] = typer.Option(None, "--correlated-json", help="Write correlated findings to path"),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings", help="Exit non-zero if any findings"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM synthesis for enhanced analysis"),
    enable_correlation: bool = typer.Option(True, "--correlation/--no-correlation", help="Enable/disable finding correlation"),
    enable_poc: bool = typer.Option(False, "--poc", help="Generate proof-of-concept exploits"),
    poc_output_dir: Optional[Path] = typer.Option(None, "--poc-dir", help="Directory to write PoC files"),
    min_severity: str = typer.Option("INFO", "--min-severity", help="Minimum severity to report (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
    use_slither: bool = typer.Option(False, "--use-slither/--no-use-slither", help="Enable Slither static analysis for enhanced metadata"),
    slither_json: Optional[Path] = typer.Option(None, "--slither-json", help="Write raw Slither analysis to JSON file"),
):
    """Scan a file or directory for potential vulnerabilities with advanced analysis."""
    
    # Import here to avoid circular imports
    from .core.correlation import CorrelationEngine
    from .core.llm_synthesis import LLMSynthesisEngine
    from .core.poc_generator import PoCGenerator
    from .core.models import Severity
    from .parsing.slither_adapter import run_slither
    
    console.print(f"[bold blue]🔍 Scanning {target}[/bold blue]")
    
    # Create scan context
    context = ScanContext(
        target_path=target,
        enable_llm=llm,
        enable_correlation=enable_correlation,
        enable_poc_generation=enable_poc
    )
    
    # Run Slither analysis if requested
    if use_slither:
        console.print("[yellow]🔍 Running Slither static analysis...[/yellow]")
        try:
            slither_result = run_slither(target)
            if slither_result:
                context.tool_artifacts["slither"] = slither_result
                console.print(f"[green]✅ Analyzed {len(slither_result.contracts)} contracts with Slither[/green]")
                
                # Count functions across all contracts
                total_functions = sum(len(contract.functions) for contract in slither_result.contracts)
                console.print(f"[green]   Found {len(slither_result.contracts)} contracts, {total_functions} functions[/green]")
                
                # Save raw Slither output if requested
                if slither_json:
                    with open(slither_json, 'w') as f:
                        json.dump(slither_result.to_dict(), f, indent=2)
                    console.print(f"[blue]💾 Raw Slither analysis saved to {slither_json}[/blue]")
            else:
                console.print("[yellow]⚠️  Slither not available or analysis failed, continuing with heuristic detectors[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  Slither analysis failed: {e}, continuing with heuristic detectors[/yellow]")
    
    # Run orchestrator
    orch = Orchestrator()
    raw_findings = orch.run_enhanced(context)
    
    if not raw_findings:
        console.print("[bold green]✅ No findings detected.[/bold green]")
        return
    
    # Filter by minimum severity
    try:
        min_sev = Severity.from_string(min_severity)
        filtered_findings = [
            f for f in raw_findings 
            if f.severity.score >= min_sev.score
        ]
    except ValueError:
        console.print(f"[red]Invalid severity level: {min_severity}[/red]")
        filtered_findings = raw_findings
    
    # LLM Enhancement
    if llm:
        console.print("[yellow]🤖 Enhancing findings with LLM synthesis...[/yellow]")
        llm_engine = LLMSynthesisEngine()
        enhanced_findings = llm_engine.enhance_findings(filtered_findings, context)
        filtered_findings = enhanced_findings
    
    # Correlation Analysis
    correlated_findings = []
    if enable_correlation:
        console.print("[yellow]🔗 Performing correlation analysis...[/yellow]")
        correlator = CorrelationEngine()
        correlated_findings = correlator.correlate_findings(filtered_findings)
        
        # Enhance correlated findings with LLM if enabled
        if llm:
            correlated_findings = llm_engine.enhance_correlated_findings(correlated_findings, context)
    
    # PoC Generation
    if enable_poc and poc_output_dir:
        console.print("[yellow]⚡ Generating proof-of-concept exploits...[/yellow]")
        poc_generator = PoCGenerator()
        for finding in filtered_findings:
            if finding.severity.score >= Severity.MEDIUM.score:  # Only generate PoCs for medium+ severity
                poc_code = poc_generator.generate_poc(finding, context, poc_output_dir)
                finding.poc_code = poc_code
    
    # Display Results
    _display_findings(filtered_findings, correlated_findings)
    
    # Save outputs
    if output_json:
        _save_findings_json(filtered_findings, output_json)
        console.print(f"[bold blue]💾 Raw findings saved to {output_json}[/bold blue]")
    
    if correlated_json and correlated_findings:
        _save_correlated_json(correlated_findings, correlated_json)
        console.print(f"[bold blue]💾 Correlated findings saved to {correlated_json}[/bold blue]")
    
    # Exit with error if findings found and flag set
    if fail_on_findings and filtered_findings:
        raise typer.Exit(code=1)


def _display_findings(findings, correlated_findings):
    """Display findings in a formatted table."""
    
    console.print(f"\n[bold yellow]📊 Found {len(findings)} individual findings[/bold yellow]")
    
    if correlated_findings:
        console.print(f"[bold cyan]🔗 Grouped into {len(correlated_findings)} correlated clusters[/bold cyan]")
    
    # Create findings table
    table = Table(title="Vulnerability Findings", box=box.ROUNDED)
    table.add_column("Detector", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Severity", style="red")
    table.add_column("File", style="green")
    table.add_column("Line", style="yellow")
    table.add_column("Confidence", style="blue")
    
    for finding in findings:
        severity_color = _get_severity_color(finding.severity)
        confidence_pct = f"{finding.confidence:.0%}"
        
        table.add_row(
            finding.detector,
            finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
            f"[{severity_color}]{finding.severity.value}[/{severity_color}]",
            finding.file.split('/')[-1],  # Just filename
            str(finding.line),
            confidence_pct
        )
    
    console.print(table)
    
    # Display correlated findings summary
    if correlated_findings:
        console.print("\n[bold cyan]🔗 Correlated Finding Clusters:[/bold cyan]")
        for i, corr in enumerate(correlated_findings, 1):
            severity_color = _get_severity_color(corr.effective_severity)
            console.print(f"  {i}. [{severity_color}]{corr.primary_finding.title}[/{severity_color}] "
                         f"({len(corr.related_findings)} related findings)")


def _get_severity_color(severity) -> str:
    """Get color for severity display."""
    if hasattr(severity, 'value'):
        sev_val = severity.value
    else:
        sev_val = str(severity)
    
    return {
        'CRITICAL': 'bright_red',
        'HIGH': 'red', 
        'MEDIUM': 'yellow',
        'LOW': 'blue',
        'INFO': 'white'
    }.get(sev_val, 'white')


def _save_findings_json(findings, output_path: Path):
    """Save findings to JSON file."""
    findings_data = [f.to_dict() for f in findings]
    output_path.write_text(json.dumps(findings_data, indent=2))


def _save_correlated_json(correlated_findings, output_path: Path):
    """Save correlated findings to JSON file."""
    corr_data = [cf.to_dict() for cf in correlated_findings]
    output_path.write_text(json.dumps(corr_data, indent=2))


def main():  # pragma: no cover - entry point convenience
    app()

if __name__ == "__main__":  # pragma: no cover
    main()