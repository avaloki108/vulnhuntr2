"""
Command-line interface for vulnhuntr2.
"""
from pathlib import Path
from typing import Optional, List
import typer
import json
from rich.console import Console
from rich.table import Table
from rich import box

# Import detectors package to trigger registration
from . import detectors  # noqa: F401

from .core.orchestrator import Orchestrator
from .core.registry import get_registered_detectors
from .core.models import ScanContext, Severity
from .core.version import VERSION
from .core.reporting import ReportingEngine
from .config.loader import load_config, dump_config, write_config, compute_config_hash
from .config.schema import RunConfig
from .detectors import load_detectors, explain_selector as explain_detector_selector

app = typer.Typer(help="Advanced smart contract vulnerability hunting with heuristic and LLM synthesis")
console = Console()


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        console.print(f"vulnhuntr2 {VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=version_callback, help="Show version and exit"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
    config_dump: bool = typer.Option(False, "--config-dump", help="Dump merged configuration as JSON and exit"),
    config_write: Optional[Path] = typer.Option(None, "--config-write", help="Write current config to TOML file and exit"),
    print_config_hash: bool = typer.Option(False, "--print-config-hash", help="Print config hash and exit"),
    explain_selector: Optional[str] = typer.Option(None, "--explain-selector", help="Explain which detectors match selector and exit"),
):
    """Global options for vulnhuntr2."""
    # Load configuration for global operations
    if any([config_dump, config_write, print_config_hash, explain_selector]):
        config, warnings = load_config(config_file)
        
        # Print warnings
        for warning in warnings:
            console.print(f"[yellow]Warning: {warning}[/yellow]")
        
        if config_dump:
            console.print(dump_config(config))
            raise typer.Exit()
        
        if config_write:
            try:
                write_config(config, config_write)
                console.print(f"[green]Configuration written to {config_write}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to write config: {e}[/red]")
                raise typer.Exit(1)
            raise typer.Exit()
        
        if print_config_hash:
            hash_value = compute_config_hash(config)
            console.print(hash_value)
            raise typer.Exit()
        
        if explain_selector:
            explanation = explain_detector_selector(explain_selector)
            console.print_json(data=explanation)
            raise typer.Exit()


@app.command()
def list_detectors(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
):
    """List all available detectors with enhanced metadata."""
    config, warnings = load_config(config_file)
    
    # Print warnings
    for warning in warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # Load detectors with current config
    enabled_detectors, detector_warnings, _ = load_detectors(config)
    enabled_names = {getattr(d, 'name', str(d)) for d in enabled_detectors}
    
    all_detectors = get_registered_detectors()
    
    if json_output:
        detectors_data = []
        for detector in all_detectors:
            metadata = detector.get_metadata()
            metadata['enabled'] = detector.name in enabled_names
            detectors_data.append(metadata)
        
        console.print_json(data={
            "total_detectors": len(all_detectors),
            "enabled_detectors": len(enabled_detectors),
            "detectors": detectors_data
        })
        return
    
    # Display as table
    table = Table(title="Available Detectors", box=box.ROUNDED)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Category", style="green")
    table.add_column("Stability", style="blue")
    table.add_column("Enabled", style="yellow")
    
    for detector in all_detectors:
        severity = getattr(detector, 'severity', 'UNKNOWN')
        category = getattr(detector, 'category', 'unknown')
        stability = getattr(detector, 'stability', 'unknown')
        enabled = "✓" if detector.name in enabled_names else "✗"
        
        # Handle both string and Severity enum
        if hasattr(severity, 'value'):
            severity_str = severity.value
        else:
            severity_str = str(severity)
        
        table.add_row(
            detector.name,
            detector.description[:60] + "..." if len(detector.description) > 60 else detector.description,
            severity_str,
            category,
            stability,
            enabled
        )
    
    console.print(table)
    console.print(f"\n[bold green]Total detectors: {len(all_detectors)} | Enabled: {len(enabled_detectors)}[/bold green]")
    
    # Show detector warnings
    for warning in detector_warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to analyze (Solidity)"),
    
    # Configuration
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
    
    # Detector selection
    enable: List[str] = typer.Option([], "--enable", help="Enable detector selectors (can be used multiple times)"),
    disable: List[str] = typer.Option([], "--disable", help="Disable detector selectors (can be used multiple times)"),
    
    # Output options
    output_json: Optional[Path] = typer.Option(None, "--json", help="Write findings as JSON to path"),
    correlated_json: Optional[Path] = typer.Option(None, "--correlated-json", help="Write correlated findings to path"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Minimum severity to report (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
    
    # Analysis options
    llm: Optional[bool] = typer.Option(None, "--llm/--no-llm", help="Enable/disable LLM synthesis"),
    enable_correlation: Optional[bool] = typer.Option(None, "--correlation/--no-correlation", help="Enable/disable finding correlation"),
    enable_poc: Optional[bool] = typer.Option(None, "--poc/--no-poc", help="Enable/disable PoC generation"),
    poc_output_dir: Optional[Path] = typer.Option(None, "--poc-dir", help="Directory to write PoC files"),
    use_slither: Optional[bool] = typer.Option(None, "--use-slither/--no-use-slither", help="Enable/disable Slither static analysis"),
    slither_json: Optional[Path] = typer.Option(None, "--slither-json", help="Write raw Slither analysis to JSON file"),
    
    # CI Gating options
    fail_on_findings: Optional[bool] = typer.Option(None, "--fail-on-findings/--no-fail-on-findings", help="Exit non-zero if any findings"),
    fail_on_severity: Optional[str] = typer.Option(None, "--fail-on-severity", help="Exit non-zero if findings >= severity"),
    fail_on_confidence: Optional[float] = typer.Option(None, "--fail-on-confidence", help="Exit non-zero if findings >= confidence"),
    fail_on_finding_count: Optional[int] = typer.Option(None, "--fail-on-finding-count", help="Exit non-zero if total findings >= count"),
):
    """Scan a file or directory for potential vulnerabilities with advanced analysis."""
    
    # Load base configuration
    config, config_warnings = load_config(config_file)
    
    # Override with CLI options
    config.target_path = target
    
    # Detector selection overrides
    if enable:
        config.detectors.enabled.extend(enable)
    if disable:
        config.detectors.disabled.extend(disable)
    
    # Analysis overrides
    if llm is not None:
        config.llm.enabled = llm
    if enable_correlation is not None:
        config.analysis.enable_correlation = enable_correlation
    if enable_poc is not None:
        config.analysis.enable_poc_generation = enable_poc
    if poc_output_dir is not None:
        config.analysis.poc_output_dir = poc_output_dir
    if use_slither is not None:
        config.analysis.use_slither = use_slither
    if slither_json is not None:
        config.analysis.slither_json_file = slither_json
    
    # Output overrides
    if output_json is not None:
        config.output.json_file = output_json
    if correlated_json is not None:
        config.output.correlated_json_file = correlated_json
    if min_severity is not None:
        config.output.min_severity = min_severity
    
    # Gating overrides
    if fail_on_findings is not None:
        config.reporting.fail_on_findings = fail_on_findings
    if fail_on_severity is not None:
        config.reporting.fail_on_severity = fail_on_severity
    if fail_on_confidence is not None:
        config.reporting.fail_on_confidence = fail_on_confidence
    if fail_on_finding_count is not None:
        config.reporting.fail_on_finding_count = fail_on_finding_count
    
    # Print configuration warnings
    for warning in config_warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    console.print(f"[bold blue]🔍 Scanning {target}[/bold blue]")
    
    # Load enabled detectors
    enabled_detectors, detector_warnings, _ = load_detectors(config)
    
    # Print detector warnings
    for warning in detector_warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    console.print(f"[green]Loaded {len(enabled_detectors)} detectors[/green]")
    
    # Create scan context
    context = ScanContext(
        target_path=target,
        enable_llm=config.llm.enabled,
        enable_correlation=config.analysis.enable_correlation,
        enable_poc_generation=config.analysis.enable_poc_generation
    )
    
    # Run Slither analysis if requested
    if config.analysis.use_slither:
        console.print("[yellow]🔍 Running Slither static analysis...[/yellow]")
        try:
            from .parsing.slither_adapter import run_slither
            slither_result = run_slither(target)
            if slither_result:
                context.tool_artifacts["slither"] = slither_result
                console.print(f"[green]✅ Analyzed {len(slither_result.contracts)} contracts with Slither[/green]")
                
                # Count functions across all contracts
                total_functions = sum(len(contract.functions) for contract in slither_result.contracts)
                console.print(f"[green]   Found {len(slither_result.contracts)} contracts, {total_functions} functions[/green]")
                
                # Save raw Slither output if requested
                if config.analysis.slither_json_file:
                    with open(config.analysis.slither_json_file, 'w') as f:
                        json.dump(slither_result.to_dict(), f, indent=2)
                    console.print(f"[blue]💾 Raw Slither analysis saved to {config.analysis.slither_json_file}[/blue]")
            else:
                console.print("[yellow]⚠️  Slither not available or analysis failed, continuing with heuristic detectors[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  Slither analysis failed: {e}, continuing with heuristic detectors[/yellow]")
    
    # Run orchestrator with filtered detectors
    orch = Orchestrator(enabled_detectors)
    raw_findings = orch.run_enhanced(context)
    
    if not raw_findings:
        console.print("[bold green]✅ No findings detected.[/bold green]")
        
        # Still create reporting engine to handle gating (might fail on zero findings if configured)
        reporting_engine = ReportingEngine(config)
        exit_code, gating_reasons, report = reporting_engine.package_results(
            raw_findings, raw_findings, [], enabled_detectors, config_warnings + detector_warnings
        )
        
        if exit_code != 0:
            console.print(reporting_engine.format_exit_summary(exit_code, gating_reasons))
            raise typer.Exit(exit_code)
        
        return
    
    # Filter by minimum severity
    try:
        min_sev = Severity.from_string(config.output.min_severity)
        filtered_findings = [
            f for f in raw_findings 
            if f.severity.score >= min_sev.score
        ]
    except ValueError:
        console.print(f"[red]Invalid severity level: {config.output.min_severity}[/red]")
        filtered_findings = raw_findings
    
    # LLM Enhancement
    if config.llm.enabled:
        console.print("[yellow]🤖 Enhancing findings with LLM synthesis...[/yellow]")
        from .core.llm_synthesis import LLMSynthesisEngine
        llm_engine = LLMSynthesisEngine()
        enhanced_findings = llm_engine.enhance_findings(filtered_findings, context)
        filtered_findings = enhanced_findings
    
    # Correlation Analysis
    correlated_findings = []
    if config.analysis.enable_correlation:
        console.print("[yellow]🔗 Performing correlation analysis...[/yellow]")
        from .core.correlation import CorrelationEngine
        correlator = CorrelationEngine()
        correlated_findings = correlator.correlate_findings(filtered_findings)
        
        # Enhance correlated findings with LLM if enabled
        if config.llm.enabled:
            correlated_findings = llm_engine.enhance_correlated_findings(correlated_findings, context)
    
    # PoC Generation
    if config.analysis.enable_poc_generation and config.analysis.poc_output_dir:
        console.print("[yellow]⚡ Generating proof-of-concept exploits...[/yellow]")
        from .core.poc_generator import PoCGenerator
        poc_generator = PoCGenerator()
        for finding in filtered_findings:
            if finding.severity.score >= Severity.MEDIUM.score:  # Only generate PoCs for medium+ severity
                poc_code = poc_generator.generate_poc(finding, context, config.analysis.poc_output_dir)
                finding.poc_code = poc_code
    
    # Create reporting engine and evaluate gating against raw findings (before filtering)
    reporting_engine = ReportingEngine(config)
    exit_code, gating_reasons, report = reporting_engine.package_results(
        raw_findings, filtered_findings, correlated_findings, enabled_detectors, config_warnings + detector_warnings
    )
    
    # Display Results
    _display_findings(filtered_findings, correlated_findings)
    
    # Save outputs
    if config.output.json_file:
        reporting_engine.save_json_report(report, config.output.json_file)
        console.print(f"[bold blue]💾 Report saved to {config.output.json_file}[/bold blue]")
    
    if config.output.correlated_json_file and correlated_findings:
        corr_data = [cf.to_dict() for cf in correlated_findings]
        config.output.correlated_json_file.write_text(json.dumps(corr_data, indent=2))
        console.print(f"[bold blue]💾 Correlated findings saved to {config.output.correlated_json_file}[/bold blue]")
    
    # Display exit summary and exit with appropriate code
    if exit_code != 0:
        console.print(f"\n{reporting_engine.format_exit_summary(exit_code, gating_reasons)}")
    
    raise typer.Exit(exit_code)
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


def main():  # pragma: no cover - entry point convenience
    app()


if __name__ == "__main__":  # pragma: no cover
    main()