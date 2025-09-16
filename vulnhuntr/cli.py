"""
Command-line interface for vulnhuntr2.
"""
from pathlib import Path
from typing import Optional, List
import typer
import json
import time
from rich.console import Console
from rich.table import Table
from rich import box

# Import detectors package to trigger registration
from . import detectors  # noqa: F401

from .core.orchestrator import Orchestrator
from .core.registry import get_registered_detectors
from .core.models import ScanContext, Severity
from .core.version import VERSION
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
def explain_finding(
    finding_id: str = typer.Argument(..., help="Finding ID or finding description to explain"),
    format: str = typer.Option("json", "--format", help="Output format: json, markdown"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
):
    """Explain a specific finding with detailed analysis and evidence."""
    config, warnings = load_config(config_file)
    
    # Print warnings
    for warning in warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # For now, provide a template explanation
    # In a full implementation, this would look up the finding and provide detailed analysis
    explanation = {
        "finding_id": finding_id,
        "explanation": {
            "description": "Detailed explanation of the vulnerability",
            "attack_vector": "How this vulnerability could be exploited",
            "impact": "Potential impact if exploited",
            "remediation": "Recommended fixes and mitigations",
            "evidence": {
                "path_slices": "Code execution paths that lead to the vulnerability",
                "symbolic_traces": "Symbolic execution evidence",
                "variables_of_interest": "Key variables involved in the vulnerability"
            },
            "references": [
                "https://example.com/vulnerability-details",
                "https://example.com/best-practices"
            ]
        }
    }
    
    if format == "markdown":
        console.print(f"# Finding Explanation: {finding_id}")
        console.print(f"\n## Description\n{explanation['explanation']['description']}")
        console.print(f"\n## Attack Vector\n{explanation['explanation']['attack_vector']}")
        console.print(f"\n## Impact\n{explanation['explanation']['impact']}")
        console.print(f"\n## Remediation\n{explanation['explanation']['remediation']}")
        console.print("\n## Evidence")
        for key, value in explanation['explanation']['evidence'].items():
            console.print(f"- **{key.replace('_', ' ').title()}**: {value}")
        console.print("\n## References")
        for ref in explanation['explanation']['references']:
            console.print(f"- {ref}")
    else:
        console.print_json(data=explanation)


@app.command()
def export_evidence(
    target: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to analyze"),
    output: Path = typer.Argument(..., help="Output file for evidence export"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
    format: str = typer.Option("json", "--format", help="Export format: json"),
):
    """Export evidence bundles for findings."""
    config, warnings = load_config(config_file)
    
    # Print warnings
    for warning in warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    console.print(f"[bold blue]🔍 Analyzing {target} for evidence export[/bold blue]")
    
    # Load enabled detectors
    enabled_detectors, detector_warnings, _ = load_detectors(config)
    
    # Print detector warnings
    for warning in detector_warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # Create scan context
    context = ScanContext(target_path=target)
    
    # Run analysis
    orch = Orchestrator(enabled_detectors)
    findings = orch.run_enhanced(context)
    
    if not findings:
        console.print("[bold yellow]No findings to export evidence for[/bold yellow]")
        return
    
    # Run correlation to generate evidence bundles
    console.print("[yellow]🔗 Performing correlation analysis for evidence generation...[/yellow]")
    from .core.correlation import CorrelationEngine
    correlator = CorrelationEngine()
    correlated_findings = correlator.correlate_findings(findings)
    
    # Export evidence
    from .core.reporting import EnhancedReportingEngine
    reporting_engine = EnhancedReportingEngine(config)
    reporting_engine.save_evidence_export(correlated_findings, output)
    
    console.print(f"[bold green]✅ Evidence exported to {output}[/bold green]")
    console.print(f"[green]Exported {len(correlated_findings)} evidence bundles[/green]")


@app.command()
def profile(
    target: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to analyze"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
    output: Optional[Path] = typer.Option(None, "--output", help="Save profiling results to file"),
):
    """Profile vulnhuntr performance and resource usage."""
    import time
    import psutil
    
    config, warnings = load_config(config_file)
    
    # Print warnings
    for warning in warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    console.print(f"[bold blue]📊 Profiling performance on {target}[/bold blue]")
    
    # Start profiling
    start_time = time.time()
    start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
    
    # Load detectors
    detector_start = time.time()
    enabled_detectors, detector_warnings, _ = load_detectors(config)
    detector_time = time.time() - detector_start
    
    # Run analysis
    analysis_start = time.time()
    context = ScanContext(target_path=target)
    orch = Orchestrator(enabled_detectors)
    findings = orch.run_enhanced(context)
    analysis_time = time.time() - analysis_start
    
    # Run correlation
    correlation_start = time.time()
    from .core.correlation import CorrelationEngine
    correlator = CorrelationEngine()
    correlated_findings = correlator.correlate_findings(findings)
    correlation_time = time.time() - correlation_start
    
    # End profiling
    end_time = time.time()
    end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
    
    total_time = end_time - start_time
    memory_used = end_memory - start_memory
    
    # Generate profiling report
    profile_data = {
        "total_runtime_seconds": total_time,
        "memory_used_mb": memory_used,
        "peak_memory_mb": end_memory,
        "phase_timings": {
            "detector_loading": detector_time,
            "analysis": analysis_time,
            "correlation": correlation_time
        },
        "performance_metrics": {
            "findings_per_second": len(findings) / total_time if total_time > 0 else 0,
            "detectors_per_second": len(enabled_detectors) / detector_time if detector_time > 0 else 0,
            "correlation_clusters_per_second": len(correlated_findings) / correlation_time if correlation_time > 0 else 0
        },
        "resource_efficiency": {
            "findings_per_mb": len(findings) / memory_used if memory_used > 0 else 0,
            "time_per_detector": detector_time / len(enabled_detectors) if enabled_detectors else 0
        },
        "analysis_stats": {
            "total_findings": len(findings),
            "correlated_clusters": len(correlated_findings),
            "detectors_enabled": len(enabled_detectors)
        }
    }
    
    # Display profiling results
    console.print("\n[bold cyan]📊 Profiling Results[/bold cyan]")
    
    table = Table(title="Performance Metrics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Runtime", f"{total_time:.2f}s")
    table.add_row("Memory Used", f"{memory_used:.1f} MB")
    table.add_row("Peak Memory", f"{end_memory:.1f} MB")
    table.add_row("Detector Loading", f"{detector_time:.3f}s")
    table.add_row("Analysis Time", f"{analysis_time:.3f}s")
    table.add_row("Correlation Time", f"{correlation_time:.3f}s")
    table.add_row("Findings/Second", f"{profile_data['performance_metrics']['findings_per_second']:.1f}")
    table.add_row("Findings/MB", f"{profile_data['resource_efficiency']['findings_per_mb']:.1f}")
    
    console.print(table)
    
    # Save to file if requested
    if output:
        import json
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w') as f:
            json.dump(profile_data, f, indent=2)
        console.print(f"[bold blue]💾 Profiling results saved to {output}[/bold blue]")


@app.command()
def list_detectors(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file path"),
    show_categories: bool = typer.Option(False, "--show-categories", help="Show available categories"),
    show_patterns: bool = typer.Option(False, "--show-patterns", help="Show correlation patterns"),
    show_metadata: bool = typer.Option(False, "--show-metadata", help="Show enhanced detector metadata"),
):
    """List all available detectors with enhanced metadata and correlation patterns."""
    config, warnings = load_config(config_file)
    
    # Print warnings
    for warning in warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # Load detectors with current config
    enabled_detectors, detector_warnings, _ = load_detectors(config)
    enabled_names = {getattr(d, 'name', str(d)) for d in enabled_detectors}
    
    all_detectors = get_registered_detectors()
    
    # Load correlation patterns if requested
    patterns_info = []
    if show_patterns:
        try:
            from .correlation import EnhancedCorrelationEngine
            engine = EnhancedCorrelationEngine()
            patterns_info = [
                {
                    "name": pattern.name,
                    "kind": pattern.kind,
                    "member_detectors": pattern.member_detectors,
                    "min_members": pattern.min_members,
                    "notes": pattern.notes
                }
                for pattern in engine.patterns
            ]
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load correlation patterns: {e}[/yellow]")
    
    if json_output:
        detectors_data = []
        for detector in all_detectors:
            metadata = detector.get_metadata()
            metadata['enabled'] = detector.name in enabled_names
            
            # Add enhanced metadata if requested
            if show_metadata:
                metadata.update({
                    'requires_slither': getattr(detector, 'requires_slither', False),
                    'supports_llm_enrichment': getattr(detector, 'supports_llm_enrichment', False),
                    'maturity': getattr(detector, 'maturity', 'alpha'),
                    'enabled_by_default': getattr(detector, 'enabled_by_default', True)
                })
            
            detectors_data.append(metadata)
        
        output_data = {
            "total_detectors": len(all_detectors),
            "enabled_detectors": len(enabled_detectors),
            "detectors": detectors_data
        }
        
        if show_categories:
            categories = set()
            for detector in all_detectors:
                categories.add(getattr(detector, 'category', 'unknown'))
            output_data["available_categories"] = sorted(list(categories))
        
        if show_patterns:
            output_data["correlation_patterns"] = patterns_info
        
        console.print_json(data=output_data)
        return
    
    # Display as enhanced table
    table = Table(title="Available Detectors", box=box.ROUNDED)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Category", style="green")
    table.add_column("Stability", style="blue")
    
    if show_metadata:
        table.add_column("Maturity", style="yellow")
        table.add_column("Slither", style="magenta")
    
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
        
        row_data = [
            detector.name,
            detector.description[:60] + "..." if len(detector.description) > 60 else detector.description,
            severity_str,
            category,
            stability
        ]
        
        if show_metadata:
            maturity = getattr(detector, 'maturity', 'alpha')
            requires_slither = "✓" if getattr(detector, 'requires_slither', False) else "✗"
            row_data.extend([maturity, requires_slither])
        
        row_data.append(enabled)
        table.add_row(*row_data)
    
    console.print(table)
    console.print(f"\n[bold green]Total detectors: {len(all_detectors)} | Enabled: {len(enabled_detectors)}[/bold green]")
    
    # Show detector warnings
    for warning in detector_warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # Show categories if requested
    if show_categories:
        categories = set()
        for detector in all_detectors:
            categories.add(getattr(detector, 'category', 'unknown'))
        
        console.print(f"\n[bold cyan]Available Categories ({len(categories)}):[/bold cyan]")
        for category in sorted(categories):
            detector_count = sum(1 for d in all_detectors if getattr(d, 'category', 'unknown') == category)
            console.print(f"  • {category} ({detector_count} detectors)")
    
    # Show correlation patterns if requested
    if show_patterns and patterns_info:
        console.print(f"\n[bold cyan]Correlation Patterns ({len(patterns_info)}):[/bold cyan]")
        for pattern in patterns_info:
            console.print(f"  • [bold]{pattern['name']}[/bold] ({pattern['kind']})")
            console.print(f"    Detectors: {', '.join(pattern['member_detectors'])}")
            console.print(f"    Notes: {pattern['notes']}")
            console.print()


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
    sarif_file: Optional[Path] = typer.Option(None, "--sarif-file", help="Write SARIF output to path"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Minimum severity to report (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
    
    # Analysis options
    llm: Optional[bool] = typer.Option(None, "--llm/--no-llm", help="Enable/disable LLM synthesis"),
    enable_correlation: Optional[bool] = typer.Option(None, "--correlation/--no-correlation", help="Enable/disable finding correlation"),
    enable_poc: Optional[bool] = typer.Option(None, "--poc/--no-poc", help="Enable/disable PoC generation"),
    poc_output_dir: Optional[Path] = typer.Option(None, "--poc-dir", help="Directory to write PoC files"),
    use_slither: Optional[bool] = typer.Option(None, "--use-slither/--no-use-slither", help="Enable/disable Slither static analysis"),
    slither_json: Optional[Path] = typer.Option(None, "--slither-json", help="Write raw Slither analysis to JSON file"),
    
    # Phase 4 analysis options
    enable_path_slicing: Optional[bool] = typer.Option(None, "--path-slicing/--no-path-slicing", help="Enable/disable path slicing analysis"),
    enable_symbolic: Optional[bool] = typer.Option(None, "--symbolic/--no-symbolic", help="Enable/disable symbolic exploration"),
    enable_scoring: Optional[bool] = typer.Option(None, "--scoring/--no-scoring", help="Enable/disable enhanced scoring"),
    symbolic_timeout: Optional[int] = typer.Option(None, "--symbolic-timeout", help="Symbolic exploration timeout per function (seconds)"),
    path_slice_max_nodes: Optional[int] = typer.Option(None, "--path-max-nodes", help="Maximum nodes in path slices"),
    
    # Phase 5 options
    enable_plugins: Optional[bool] = typer.Option(None, "--plugins/--no-plugins", help="Enable/disable plugin system"),
    enable_triage: Optional[bool] = typer.Option(None, "--triage/--no-triage", help="Enable/disable AI triage"),
    diff_base: Optional[str] = typer.Option(None, "--diff-base", help="Git ref for incremental scanning"),
    enable_incremental: Optional[bool] = typer.Option(None, "--incremental/--no-incremental", help="Enable/disable incremental scanning"),
    enable_sarif: Optional[bool] = typer.Option(None, "--sarif/--no-sarif", help="Enable/disable SARIF output"),
    
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
    
    # Phase 4 analysis overrides
    if enable_path_slicing is not None:
        config.analysis.enable_path_slicing = enable_path_slicing
    if enable_symbolic is not None:
        config.analysis.enable_symbolic_exploration = enable_symbolic
    if enable_scoring is not None:
        config.analysis.enable_scoring = enable_scoring
    if symbolic_timeout is not None:
        config.analysis.symbolic_max_time_per_function = symbolic_timeout
    if path_slice_max_nodes is not None:
        config.analysis.path_slicing_max_nodes = path_slice_max_nodes
    
    # Phase 5 overrides
    if enable_plugins is not None:
        config.plugins.enable_plugins = enable_plugins
    if enable_triage is not None:
        config.triage.enable = enable_triage
    if diff_base is not None:
        config.analysis.diff_base = diff_base
    if enable_incremental is not None:
        config.analysis.enable_incremental = enable_incremental
    if enable_sarif is not None:
        config.reporting.sarif = enable_sarif
    
    # Output overrides
    if output_json is not None:
        config.output.json_file = output_json
    if correlated_json is not None:
        config.output.correlated_json_file = correlated_json
    if sarif_file is not None:
        config.output.sarif_file = sarif_file
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
    orch = Orchestrator(enabled_detectors, config)
    raw_findings = orch.run_enhanced(context)
    
    # Show Phase 5 status if any features are enabled
    phase5_status = orch.get_phase5_status()
    if any(phase5_status.values()):
        console.print("[blue]📋 Phase 5 Features Status:[/blue]")
        for feature, enabled in phase5_status.items():
            status_icon = "✅" if enabled else "❌"
            console.print(f"  {status_icon} {feature.replace('_', ' ').title()}")
    
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
    
    # Create enhanced reporting engine
    from .core.reporting import EnhancedReportingEngine
    reporting_engine = EnhancedReportingEngine(config)
    
    # Set compiler context if available from Slither
    if config.analysis.use_slither and context.tool_artifacts.get("slither"):
        slither_result = context.tool_artifacts["slither"]
        compiler_context = {
            "solc_version": getattr(slither_result, 'solc_version', ''),
            "evm_version": getattr(slither_result, 'evm_version', ''),
            "optimizer_enabled": getattr(slither_result, 'optimization_used', False)
        }
        reporting_engine.set_compiler_context(compiler_context)
    
    # Phase 4 Analysis Pipeline
    path_slices = []
    symbolic_traces = []
    scoring_results = []
    
    # Path Slicing Analysis
    if config.analysis.enable_path_slicing and context.tool_artifacts.get("slither"):
        console.print("[yellow]🛤️  Performing path slicing analysis...[/yellow]")
        start_time = time.time()
        
        try:
            from .core.path_slicing import PathSlicer, PathSlicingConfig
            
            path_config = PathSlicingConfig(
                max_nodes=config.analysis.path_slicing_max_nodes,
                cache_dir=config.analysis.path_slicing_cache_dir
            )
            
            path_slicer = PathSlicer(path_config)
            slither_result = context.tool_artifacts["slither"]
            path_slices = path_slicer.extract_paths(slither_result)
            
            console.print(f"[green]✅ Generated {len(path_slices)} path slices[/green]")
            
        except Exception as e:
            console.print(f"[yellow]⚠️  Path slicing failed: {e}[/yellow]")
        
        reporting_engine.set_timing_metric("path_slicing_time", time.time() - start_time)
    
    # Symbolic Exploration
    if config.analysis.enable_symbolic_exploration:
        console.print("[yellow]🔍 Performing symbolic exploration...[/yellow]")
        start_time = time.time()
        
        try:
            from .core.symbolic_exploration import SymbolicExplorer, SymbolicConfig
            
            symbolic_config = SymbolicConfig(
                enable=True,
                max_time_s=config.analysis.symbolic_max_time_per_function,
                max_total_time_s=config.analysis.symbolic_max_total_time,
                max_paths=config.analysis.symbolic_max_paths,
                max_functions=config.analysis.symbolic_max_functions,
                trigger_min_severity=config.analysis.symbolic_trigger_min_severity,
                trigger_min_cluster_size=config.analysis.symbolic_trigger_min_cluster_size,
                trigger_min_significance=config.analysis.symbolic_trigger_min_significance
            )
            
            symbolic_explorer = SymbolicExplorer(symbolic_config)
            
            # Check if symbolic analysis should be triggered
            should_trigger = symbolic_explorer.should_trigger_symbolic_analysis(
                filtered_findings, correlated_findings
            )
            
            if should_trigger:
                # Collect source files
                source_files = []
                if target.is_file():
                    source_files = [target]
                else:
                    source_files = list(target.glob("**/*.sol"))
                
                symbolic_traces = symbolic_explorer.analyze_contracts(source_files)
                console.print(f"[green]✅ Generated {len(symbolic_traces)} symbolic traces[/green]")
                
                # Update budget consumption
                budget_summary = symbolic_explorer.get_budget_summary()
                reporting_engine.update_budget_consumption({
                    "symbolic_time_used": budget_summary["total_time_used"],
                    "symbolic_functions_analyzed": budget_summary["functions_analyzed"]
                })
            else:
                console.print("[blue]ℹ️  Symbolic exploration not triggered (thresholds not met)[/blue]")
        
        except Exception as e:
            console.print(f"[yellow]⚠️  Symbolic exploration failed: {e}[/yellow]")
        
        reporting_engine.set_timing_metric("symbolic_exploration_time", time.time() - start_time)
    
    # Enhanced Scoring Analysis
    if config.analysis.enable_scoring:
        console.print("[yellow]📊 Performing enhanced scoring analysis...[/yellow]")
        start_time = time.time()
        
        try:
            from .core.scoring import ScoringEngine
            
            scoring_engine = ScoringEngine()
            
            # Prepare context for scoring
            scoring_context = {
                "path_slices": [
                    {
                        "node_sequence": getattr(ps, 'node_sequence', []),
                        "has_reentrancy_guard": getattr(ps, 'has_reentrancy_guard', False),
                        "external_calls": getattr(ps, 'external_calls', []),
                        "state_modifications": getattr(ps, 'state_modifications', []),
                        "hop_count": getattr(ps, 'hop_count', 0),
                        "termination_reason": getattr(ps, 'termination_reason', '')
                    }
                    for ps in path_slices
                ],
                "symbolic_traces": [
                    {
                        "vulnerability_type": getattr(st, 'vulnerability_type', ''),
                        "exploitability_score": getattr(st, 'exploitability_score', 0.0),
                        "function_name": getattr(st, 'function_name', ''),
                        "contract_name": getattr(st, 'contract_name', '')
                    }
                    for st in symbolic_traces
                ]
            }
            
            # Score individual findings
            for finding in filtered_findings:
                scoring_result = scoring_engine.score_finding(finding, scoring_context)
                scoring_results.append(scoring_result)
                
                # Update finding with scoring results
                finding.severity = scoring_result.adjusted_severity
                finding.confidence = scoring_result.adjusted_confidence
            
            # Score correlated findings
            for corr_finding in correlated_findings:
                corr_scoring_result = scoring_engine.score_correlated_finding(corr_finding, scoring_context)
                scoring_results.append(corr_scoring_result)
                
                # Update correlated finding with scoring results
                corr_finding.primary_finding.severity = corr_scoring_result.adjusted_severity
                corr_finding.primary_finding.confidence = corr_scoring_result.adjusted_confidence
            
            console.print(f"[green]✅ Completed scoring analysis for {len(scoring_results)} items[/green]")
            
        except Exception as e:
            console.print(f"[yellow]⚠️  Scoring analysis failed: {e}[/yellow]")
        
        reporting_engine.set_timing_metric("scoring_time", time.time() - start_time)
    # Package results with enhanced metadata
    exit_code, gating_reasons, report = reporting_engine.package_results(
        raw_findings, filtered_findings, correlated_findings, enabled_detectors, 
        config_warnings + detector_warnings, path_slices, symbolic_traces, scoring_results
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
    
    # Phase 5: SARIF export
    if config.output.sarif_file or config.reporting.sarif:
        sarif_path = config.output.sarif_file or Path("vulnhuntr-results.sarif")
        orch.export_sarif(filtered_findings, sarif_path, {
            "tool_name": "vulnhuntr2",
            "start_time": report.get("metadata", {}).get("start_time"),
            "command_line": " ".join(["vulnhuntr2", "scan", str(target)])
        })
        console.print(f"[bold blue]💾 SARIF results saved to {sarif_path}[/bold blue]")
    
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