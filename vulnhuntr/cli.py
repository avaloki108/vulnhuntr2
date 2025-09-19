"""
Command-line interface for the vulnhuntr2 tool.
"""

import sys
import os
from pathlib import Path
import logging
import json
from typing import List, Optional, Dict, Any, Union, Tuple

try:
    import typer  # type: ignore
    _USE_TYPER = True
except Exception:
    _USE_TYPER = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rich_print
    from rich.logging import RichHandler
    _HAS_RICH = True
except Exception:
    Console = None  # type: ignore
    Table = None  # type: ignore
    Panel = None  # type: ignore
    def rich_print(*args, **kwargs):  # type: ignore
        print(*args)
    class RichHandler:  # type: ignore
        def __init__(self, *a, **kw):
            pass
    _HAS_RICH = False

from vulnhuntr.core.registry import registry, Finding
# Lazy imports in commands to avoid heavy deps for simple invocations

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)] if _HAS_RICH else [logging.StreamHandler()],
)
logger = logging.getLogger("vulnhuntr")

console = Console() if _HAS_RICH and Console is not None else type('ConsoleStub', (), {'print': staticmethod(print)})()

if _USE_TYPER:
    app = typer.Typer(
        name="vulnhuntr",
        help="Smart contract vulnerability hunting tool",
        add_completion=False,
    )
else:
    app = None  # Fallback CLI will be used in __main__

if _USE_TYPER:
    @app.command()
    def elite(
        target: str = typer.Argument(..., help="Path to smart contract or project directory"),
        llm: str = typer.Option("all", "--llm", help="LLM provider: openai, anthropic, ollama, lmstudio, all"),
        model: Optional[str] = typer.Option(None, "--model", help="Specific model to use"),
        min_score: int = typer.Option(200, "--min-score", help="Minimum vulnerability score threshold"),
        output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results (JSON)"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
        deep_mode: bool = typer.Option(False, "--deep-mode", help="Enable deep persistence hunting"),
        api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for LLM provider"),
        api_url: Optional[str] = typer.Option(None, "--api-url", help="API URL for local LLM"),
    ):
        """
        🎯 ELITE WEB3 AUDIT - The ultimate vulnerability hunter.

        Combines Slither analysis with advanced LLM intelligence to discover
        novel, high-impact vulnerabilities worth $10k+ bug bounties.

        Operational mode: John Wick style - silent, precise, relentless.
        """
        import asyncio
        from vulnhuntr.detectors.elite_web3_detector import EliteWeb3Detector
        from vulnhuntr.core.elite_llm import LLMConfig, LLMProvider, create_default_configs

        # Configure LLM providers
        configs = []

        console.print(f"[cyan]Configuring LLM provider: {llm}[/cyan]")

        if llm == 'all':
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
            selected_model = model or 'llama3:70b'
            selected_url = api_url or 'http://localhost:11434/api/chat'
            console.print(f"[cyan]Configuring Ollama: model={selected_model}, url={selected_url}[/cyan]")
            configs.append(LLMConfig(
                provider=LLMProvider.OLLAMA,
                model=selected_model,
                api_url=selected_url
            ))
        elif llm == 'lmstudio':
            configs.append(LLMConfig(
                provider=LLMProvider.LMSTUDIO,
                model=model or 'local-model',
                api_url=api_url or 'http://localhost:1234/v1/chat/completions'
            ))

        console.print(f"[cyan]Total configs created: {len(configs)}[/cyan]")
        for config in configs:
            console.print(f"  - {config.provider.value}: {config.model}")

        if not configs:
            console.print("[red]No LLM providers configured! Set API keys or ensure local LLMs are running.[/red]")
            sys.exit(1)

        # Print banner
        if _HAS_RICH and Panel:
            console.print(Panel.fit("""
    ELITE WEB3 VULNERABILITY RESEARCH SYSTEM v4.0

    🎯 Minimum Score: (N × E × I) ≥ 200
    🤖 Multi-Agent Intelligence: 15+ Parallel Agents
    💰 Target: $10k+ Bug Bounties
    🔍 Mode: John Wick - Silent, Precise, Relentless
            """, style="bold cyan"))

        # Initialize and run detector
        detector = EliteWeb3Detector(configs)

        # Run analysis
        findings = asyncio.run(detector.analyze(target))

        # Display results
        if findings:
            console.print(f"\n[green]✅ Found {len(findings)} elite vulnerabilities![/green]")
            for finding in findings:
                console.print(f"\n[bold]{finding.title}[/bold]")
                console.print(f"File: {finding.file}")
                console.print(f"Line: {finding.line}")
                console.print(f"Severity: {finding.severity}")
                console.print(f"Category: {finding.category}")
                console.print(f"Confidence: {finding.confidence:.1%}")
                # Extract score and bounty from tags
                for tag in finding.tags:
                    if tag.startswith("score:"):
                        console.print(f"Score: {tag.split(':')[1]}")
                    elif tag.startswith("bounty:"):
                        console.print(f"Estimated Bounty: {tag.split(':')[1]}")
                console.print(f"Description: {finding.description[:200]}...")
        else:
            console.print("\n[yellow]No vulnerabilities meeting elite threshold found.[/yellow]")

        # Save output if requested
        if output:
            import json
            results = {
                "vulnerabilities": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "severity": str(f.severity),
                        "file": f.file,
                        "line": f.line,
                        "category": f.category,
                        "confidence": f.confidence,
                        "tags": f.tags
                    } for f in findings
                ]
            }
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"\nResults saved to: {output}")

    @app.command()
    def list_detectors(
        show_patterns: bool = typer.Option(False, "--show-patterns", help="Show detector patterns"),
        show_categories: bool = typer.Option(False, "--show-categories", help="Show detector categories"),
        show_metadata: bool = typer.Option(False, "--show-metadata", help="Show detector metadata"),
    ):
        """List all available vulnerability detectors."""
        # Normalize options for environments using the local Typer stub
        def _opt(v):
            return getattr(v, "default", v)
        show_patterns_val = _opt(show_patterns)
        show_categories_val = _opt(show_categories)
        show_metadata_val = _opt(show_metadata)

        # Discover all detectors first
        from vulnhuntr.core.registry import discover_detectors
        discover_detectors()
        
        if not _HAS_RICH or Console is None or Table is None:
            print("Available Detectors:")
            for name, detector_cls in registry.detectors.items():
                detector = detector_cls()
                print(f"- {detector.name}: {detector.description}")
            return

        table = Table(title="Available Vulnerability Detectors")
        
        if show_metadata_val:
            table.add_column("Name", style="cyan")
            table.add_column("Description")
            table.add_column("Severity", style="magenta")
            table.add_column("Category", style="green")
            table.add_column("Confidence", style="yellow")
        else:
            table.add_column("Name", style="cyan")
            table.add_column("Description")
            table.add_column("Severity", style="magenta")
        
        for name, detector_cls in registry.detectors.items():
            detector = detector_cls()
            
            if show_metadata_val:
                category = getattr(detector, "category", "general")
                confidence = getattr(detector, "confidence", 0.5)
                severity_str = str(detector.severity) if hasattr(detector.severity, '__str__') else detector.severity
                table.add_row(
                    detector.name,
                    detector.description,
                    severity_str,
                    category,
                    f"{confidence:.2f}"
                )
            else:
                severity_str = str(detector.severity) if hasattr(detector.severity, '__str__') else detector.severity
                table.add_row(
                    detector.name,
                    detector.description,
                    severity_str
                )
        
        console.print(table)
        
        if show_patterns_val:
            rich_print("\n[bold]Detector Patterns:[/bold]")
            for name, detector_cls in registry.detectors.items():
                detector = detector_cls()
                patterns = getattr(detector, "patterns", None)
                if patterns:
                    rich_print(f"[cyan]{name}[/cyan]:")
                    for pattern in patterns:
                        # Disable markup to safely display regex dictionaries
                        rich_print(f"  - {pattern}", markup=False)
        
        if show_categories_val:
            categories = {}
            for name, detector_cls in registry.detectors.items():
                detector = detector_cls()
                category = getattr(detector, "category", "general")
                if category not in categories:
                    categories[category] = []
                categories[category].append(detector.name)
            
            rich_print("\n[bold]Categories:[/bold]")
            for category, detectors in categories.items():
                rich_print(f"[green]{category}[/green]: {', '.join(detectors)}")

if _USE_TYPER:
    @app.command()
    def scan(
        target: str = typer.Argument(..., help="File or directory to scan"),
        json_file: Optional[str] = typer.Option(None, "--json", help="Save findings as JSON"),
        sarif_file: Optional[str] = typer.Option(None, "--sarif", help="Save findings as SARIF"),
        fail_on_findings: bool = typer.Option(False, "--fail-on-findings", help="Exit with non-zero code if findings"),
        config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Configuration file path"),
        mutation: bool = typer.Option(False, "--mutation", help="Enable mutation testing"),
        mutation_output: Optional[str] = typer.Option(None, "--mutation-output", help="Directory for mutation output"),
        llm_triage: bool = typer.Option(False, "--llm-triage", help="Enable LLM triage for findings"),
    ):
        """Scan for vulnerabilities in Solidity smart contracts."""
        # Lazy imports to keep list-detectors lightweight
        try:
            from vulnhuntr.config.settings import ConfigManager
        except Exception:
            ConfigManager = None  # type: ignore
        try:
            from vulnhuntr.core.orchestrator import scan_directory, scan_file
            _HAS_ORCH = True
        except Exception:
            _HAS_ORCH = False
        try:
            from vulnhuntr.core.mutations import create_default_engine
        except Exception:
            create_default_engine = None  # type: ignore
        
        # Load configuration (fallback to None if unavailable)
        config = None
        try:
            config_manager = ConfigManager()
            config = config_manager.load(config_file)
        except Exception:
            config = None
        
        # Initialize results
        all_findings: List[Finding] = []
        
        # Determine target type and scan
        target_path = Path(target)
        if not target_path.exists():
            rich_print(f"[bold red]Error:[/bold red] Target '{target}' does not exist.")
            sys.exit(1)
        
        rich_print(f"[bold]Scanning[/bold] {target}...")
        
        if _HAS_ORCH:
            if target_path.is_dir():
                all_findings = scan_directory(target, config=config)
            else:
                all_findings = scan_file(target, config=config)
        else:
            # Fallback: simple orchestrator using detector registry only
            from vulnhuntr.core.registry import DetectorOrchestrator
            from vulnhuntr.core.models import ScanContext
            sources: List[Path] = []
            if target_path.is_dir():
                sources = [p for p in target_path.rglob('*.sol')]
            else:
                sources = [target_path]
            ctx = ScanContext(target_path=str(target_path))
            for p in sources:
                try:
                    content = p.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    content = ''
                # minimal contract stub to satisfy legacy detectors
                ctx.contracts.append(type('ContractStub', (), {'file_path': str(p), 'source': content, 'name': p.stem}))
            orch = DetectorOrchestrator()
            all_findings = orch.run_detectors(ctx)
        
        # Apply mutation testing if enabled
        if mutation:
            rich_print("\n[bold yellow]Running mutation testing...[/bold yellow]")
        mutation_engine = create_default_engine()
        
        # Create a set of files that produced findings
        files_with_findings = {finding.file for finding in all_findings}
        
        # Generate mutations for files with findings
        mutation_findings = []
        for file_path in files_with_findings:
            try:
                rich_print(f"Generating mutations for {file_path}...")
                mutations = mutation_engine.generate_mutations(file_path, mutation_output)
                
                # For each mutation, scan the generated file
                for mutation_info in mutations:
                    if "path" in mutation_info:
                        mutation_file = mutation_info["path"]
                        rich_print(f"Scanning mutation: {mutation_info['description']}")
                        
                        # Scan the mutated file
                        findings = scan_file(mutation_file, config=config)
                        
                        # Tag findings with mutation information
                        for finding in findings:
                            finding.tags = getattr(finding, "tags", []) + ["mutation"]
                            finding.mutation_info = mutation_info
                            mutation_findings.append(finding)
            except Exception as e:
                rich_print(f"[bold red]Error in mutation testing for {file_path}:[/bold red] {str(e)}")
        
        # Add mutation findings to all findings
        if mutation_findings:
            all_findings.extend(mutation_findings)
            rich_print(f"[bold green]Found {len(mutation_findings)} issues in mutated code.[/bold green]")
        # Process findings with LLM if enabled
        if llm_triage and all_findings:
            # Lazy import to avoid hard deps for simple list-detectors
            from vulnhuntr.core.llm import create_llm_client
            rich_print("\n[bold yellow]Performing LLM triage of findings...[/bold yellow]")
            
            # Create LLM client based on configuration
            llm_client = create_llm_client(
                provider=config.llm.provider,
                api_key=config.llm.api_key,
                model=config.llm.model
            )
            
            if not llm_client.is_configured():
                rich_print("[bold red]Error:[/bold red] LLM API key not configured. Skipping triage.")
            else:
                # Process each finding
                for finding in all_findings:
                    try:
                        # Get code context for the finding
                        code_context = ""
                        if finding.file and Path(finding.file).exists():
                            with open(finding.file, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read().splitlines()
                                line_num = finding.line or 1
                                start = max(0, line_num - 5)
                                end = min(len(content), line_num + 5)
                                code_context = "\n".join(content[start:end])
                        
                        # Create context for LLM
                        context = {
                            "code_context": code_context,
                            "file": finding.file,
                            "line": finding.line
                        }
                        
                        # Get LLM analysis
                        rich_print(f"Analyzing finding: {finding.title}")
                        analysis = llm_client.analyze_finding(finding, context)
                        
                        # Attach analysis to finding
                        finding.llm_analysis = analysis
                        
                    except Exception as e:
                        rich_print(f"[bold red]Error in LLM triage for {finding.title}:[/bold red] {str(e)}")
        
        # Display results
        display_findings(all_findings)
        
        # Save results if requested
        if json_file:
            save_json(all_findings, json_file, target)
            rich_print(f"[bold green]Enhanced report saved to {json_file}[/bold green]")
        
        if sarif_file:
            from vulnhuntr.core.sarif import SarifReport
            sarif_report = SarifReport()
            sarif_report.generate(all_findings, sarif_file)
            rich_print(f"[bold green]SARIF report saved to {sarif_file}[/bold green]")
        
        # Exit with error if findings found and flag enabled
        if fail_on_findings and all_findings:
            sys.exit(1)

def display_findings(findings: List[Finding]) -> None:
    """Display findings in a table."""
    if not findings:
        rich_print("[bold green]No vulnerabilities found.[/bold green]")
        return
    
    # Group findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_by_severity = {}
    for finding in findings:
        severity = finding.severity
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding)
    
    # Display summary
    rich_print(f"\n[bold]Found {len(findings)} potential issues:[/bold]")
    for severity in sorted(findings_by_severity.keys(), key=lambda s: severity_order.get(s, 999)):
        count = len(findings_by_severity[severity])
        color = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }.get(severity, "white")
        rich_print(f"  [{color}]{severity}[/{color}]: {count}")
    
    # Display detailed findings
    table = Table(title="Vulnerability Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Detector", style="cyan")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Confidence", justify="right")
    
    for severity in sorted(findings_by_severity.keys(), key=lambda s: severity_order.get(s, 999)):
        for finding in findings_by_severity[severity]:
            severity_style = {
                "CRITICAL": "bright_red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "green"
            }.get(severity, "white")
            
            # Format file path to be shorter
            file_path = finding.file
            if file_path:
                file_path = str(Path(file_path).name)
            
            # Format confidence score
            confidence_str = "N/A"
            confidence_style = "white"
            if hasattr(finding, 'confidence') and finding.confidence is not None:
                confidence_pct = f"{finding.confidence * 100:.1f}%"
                if finding.confidence >= 0.8:
                    confidence_style = "green"
                elif finding.confidence >= 0.6:
                    confidence_style = "yellow"
                else:
                    confidence_style = "red"
                confidence_str = f"[{confidence_style}]{confidence_pct}[/{confidence_style}]"

            table.add_row(
                f"[{severity_style}]{finding.severity}[/{severity_style}]",
                finding.detector,
                finding.title,
                file_path,
                str(finding.line) if finding.line else "",
                confidence_str
            )
    
    console.print(table)
    
    # Display LLM analysis if available
    for finding in findings:
        if hasattr(finding, "llm_analysis") and finding.llm_analysis:
            analysis = finding.llm_analysis
            rich_print(f"\n[bold]LLM Analysis for {finding.title}:[/bold]")
            if "error" in analysis:
                rich_print(f"[red]Error: {analysis['error']}[/red]")
            else:
                rich_print(Panel(analysis["explanation"], 
                                title=f"[cyan]{finding.detector}[/cyan] - {finding.title}",
                                subtitle=f"Suggested severity: {analysis.get('suggested_severity', 'Unknown')}"))

def save_json(findings: List[Finding], output_path: str, target: str = None) -> None:
    """Save findings to a structured JSON file with enhanced metadata and dynamic title."""
    try:
        from vulnhuntr.core.reporting import EnhancedReportingEngine
        from vulnhuntr.config.schema import RunConfig

        # Create a minimal config for reporting
        config = RunConfig()
        if target:
            config.target_path = target

        # Initialize reporting engine
        reporting_engine = EnhancedReportingEngine(config)

        # Package results using the enhanced reporting engine
        exit_code, reasons, report = reporting_engine.package_results(
            gating_findings=findings,
            display_findings=findings,
            correlated_findings=[],
            enabled_detectors=list(registry.detectors.values()),
            warnings=[]
        )

        # Save the enhanced report
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

    except Exception as e:
        # Fall back to basic JSON format if enhanced reporting fails
        console.print(f"[yellow]Warning: Enhanced reporting failed ({e}), using basic format[/yellow]")

        # Basic metadata stub for CLI mode
        meta = {
            "version": "0.1.0",
            "total_findings": len(findings),
            "detectors_enabled": len(registry.detectors),
            "config_hash": "cli-compat",
            "gating": {"triggered": False, "reasons": []},
        }
        findings_list = []
        for finding in findings:
            # Convert finding to dictionary
            finding_dict = {
                "detector": finding.detector,
                "title": finding.title,
                "severity": str(finding.severity) if not isinstance(finding.severity, str) else finding.severity,
                "file": finding.file,
                "line": finding.line,
            }
            # Add optional attributes
            for attr in ["code", "confidence", "tags", "recommendation", "llm_analysis", "mutation_info"]:
                if hasattr(finding, attr):
                    value = getattr(finding, attr)
                    # Convert sets to lists for JSON serialization
                    if isinstance(value, set):
                        value = list(value)
                    finding_dict[attr] = value
            findings_list.append(finding_dict)
        payload = {
            "meta": meta,
            "findings": findings_list,
            "correlated_findings": [],
        }
        with open(output_path, "w") as f:
            json.dump(payload, f, indent=2)

@app.command()
def explain_finding(
    finding_id: str = typer.Argument(..., help="Finding ID or title to explain"),
    format: str = typer.Option("text", "--format", "-f", help="Output format (text, markdown)"),
    llm: bool = typer.Option(False, "--llm", help="Use LLM for detailed explanation"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Configuration file path"),
):
    """Explain a specific type of finding with remediation guidelines."""
    # Load configuration
    config_manager = ConfigManager()
    config = config_manager.load(config_file)
    
    # Find the detector
    detector_found = None
    for name, detector_cls in registry.detectors.items():
        if name == finding_id or name.startswith(finding_id):
            detector_found = detector_cls()
            break
    
    if not detector_found:
        rich_print(f"[bold red]Error:[/bold red] Finding type '{finding_id}' not found.")
        sys.exit(1)
    
    # Prepare explanation
    title = detector_found.description
    description = getattr(detector_found, "detailed_description", "No detailed description available.")
    remediation = getattr(detector_found, "remediation_advice", "No specific remediation advice available.")
    
    # Use LLM to generate detailed explanation if requested
    if llm:
        try:
            llm_client = create_llm_client(
                provider=config.llm.provider,
                api_key=config.llm.api_key,
                model=config.llm.model
            )
            
            if not llm_client.is_configured():
                rich_print("[bold red]Error:[/bold red] LLM API key not configured. Continuing without LLM.")
            else:
                # Craft prompt for explanation
                context = {
                    "code_context": "",
                    "file": "",
                    "line": 0
                }
                
                # Create a mock finding for LLM analysis
                mock_finding = Finding(
                    detector=detector_found.name,
                    title=detector_found.description,
                    severity=detector_found.severity,
                    file="",
                    line=0
                )
                
                analysis = llm_client.analyze_finding(mock_finding, context)
                if "explanation" in analysis:
                    description = analysis["explanation"]
        except Exception as e:
            rich_print(f"[bold red]Error generating LLM explanation:[/bold red] {str(e)}")
    
    # Output based on format
    if format.lower() == "markdown":
        output = f"# {title}\n\n"
        output += f"**Severity:** {detector_found.severity}\n\n"
        output += f"## Description\n\n{description}\n\n"
        output += f"## Remediation\n\n{remediation}\n"
        
        print(output)  # Plain print for markdown to avoid Rich formatting
    else:
        rich_print(f"[bold]{title}[/bold]")
        rich_print(f"Severity: [bold]{detector_found.severity}[/bold]")
        rich_print("\n[bold]Description:[/bold]")
        rich_print(description)
        rich_print("\n[bold]Remediation:[/bold]")
        rich_print(remediation)

def _fallback_main():
    # Minimal CLI for tests when Typer is unavailable
    import argparse
    from vulnhuntr.core.registry import discover_detectors, get_registered_detectors
    parser = argparse.ArgumentParser(prog="vulnhuntr")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list-detectors")
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("target")
    scan_p.add_argument("--json", dest="json_file")

    args = parser.parse_args()

    if args.cmd == "list-detectors":
        discover_detectors()
        detectors = get_registered_detectors()
        print("Available Detectors:")
        for d in detectors:
            inst = d()
            print(f"- {inst.name}: {inst.description}")
        return 0
    elif args.cmd == "scan":
        discover_detectors()
        from vulnhuntr.core.registry import DetectorOrchestrator, ScanContext
        # Build a simple scan context reading .sol files
        target = Path(args.target)
        sources = []
        if target.is_dir():
            for p in target.rglob("*.sol"):
                try:
                    sources.append((str(p), p.read_text(encoding="utf-8", errors="ignore")))
                except Exception:
                    continue
        elif target.is_file():
            sources.append((str(target), target.read_text(encoding="utf-8", errors="ignore")))
        ctx = ScanContext(target_path=str(target))
        # Populate minimal contracts list for legacy detectors
        ctx.contracts = []
        for path, content in sources:
            ctx.contracts.append(type("ContractStub", (), {"file_path": path, "source": content, "name": Path(path).stem}))
        orch = DetectorOrchestrator()
        findings = orch.run_detectors(ctx)
        if args.json_file:
            save_json(findings, args.json_file)
        return 0
    else:
        parser.print_help()
        return 2


def main():
    """Entry point for the vulnhuntr CLI."""
    # Delegate to Typer (real or stub)
    if app is not None:
        app()
    else:
        # Fallback parser when Typer is truly unavailable
        sys.exit(_fallback_main())

if __name__ == "__main__":
    main()
