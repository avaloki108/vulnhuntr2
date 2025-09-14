"""
Command-line interface for vulnhuntr2.
"""
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import box

from .core.orchestrator import Orchestrator
from .core.registry import get_registered_detectors

app = typer.Typer(help="Mutation-driven / heuristic smart contract vulnerability hunting (prototype)")
console = Console()


@app.command()
def list_detectors():
    """List all available detectors."""
    detectors = get_registered_detectors()
    table = Table(title="Registered Detectors", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Severity", style="magenta")
    for det in detectors:
        table.add_row(det.name, det.description, det.severity)
    console.print(table)


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to analyze (Solidity)"),
    output_json: Optional[Path] = typer.Option(None, "--json", help="Write findings as JSON to path"),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings", help="Exit non-zero if any findings"),
):
    """Scan a file or directory for potential vulnerabilities (heuristic prototype)."""
    orch = Orchestrator()
    findings = orch.run(target)

    if not findings:
        console.print("[bold green]No findings detected.\n")
    else:
        console.print(f"[bold yellow]{len(findings)} findings detected:\n")
        for f in findings:
            console.print(
                f"[cyan]{f['detector']}[/cyan]: [bold]{f['title']}[/bold]\n"
                f"  File: {f['file']}  Line: {f['line']}  Severity: {f['severity']}\n"
                f"  Snippet: {f['code'].strip()}\n"
            )

    if output_json:
        import json
        output_json.write_text(json.dumps(findings, indent=2))
        console.print(f"[bold blue]JSON findings written to {output_json}")

    if fail_on_findings and findings:
        raise typer.Exit(code=1)


def main():  # pragma: no cover - entry point convenience
    app()

if __name__ == "__main__":  # pragma: no cover
    main()