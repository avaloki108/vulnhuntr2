#!/usr/bin/env python3
"""
Simple CLI for vulnhuntr2 testing
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add the project to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnhuntr.core.orchestrator import scan_file, scan_directory
from vulnhuntr.config.settings import ConfigManager
from rich.console import Console
from rich.table import Table
from rich import print as rich_print

console = Console()

def display_findings(findings):
    """Display findings in a table."""
    if not findings:
        rich_print("[bold green]No vulnerabilities found.[/bold green]")
        return
    
    # Display summary
    rich_print(f"\n[bold]Found {len(findings)} potential issues:[/bold]")
    
    # Display detailed findings
    table = Table(title="Vulnerability Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Detector", style="cyan")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Line", justify="right")
    
    for finding in findings:
        severity_str = str(finding.severity) if hasattr(finding.severity, '__str__') else finding.severity
        severity_style = {
            "CRITICAL": "bright_red",
            "HIGH": "red", 
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }.get(severity_str, "white")
        
        # Format file path to be shorter
        file_path = finding.file
        if file_path:
            file_path = str(Path(file_path).name)
        
        table.add_row(
            f"[{severity_style}]{severity_str}[/{severity_style}]",
            finding.detector,
            finding.title,
            file_path,
            str(finding.line) if finding.line else ""
        )
    
    console.print(table)

def save_json_findings(findings, output_path):
    """Save findings to structured JSON."""
    data = {
        "scan_info": {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": "vulnhuntr2",
            "version": "0.1.0"
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": {}
        },
        "findings": []
    }
    
    # Count by severity
    for finding in findings:
        severity = str(finding.severity)
        data["summary"]["severity_counts"][severity] = data["summary"]["severity_counts"].get(severity, 0) + 1
    
    # Convert findings
    for finding in findings:
        finding_dict = {
            "detector": finding.detector,
            "title": finding.title,
            "description": finding.description,
            "severity": str(finding.severity),
            "file": finding.file,
            "line": finding.line,
            "code": finding.code,
            "confidence": getattr(finding, 'confidence', None),
            "category": getattr(finding, 'category', None)
        }
        data["findings"].append(finding_dict)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    if len(sys.argv) < 3:
        print("Usage: python simple_cli.py scan <target> [--json output.json]")
        return 1
    
    command = sys.argv[1]
    target = sys.argv[2]
    json_output = None
    
    # Check for --json flag
    if len(sys.argv) > 3 and sys.argv[3] == "--json" and len(sys.argv) > 4:
        json_output = sys.argv[4]
    
    if command == "scan":
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load()
        
        # Determine target type and scan
        target_path = Path(target)
        if not target_path.exists():
            rich_print(f"[bold red]Error:[/bold red] Target '{target}' does not exist.")
            return 1
        
        rich_print(f"[bold]Scanning[/bold] {target}...")
        
        try:
            if target_path.is_dir():
                all_findings = scan_directory(target, config=config)
            else:
                all_findings = scan_file(target, config=config)
            
            # Display results
            display_findings(all_findings)
            
            # Save JSON if requested
            if json_output:
                save_json_findings(all_findings, json_output)
                rich_print(f"[bold green]JSON report saved to {json_output}[/bold green]")
            
        except Exception as e:
            rich_print(f"[bold red]Error during scan:[/bold red] {str(e)}")
            import traceback
            traceback.print_exc()
            return 1
    else:
        print("Unknown command. Use 'scan'.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())