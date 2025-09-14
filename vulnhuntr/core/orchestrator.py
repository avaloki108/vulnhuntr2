from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Dict, Any

from .registry import get_registered_detectors, Finding


class Orchestrator:
    """
    Simple orchestrator that:
    - Walks a target file or directory
    - Collects all *.sol files
    - Runs each registered detector
    - Returns a list of finding dicts suitable for CLI output / JSON
    """

    def __init__(self) -> None:
        self.detectors = get_registered_detectors()

    def collect_sources(self, target: Path) -> List[Path]:
        if target.is_file():
            return [target] if target.suffix.lower() == ".sol" else []
        collected: List[Path] = []
        for root, _dirs, files in os.walk(target):
            for f in files:
                if f.lower().endswith(".sol"):
                    collected.append(Path(root) / f)
        return collected

    def run(self, target: Path) -> List[Dict[str, Any]]:
        sources = self.collect_sources(target)
        all_findings: List[Dict[str, Any]] = []

        for src in sources:
            try:
                content = src.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:  # pragma: no cover - defensive
                all_findings.append(
                    {
                        "detector": "io",
                        "title": "File Read Error",
                        "file": str(src),
                        "line": 0,
                        "severity": "INFO",
                        "code": "",
                        "description": f"Could not read file: {e}",
                    }
                )
                continue

            for det in self.detectors:
                try:
                    findings: Iterable[Finding] = det.analyze(str(src), content)
                    for f in findings:
                        all_findings.append(
                            {
                                "detector": f.detector,
                                "title": f.title,
                                "file": f.file,
                                "line": f.line,
                                "severity": f.severity,
                                "code": f.code,
                                "description": f.description or "",
                            }
                        )
                except Exception as e:  # pragma: no cover - defensive
                    all_findings.append(
                        {
                            "detector": getattr(det, "name", "unknown"),
                            "title": "Detector Execution Error",
                            "file": str(src),
                            "line": 0,
                            "severity": "LOW",
                            "code": "",
                            "description": f"Detector crashed: {e}",
                        }
                    )
        return all_findings
