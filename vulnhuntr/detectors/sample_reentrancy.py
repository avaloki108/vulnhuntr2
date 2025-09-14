from __future__ import annotations

import re
from typing import Iterable

from ..core.registry import register, Finding


@register
class ReentrancyHeuristic:
    """
    Extremely naive heuristic detector for potential reentrancy risk patterns.
    This is a placeholder example: real detectors should use proper AST parsing.
    """

    name = "reentrancy_heuristic"
    description = "Flags occurrences of low-level external calls before state updates."
    severity = "MEDIUM"

    # Simple regex indicators of an external call
    CALL_PATTERNS = [
        re.compile(r"\.call\.value\(", re.IGNORECASE),
        re.compile(r"\bcall\(", re.IGNORECASE),
        re.compile(r"\bdelegatecall\(", re.IGNORECASE),
        re.compile(r"\bcallcode\(", re.IGNORECASE),
        re.compile(r"\.send\(", re.IGNORECASE),
        re.compile(r"\.transfer\(", re.IGNORECASE),
    ]

    def analyze(self, path: str, content: str) -> Iterable[Finding]:
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pat in self.CALL_PATTERNS:
                if pat.search(stripped):
                    yield Finding(
                        detector=self.name,
                        title="Potential reentrancy-sensitive external call",
                        file=path,
                        line=idx,
                        severity=self.severity,
                        code=stripped[:300],
                        description=(
                            "External call detected. Ensure state changes occur "
                            "before external interactions and employ reentrancy guards."
                        ),
                    )
                    break
