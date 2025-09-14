from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, List, Iterable, Protocol

dataclass
class Finding:
    detector: str
    title: str
    file: str
    line: int
    severity: str
    code: str
    description: str | None = None

class Detector(Protocol):
    name: str
    description: str
    severity: str

    def analyze(self, path: str, content: str) -> Iterable[Finding]:
        ...

_REGISTRY: list[Detector] = []

def register(detector_cls: Callable[[], Detector] | Detector):
    """Register a detector class or instance."""
    if callable(detector_cls) and not isinstance(detector_cls, type):  # instance factory
        inst = detector_cls()  # type: ignore
        _REGISTRY.append(inst)
        return detector_cls
    if isinstance(detector_cls, type):
        inst = detector_cls()  # type: ignore
        _REGISTRY.append(inst)
        return detector_cls
    _REGISTRY.append(detector_cls)  # type: ignore
    return detector_cls

def get_registered_detectors() -> List[Detector]:
    return list(_REGISTRY)