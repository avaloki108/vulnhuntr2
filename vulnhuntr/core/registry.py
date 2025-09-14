from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Protocol, Union


@dataclass
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


def register(detector_cls: Union[type, Callable[[], Detector], Detector]):
    """
    Decorator / function to register a detector.

    Supports:
    - @register applied to a detector class (instantiated immediately)
    - Passing an instance
    - Passing a zero-arg factory callable
    """
    if isinstance(detector_cls, type):
        instance = detector_cls()  # type: ignore
        _REGISTRY.append(instance)
        return detector_cls
    if callable(detector_cls) and not hasattr(detector_cls, "analyze"):
        # factory function returning a detector
        instance = detector_cls()  # type: ignore
        _REGISTRY.append(instance)
        return detector_cls
    # assume it is already an instance
    _REGISTRY.append(detector_cls)  # type: ignore
    return detector_cls


def get_registered_detectors() -> List[Detector]:
    return list(_REGISTRY)
