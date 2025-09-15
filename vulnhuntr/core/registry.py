from __future__ import annotations

from typing import Callable, List, Protocol, Union

# Import Finding from models to maintain compatibility
from .models import Finding


class Detector(Protocol):
    name: str
    description: str
    severity: str

    def analyze(self, path: str, content: str):
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
