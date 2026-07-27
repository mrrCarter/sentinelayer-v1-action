"""Reusable analysis primitives.

Runtime orchestration belongs to the action bridge and is intentionally not imported
here. Keeping this package side-effect free prevents an import from selecting a gate.
"""

from .deterministic.config_scanner import ConfigScanner
from .deterministic.eng_quality_scanner import EngQualityScanner
from .deterministic.pattern_scanner import Finding, PatternScanner
from .deterministic.secret_scanner import calculate_entropy, scan_for_secrets

__all__ = [
    "ConfigScanner",
    "EngQualityScanner",
    "Finding",
    "PatternScanner",
    "calculate_entropy",
    "scan_for_secrets",
]
