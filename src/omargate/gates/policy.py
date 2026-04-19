"""Policy loader for Omar Gate 2.0 (`.sentinelayer/policy.yaml` / .json).

Per CODEX_OMARGATE_COMBINE_SPEC.md §6, policy.yaml is the single source
of truth for: which gates run, what each gate's config is, forbid
patterns for the policy-check layer, severity thresholds, and LLM-judge
routing hints.

This module is the typed loader surface. Gates consume `PolicyConfig`
instead of reading raw dicts.

File format:
  - JSON always supported (stdlib).
  - YAML supported when PyYAML is installed; otherwise loading a .yaml
    / .yml path raises a clear ImportError with install instructions.

Schema validation is intentionally lenient — unknown keys are preserved
on the dataclass's `raw` field for forward-compat, but REQUIRED keys
missing → explicit error. We do not enforce a strict schema yet; the
spec is still being iterated. Breaking contract changes will bump
`SCHEMA_VERSION`.

Usage:
    config = load_policy(Path(".sentinelayer/policy.yaml"))
    if config.gates.security.enabled:
        SecurityScanGate(...).run(ctx)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "GateToggle",
    "GateTogglesConfig",
    "ForbidPattern",
    "PolicyConfig",
    "DEFAULT_POLICY",
    "PolicyLoadError",
    "SCHEMA_VERSION",
    "load_policy",
    "parse_policy",
]

SCHEMA_VERSION = 1


class PolicyLoadError(Exception):
    """Raised when policy loading fails (file IO, parse error, schema mismatch)."""


@dataclass(frozen=True)
class GateToggle:
    """Per-gate enable/disable flag + optional config bag."""

    enabled: bool = True
    hard: bool = True  # Whether this gate blocks merge on findings
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateTogglesConfig:
    """Toggles for the 7 Omar Gate layers."""

    ownership: GateToggle = field(default_factory=lambda: GateToggle(enabled=False, hard=True))
    locks: GateToggle = field(default_factory=lambda: GateToggle(enabled=False, hard=True))
    static_analysis: GateToggle = field(default_factory=lambda: GateToggle(enabled=True, hard=True))
    security: GateToggle = field(default_factory=lambda: GateToggle(enabled=True, hard=True))
    policy: GateToggle = field(default_factory=lambda: GateToggle(enabled=False, hard=True))
    scoped_tests: GateToggle = field(default_factory=lambda: GateToggle(enabled=False, hard=True))
    llm_judge: GateToggle = field(default_factory=lambda: GateToggle(enabled=False, hard=False))


@dataclass(frozen=True)
class ForbidPattern:
    """A single forbid-pattern row for the policy-check layer."""

    pattern: str
    severity: str = "P2"
    message: str = ""
    in_glob: str | None = None  # Optional file-glob filter (e.g. "*.ts")


@dataclass(frozen=True)
class PolicyConfig:
    """Parsed + validated `.sentinelayer/policy.yaml` contents."""

    version: int = SCHEMA_VERSION
    spec_id: str | None = None
    spec_hash_auto_discover: bool = True
    gates: GateTogglesConfig = field(default_factory=GateTogglesConfig)
    forbid_patterns: tuple[ForbidPattern, ...] = ()
    coverage_min: float | None = None
    severity_block_list: tuple[str, ...] = ("P0", "P1")
    severity_warn_list: tuple[str, ...] = ("P2",)
    raw: dict[str, Any] = field(default_factory=dict)


DEFAULT_POLICY = PolicyConfig()


# ---------- parsers ----------


def _parse_gate_toggle(raw: Any, default: GateToggle) -> GateToggle:
    if not isinstance(raw, dict):
        return default
    return GateToggle(
        enabled=bool(raw.get("enabled", default.enabled)),
        hard=bool(raw.get("hard", default.hard)),
        config=dict(raw.get("config") or {}),
    )


def _parse_gates(raw: Any) -> GateTogglesConfig:
    default = GateTogglesConfig()
    if not isinstance(raw, list):
        return default
    # raw is a list of {id, enabled, hard, config}
    found: dict[str, GateToggle] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        gate_id = str(entry.get("id", "")).strip().replace("-", "_")
        if not gate_id:
            continue
        default_gate = getattr(default, gate_id, None)
        if default_gate is None:
            continue  # unknown gate id — ignored for forward-compat
        found[gate_id] = _parse_gate_toggle(entry, default_gate)
    return GateTogglesConfig(
        ownership=found.get("ownership", default.ownership),
        locks=found.get("locks", default.locks),
        static_analysis=found.get("static_analysis", default.static_analysis),
        security=found.get("security", default.security),
        policy=found.get("policy", default.policy),
        scoped_tests=found.get("scoped_tests", default.scoped_tests),
        llm_judge=found.get("llm_judge", default.llm_judge),
    )


def _parse_forbid_patterns(raw: Any) -> tuple[ForbidPattern, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[ForbidPattern] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        pattern = str(entry.get("pattern", "")).strip()
        if not pattern:
            continue
        out.append(
            ForbidPattern(
                pattern=pattern,
                severity=str(entry.get("severity", "P2") or "P2").upper(),
                message=str(entry.get("message", "") or ""),
                in_glob=str(entry["in"]).strip() if entry.get("in") else None,
            )
        )
    return tuple(out)


def _parse_severity_tuple(raw: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return default
    cleaned = tuple(str(s).strip().upper() for s in raw if str(s).strip())
    return cleaned or default


def parse_policy(raw: dict[str, Any]) -> PolicyConfig:
    """Convert a parsed dict (from JSON or YAML) into a PolicyConfig.

    Unknown top-level keys are preserved on `raw` but not errored. Unknown
    values inside known keys fall back to sensible defaults.
    """
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"Policy root must be a mapping, got {type(raw).__name__}")

    version_raw = raw.get("version", SCHEMA_VERSION)
    try:
        version = int(version_raw)
    except (TypeError, ValueError):
        raise PolicyLoadError(f"Policy version must be an integer, got {version_raw!r}")

    if version > SCHEMA_VERSION:
        raise PolicyLoadError(
            f"Policy schema version {version} is newer than this runner supports "
            f"(max supported: {SCHEMA_VERSION}). Upgrade the Omar Gate action."
        )

    sev_gate = raw.get("severity_gate") if isinstance(raw.get("severity_gate"), dict) else {}
    return PolicyConfig(
        version=version,
        spec_id=str(raw["spec_id"]).strip() if raw.get("spec_id") else None,
        spec_hash_auto_discover=bool(raw.get("spec_hash_auto_discover", True)),
        gates=_parse_gates(raw.get("gates")),
        forbid_patterns=_parse_forbid_patterns(
            (raw.get("policy") or {}).get("forbid_patterns")
            if isinstance(raw.get("policy"), dict)
            else None,
        ),
        coverage_min=_parse_coverage_min(raw),
        severity_block_list=_parse_severity_tuple(sev_gate.get("block_on"), ("P0", "P1")),
        severity_warn_list=_parse_severity_tuple(sev_gate.get("soft_warn"), ("P2",)),
        raw=dict(raw),
    )


def _parse_coverage_min(raw: dict[str, Any]) -> float | None:
    policy_block = raw.get("policy")
    if not isinstance(policy_block, dict):
        return None
    value = policy_block.get("coverage_min")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------- file loader ----------


def load_policy(path: Path | str) -> PolicyConfig:
    """Read + parse a policy file. Supports .json natively, .yaml / .yml when PyYAML is available."""
    p = Path(path)
    if not p.exists():
        raise PolicyLoadError(f"Policy file not found: {p}")
    if not p.is_file():
        raise PolicyLoadError(f"Policy path is not a file: {p}")

    suffix = p.suffix.lower()
    try:
        content = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"Failed to read policy file {p}: {exc}") from exc

    if suffix in {".json"}:
        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(f"Failed to parse JSON policy {p}: {exc}") from exc
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise PolicyLoadError(
                "YAML policy files require PyYAML. Install with 'pip install pyyaml' "
                "or convert the policy to JSON (.json)."
            ) from exc
        try:
            raw = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"Failed to parse YAML policy {p}: {exc}") from exc
    else:
        raise PolicyLoadError(
            f"Unsupported policy file extension '{suffix}'. Use .json, .yaml, or .yml."
        )

    return parse_policy(raw if raw is not None else {})
