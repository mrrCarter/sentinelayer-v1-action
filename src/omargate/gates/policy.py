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

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

from ..path_safety import EXCLUDED_PATH_PREFIXES
from . import GateContext, GateResult
from .findings import Finding, Severity

__all__ = [
    "GateToggle",
    "GateTogglesConfig",
    "ForbidPattern",
    "PermissionBehavior",
    "PolicyConfig",
    "DEFAULT_POLICY",
    "PolicyLoadError",
    "PolicyGate",
    "SCHEMA_VERSION",
    "load_policy",
    "parse_policy",
]

PermissionBehavior = Literal["allow", "deny", "ask"]
"""3-state policy decision: allow (warn-or-pass), deny (block merge), ask (annotate but non-blocking).

Lifted from src/utils/permissions/PermissionRule.ts allow/deny/ask semantics.
"ask" lets policy authors say "annotate test fixture files but don't block the gate"
without disabling the rule entirely.
"""

SCHEMA_VERSION = 1


class PolicyLoadError(Exception):
    """Raised when policy loading fails (file IO, parse error, schema mismatch)."""


@dataclass(frozen=True)
class GateToggle:
    """Per-gate enable/disable flag + 3-state behavior + optional config bag.

    behavior: 3-state allow/deny/ask. Default "deny" preserves the original
    pre-2026-04 semantic where every enabled gate blocked merge on findings.

    hard: DEPRECATED — kept for back-compat with policy.yaml files that predate
    the `behavior` field. Resolved via `_coerce_toggle_behavior` at parse time:
    explicit `behavior` wins; else `hard=True` → "deny", `hard=False` → "allow".
    The two fields are kept in sync after parsing so downstream code that still
    reads `.hard` remains correct.
    """

    enabled: bool = True
    hard: bool = True
    behavior: PermissionBehavior = "deny"
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateTogglesConfig:
    """Toggles for the 7 Omar Gate layers."""

    ownership: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=False, hard=True, behavior="deny")
    )
    locks: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=False, hard=True, behavior="deny")
    )
    static_analysis: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=True, hard=True, behavior="deny")
    )
    security: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=True, hard=True, behavior="deny")
    )
    policy: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=False, hard=True, behavior="deny")
    )
    scoped_tests: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=False, hard=True, behavior="deny")
    )
    llm_judge: GateToggle = field(
        default_factory=lambda: GateToggle(enabled=False, hard=False, behavior="allow")
    )


@dataclass(frozen=True)
class ForbidPattern:
    """A single forbid-pattern row for the policy-check layer.

    behavior: 3-state allow/deny/ask. Default "deny" preserves prior
    block-on-match semantic; "ask" emits a non-blocking annotation.
    """

    pattern: str
    severity: str = "P2"
    message: str = ""
    in_glob: str | None = None  # Optional file-glob filter (e.g. "*.ts")
    behavior: PermissionBehavior = "deny"


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

_GATE_ID_ALIASES = {
    "security_scan": "security",
    "security": "security",
    "static": "static_analysis",
    "static_analysis": "static_analysis",
}

_SCAN_EXCLUDED_PREFIXES = EXCLUDED_PATH_PREFIXES | frozenset(
    {
        ".omargate",
        ".sentinelayer",
    }
)

_MAX_POLICY_FILE_BYTES = 1_000_000
_MAX_POLICY_PATTERN_CHARS = 500
_REGEX_QUANTIFIER = r"(?:[*+]|\{\d+(?:,\d*)?\})"
_UNSAFE_NESTED_QUANTIFIER_RE = re.compile(
    rf"\((?:\?:|\?P<[^>]+>)?(?:(?:\\.)|[^()])*{_REGEX_QUANTIFIER}"
    rf"(?:(?:\\.)|[^()])*\)\s*{_REGEX_QUANTIFIER}"
)
_UNSAFE_QUANTIFIED_BRANCH_RE = re.compile(
    rf"\((?:\?:|\?P<[^>]+>)?(?:(?:\\.)|[^()])*\|"
    rf"(?:(?:\\.)|[^()])*\)\s*{_REGEX_QUANTIFIER}"
)
_BACKREFERENCE_RE = re.compile(r"(?:\\[1-9]|\(\?P=)")


# ---------- parsers ----------


def _coerce_behavior(value: Any, fallback: PermissionBehavior) -> PermissionBehavior:
    """Normalize a `behavior` field to the 3-state literal, falling back on garbage input.

    Accepts str (any case, with whitespace). Anything else / unknown values fall
    back to the caller's default — keeps loading lenient per SCHEMA_VERSION 1's
    "preserve-unknown" stance.
    """
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("allow", "deny", "ask"):
            return v  # type: ignore[return-value]
    return fallback


def _resolve_toggle_behavior(
    raw: dict[str, Any], default: GateToggle
) -> tuple[bool, PermissionBehavior]:
    """Compute (hard, behavior) from raw policy with back-compat precedence.

    Precedence:
        1. explicit `behavior` field wins (and `hard` is derived to stay in sync)
        2. else legacy `hard: bool` is converted (True→deny, False→allow)
        3. else fall back to the gate's default
    """
    behavior_raw = raw.get("behavior")
    hard_raw = raw.get("hard")
    if behavior_raw is not None:
        behavior = _coerce_behavior(behavior_raw, default.behavior)
        return (behavior == "deny", behavior)
    if hard_raw is not None:
        hard = bool(hard_raw)
        return (hard, "deny" if hard else "allow")
    return (default.hard, default.behavior)


def _parse_gate_toggle(raw: Any, default: GateToggle) -> GateToggle:
    if not isinstance(raw, dict):
        return default
    hard, behavior = _resolve_toggle_behavior(raw, default)
    return GateToggle(
        enabled=bool(raw.get("enabled", default.enabled)),
        hard=hard,
        behavior=behavior,
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
        gate_id = _GATE_ID_ALIASES.get(gate_id, gate_id)
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
                behavior=_coerce_behavior(entry.get("behavior"), "deny"),
            )
        )
    return tuple(out)


def _parse_severity_tuple(raw: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return default
    cleaned = tuple(str(s).strip().upper() for s in raw if str(s).strip())
    return cleaned or default


def _policy_block(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the effective policy gate config from either supported schema shape.

    The spec sample stores policy rows under `gates[].config` for the `policy`
    gate. Earlier action-local tests used a top-level `policy:` block. Support
    both, with the explicit gate config taking precedence when keys overlap.
    """
    top_level = raw.get("policy") if isinstance(raw.get("policy"), dict) else {}
    gate_config: dict[str, Any] = {}
    gates = raw.get("gates")
    if isinstance(gates, list):
        for entry in gates:
            if not isinstance(entry, dict):
                continue
            gate_id = str(entry.get("id", "")).strip().replace("-", "_")
            gate_id = _GATE_ID_ALIASES.get(gate_id, gate_id)
            if gate_id != "policy":
                continue
            config = entry.get("config")
            if isinstance(config, dict):
                gate_config = config
            break
    return {**top_level, **gate_config}


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

    policy_block = _policy_block(raw)
    sev_gate = raw.get("severity_gate") if isinstance(raw.get("severity_gate"), dict) else {}
    return PolicyConfig(
        version=version,
        spec_id=str(raw["spec_id"]).strip() if raw.get("spec_id") else None,
        spec_hash_auto_discover=bool(raw.get("spec_hash_auto_discover", True)),
        gates=_parse_gates(raw.get("gates")),
        forbid_patterns=_parse_forbid_patterns(policy_block.get("forbid_patterns")),
        coverage_min=_parse_coverage_min(policy_block),
        severity_block_list=_parse_severity_tuple(sev_gate.get("block_on"), ("P0", "P1")),
        severity_warn_list=_parse_severity_tuple(sev_gate.get("soft_warn"), ("P2",)),
        raw=dict(raw),
    )


def _parse_coverage_min(policy_block: dict[str, Any]) -> float | None:
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


# ---------- policy gate ----------


class PolicyGate:
    """Evaluate policy.yaml forbid-pattern rows against repository text files."""

    gate_id = "policy"

    def __init__(
        self,
        policy: PolicyConfig,
        *,
        policy_path: Path | None = None,
    ) -> None:
        self._policy = policy
        self._policy_path = policy_path

    def run(self, ctx: GateContext) -> GateResult:
        findings: list[Finding] = []
        patterns = list(self._policy.forbid_patterns)

        compiled: list[
            tuple[int, ForbidPattern, re.Pattern[str] | None, str | None, str | None]
        ] = []
        for idx, pattern in enumerate(patterns, start=1):
            unsafe_reason = _unsafe_forbid_pattern_reason(pattern.pattern)
            if unsafe_reason is not None:
                compiled.append((idx, pattern, None, unsafe_reason, "unsafe-regex"))
                continue
            try:
                compiled.append((idx, pattern, re.compile(pattern.pattern), None, None))
            except re.error as exc:
                compiled.append((idx, pattern, None, str(exc), "invalid-regex"))

        policy_file = _policy_path_for_finding(ctx.repo_root, self._policy_path)
        for idx, pattern, regex, error, error_kind in compiled:
            if error is not None:
                is_unsafe = error_kind == "unsafe-regex"
                findings.append(
                    Finding(
                        gate_id=self.gate_id,
                        tool="forbid-patterns",
                        severity="P1",
                        file=policy_file,
                        line=0,
                        title=(
                            "Unsafe policy forbid pattern"
                            if is_unsafe
                            else "Invalid policy forbid pattern"
                        ),
                        description=(
                            f"Pattern {idx} was rejected before scanning: {error}"
                            if is_unsafe
                            else f"Pattern {idx} failed to compile: {error}"
                        ),
                        rule_id=f"policy:forbid-pattern:{idx}:{error_kind or 'invalid-regex'}",
                        decision="deny",
                    )
                )
                continue
            if regex is None:
                continue
            findings.extend(_scan_for_pattern(ctx.repo_root, idx, pattern, regex))

        return GateResult(
            gate_id=self.gate_id,
            findings=findings,
            status="ok",
            metadata={
                "forbid_patterns": len(patterns),
                "policy_path": str(self._policy_path) if self._policy_path else None,
                "coverage_min": self._policy.coverage_min,
            },
        )


def _policy_path_for_finding(repo_root: Path, policy_path: Path | None) -> str:
    if policy_path is None:
        return ".sentinelayer/policy.yaml"
    try:
        return policy_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return policy_path.as_posix()


def _unsafe_forbid_pattern_reason(pattern: str) -> str | None:
    """Reject regex shapes that can catastrophically backtrack in CI.

    Python's stdlib `re` has no per-match timeout. Policy files may be
    auto-discovered from PR-controlled content, so this gate must reject risky
    patterns before scanning repository text. This conservative guard favors
    explicit deny findings over a hung runner.
    """
    if len(pattern) > _MAX_POLICY_PATTERN_CHARS:
        return (
            f"pattern length {len(pattern)} exceeds "
            f"{_MAX_POLICY_PATTERN_CHARS} characters"
        )
    if _BACKREFERENCE_RE.search(pattern):
        return "backreferences are not allowed in policy forbid patterns"
    if _has_complex_quantified_group(pattern):
        return (
            "quantified groups containing nested groups, quantifiers, or "
            "alternation are not allowed in policy forbid patterns"
        )
    if _UNSAFE_NESTED_QUANTIFIER_RE.search(pattern):
        return "nested quantified groups are not allowed in policy forbid patterns"
    if _UNSAFE_QUANTIFIED_BRANCH_RE.search(pattern):
        return "quantified alternation groups are not allowed in policy forbid patterns"
    return None


def _has_complex_quantified_group(pattern: str) -> bool:
    """Return True when a quantified group has a risky internal shape.

    A wrapper like `((a+))+$` is the same ReDoS class as `(a+)+$`, but shallow
    regex heuristics miss it. This lightweight scanner tracks escaped chars
    and character classes, then conservatively rejects quantified groups whose
    body contains another group, a quantifier, or alternation.
    """
    stack: list[int] = []
    escaped = False
    in_class = False
    idx = 0
    while idx < len(pattern):
        ch = pattern[idx]
        if escaped:
            escaped = False
            idx += 1
            continue
        if ch == "\\":
            escaped = True
            idx += 1
            continue
        if ch == "[":
            in_class = True
            idx += 1
            continue
        if ch == "]" and in_class:
            in_class = False
            idx += 1
            continue
        if in_class:
            idx += 1
            continue
        if ch == "(":
            stack.append(idx)
        elif ch == ")" and stack:
            start = stack.pop()
            body = pattern[start + 1 : idx]
            if _next_token_is_quantifier(pattern, idx + 1) and _group_body_is_complex(body):
                return True
        idx += 1
    return False


def _next_token_is_quantifier(pattern: str, start: int) -> bool:
    if start >= len(pattern):
        return False
    ch = pattern[start]
    if ch in {"*", "+"}:
        return True
    if ch == "{":
        close = pattern.find("}", start + 1)
        if close == -1:
            return False
        body = pattern[start + 1 : close]
        if not body:
            return False
        left, sep, right = body.partition(",")
        return left.isdigit() and (not sep or not right or right.isdigit())
    return False


def _group_body_is_complex(body: str) -> bool:
    escaped = False
    in_class = False
    idx = 0
    while idx < len(body):
        ch = body[idx]
        if escaped:
            escaped = False
            idx += 1
            continue
        if ch == "\\":
            escaped = True
            idx += 1
            continue
        if ch == "[":
            in_class = True
            idx += 1
            continue
        if ch == "]" and in_class:
            in_class = False
            idx += 1
            continue
        if in_class:
            idx += 1
            continue
        if ch in {"(", ")", "|", "*", "+"}:
            return True
        if _next_token_is_quantifier(body, idx):
            return True
        idx += 1
    return False


def _scan_for_pattern(
    repo_root: Path,
    idx: int,
    pattern: ForbidPattern,
    regex: re.Pattern[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_policy_scan_files(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        if pattern.in_glob and not _glob_matches(rel, pattern.in_glob):
            continue
        try:
            if path.stat().st_size > _MAX_POLICY_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not regex.search(line):
                continue
            findings.append(
                Finding(
                    gate_id="policy",
                    tool="forbid-patterns",
                    severity=_normalize_severity(pattern.severity),
                    file=rel,
                    line=line_no,
                    title=pattern.message or "Forbidden policy pattern matched",
                    description=f"Configured forbid pattern matched: {pattern.pattern}",
                    rule_id=f"policy:forbid-pattern:{idx}",
                    evidence=line.strip()[:240],
                    decision=pattern.behavior,
                )
            )
    return findings


def _iter_policy_scan_files(repo_root: Path) -> Iterable[Path]:
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(repo_root).parts
        if any(part in _SCAN_EXCLUDED_PREFIXES for part in rel_parts):
            continue
        yield path


def _glob_matches(rel: str, pattern: str) -> bool:
    return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(Path(rel).name, pattern)


def _normalize_severity(value: str) -> Severity:
    upper = str(value or "P2").strip().upper()
    if upper in {"P0", "P1", "P2", "P3"}:
        return upper  # type: ignore[return-value]
    return "P2"
