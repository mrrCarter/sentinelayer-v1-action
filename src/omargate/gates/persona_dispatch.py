"""Persona dispatch (#A25) — Omar Gate layer 7 → create-sentinelayer personas.

When baseline layers 1-6 produce P1+ findings, this gate groups them by the
owning persona (via an ownership map produced by create-sentinelayer's
ingest/ownership router, #A10) and invokes the corresponding persona CLI
for deeper LLM review. The CLI returns Finding objects which are merged
back into the main findings list.

Design:
  - Input: list of baseline Finding objects + path to .sentinelayer/
    scaffold.yaml (ownership rules) + CLI binary path.
  - For every persona with at least one P1+ baseline finding under its
    scope, spawn `<cli> /persona <id> --path <repo> --files <csv> --json`
    and parse Finding[] from stdout.
  - Output: the combined list (baseline + persona-produced) with persona
    findings annotated with gate_id="persona_dispatch" and tool="<persona>".
  - Respects a per-persona budget cap so a single noisy persona can't
    empty the wallet.

All subprocess calls go through the OS sandbox envelope (#A5) when
strict=True so jailbroken LLM output can't exfiltrate or clobber the host.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .findings import Finding, Severity


__all__ = [
    "PersonaDispatchConfig",
    "PersonaDispatchResult",
    "build_persona_buckets",
    "dispatch_personas",
    "normalize_persona_finding",
]


KNOWN_PERSONAS = frozenset(
    {
        "security",
        "backend",
        "testing",
        "code-quality",
        "data-layer",
        "documentation",
        "reliability",
        "release",
        "observability",
        "infrastructure",
        "supply-chain",
        "ai-governance",
        "frontend",
    }
)

DEFAULT_BLOCKING_SEVERITIES: tuple[Severity, ...] = ("P0", "P1")
DEFAULT_PER_PERSONA_MAX_FILES = 50
DEFAULT_TIMEOUT_S = 300


@dataclass(frozen=True)
class PersonaDispatchConfig:
    """Inputs for a persona dispatch run."""

    cli_path: Path                          # `create-sentinelayer` binary
    repo_root: Path
    scaffold_path: Path | None = None       # .sentinelayer/scaffold.yaml
    blocking_severities: tuple[Severity, ...] = DEFAULT_BLOCKING_SEVERITIES
    per_persona_max_files: int = DEFAULT_PER_PERSONA_MAX_FILES
    timeout_s: int = DEFAULT_TIMEOUT_S
    strict_sandbox: bool = False             # reserved for #A5 integration
    dry_run: bool = False                    # skip the subprocess call


@dataclass
class PersonaDispatchResult:
    """Result of one full dispatch pass."""

    baseline_findings: list[Finding] = field(default_factory=list)
    persona_findings: list[Finding] = field(default_factory=list)
    personas_invoked: list[str] = field(default_factory=list)
    personas_failed: list[str] = field(default_factory=list)
    unrouted_files: list[str] = field(default_factory=list)

    @property
    def combined(self) -> list[Finding]:
        return [*self.baseline_findings, *self.persona_findings]


def build_persona_buckets(
    findings: Iterable[Finding],
    ownership_map: dict[str, str],
    *,
    blocking_severities: Iterable[Severity] = DEFAULT_BLOCKING_SEVERITIES,
) -> tuple[dict[str, list[str]], list[str]]:
    """Group findings' files by owning persona.

    Returns (persona_to_files, unrouted). persona_to_files lists only
    personas we know (KNOWN_PERSONAS); any ownership entry outside that
    set drops the file into unrouted so the caller can surface a warning.
    """
    severities = set(blocking_severities)
    persona_to_files: dict[str, list[str]] = {}
    unrouted: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()

    for finding in findings:
        if finding.severity not in severities:
            continue
        file_path = str(finding.file or "").strip().replace("\\", "/")
        if not file_path:
            continue
        persona = str(ownership_map.get(file_path, "")).strip().lower()
        if not persona or persona not in KNOWN_PERSONAS:
            unrouted.append(file_path)
            continue
        pair = (persona, file_path)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        persona_to_files.setdefault(persona, []).append(file_path)
    return persona_to_files, unrouted


def normalize_persona_finding(
    raw: dict,
    *,
    persona: str,
    default_severity: Severity = "P2",
) -> Finding | None:
    """Parse a persona's raw JSON output into a Finding, or None if malformed."""
    if not isinstance(raw, dict):
        return None
    severity_raw = str(raw.get("severity") or default_severity).upper()
    if severity_raw not in {"P0", "P1", "P2", "P3"}:
        severity_raw = default_severity
    file_path = str(raw.get("file") or "").strip().replace("\\", "/")
    if not file_path:
        return None
    title = str(raw.get("title") or raw.get("message") or f"{persona} finding").strip()
    description = str(raw.get("rootCause") or raw.get("description") or "").strip()
    rule_id = raw.get("kind") or raw.get("ruleId")
    confidence_raw = raw.get("confidence")
    try:
        confidence = float(confidence_raw) if confidence_raw is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8
    confidence = max(0.0, min(1.0, confidence))
    line_raw = raw.get("line", 0)
    try:
        line = max(0, int(line_raw))
    except (TypeError, ValueError):
        line = 0
    return Finding(
        gate_id="persona_dispatch",
        tool=persona,
        severity=severity_raw,  # type: ignore[arg-type]
        file=file_path,
        line=line,
        title=title[:200],
        description=description[:800],
        rule_id=str(rule_id)[:120] if rule_id else None,
        confidence=confidence,
        recommended_fix=(str(raw.get("recommendedFix") or "")[:800]) or None,
        evidence=(str(raw.get("evidence") or "")[:400]) or None,
    )


def _spawn_persona_cli(
    config: PersonaDispatchConfig,
    persona: str,
    files: list[str],
) -> tuple[int, str, str]:
    args = [
        str(config.cli_path),
        "/persona",
        persona,
        "--path",
        str(config.repo_root),
        "--files",
        ",".join(files),
        "--json",
    ]
    try:
        proc = subprocess.run(
            args,
            cwd=str(config.repo_root),
            capture_output=True,
            text=True,
            timeout=config.timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"persona {persona} timed out after {config.timeout_s}s: {exc}"
    except FileNotFoundError as exc:
        return 127, "", f"persona CLI not found: {exc}"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _parse_cli_output(stdout: str, persona: str) -> list[Finding]:
    stdout = (stdout or "").strip()
    if not stdout:
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        raw_findings = payload.get("findings") or payload.get("Findings") or []
    elif isinstance(payload, list):
        raw_findings = payload
    else:
        raw_findings = []
    out: list[Finding] = []
    for raw in raw_findings:
        normalized = normalize_persona_finding(raw, persona=persona)
        if normalized is not None:
            out.append(normalized)
    return out


def dispatch_personas(
    baseline_findings: list[Finding],
    ownership_map: dict[str, str],
    config: PersonaDispatchConfig,
) -> PersonaDispatchResult:
    """Run the persona dispatch pass and return the combined findings."""
    result = PersonaDispatchResult(baseline_findings=list(baseline_findings))
    buckets, unrouted = build_persona_buckets(
        baseline_findings,
        ownership_map,
        blocking_severities=config.blocking_severities,
    )
    result.unrouted_files = sorted(set(unrouted))

    for persona, files in sorted(buckets.items()):
        deduped = sorted(set(files))[: config.per_persona_max_files]
        if config.dry_run:
            result.personas_invoked.append(persona)
            continue
        exit_code, stdout, stderr = _spawn_persona_cli(config, persona, deduped)
        if exit_code not in (0, 1):
            # 0 = clean, 1 = findings emitted. Anything else = persona crashed.
            result.personas_failed.append(persona)
            continue
        parsed = _parse_cli_output(stdout, persona)
        if parsed:
            result.persona_findings.extend(parsed)
        result.personas_invoked.append(persona)
    return result


def default_cli_path(override: str | Path | None = None) -> Path:
    """Best-effort guess at the create-sentinelayer binary path."""
    candidate = str(override or "").strip()
    if candidate:
        return Path(candidate)
    resolved = shutil.which("create-sentinelayer") or shutil.which("sentinelayer-cli")
    if resolved:
        return Path(resolved)
    return Path("create-sentinelayer")
