"""Executable LLM-judge local gate (#A6).

The contract in llm_judge_contract.py is intentionally pure: it filters raw
LLM-emitted finding dictionaries. This gate wires that contract into the local
runner without making provider calls. Callers provide a checked-in JSON/JSONL
findings file, usually through `.sentinelayer/policy.*`, and the gate validates
it under the security-review contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import GateContext, GateResult
from .findings import Finding
from .llm_judge_contract import FilterResult, filter_llm_findings
from .policy import PermissionBehavior

__all__ = [
    "LlmJudgeGate",
    "LlmJudgeGateConfig",
]


@dataclass(frozen=True)
class LlmJudgeGateConfig:
    """Configuration for the local LLM-judge contract gate."""

    findings_file: str = ""
    tool: str = "llm"
    behavior: PermissionBehavior = "allow"
    confidence_floor: float | None = None
    confidence_floors: dict[str, float] | None = None


class LlmJudgeGate:
    """Validate precomputed LLM findings using the A6 security-review contract."""

    gate_id = "llm_judge"

    def __init__(self, config: LlmJudgeGateConfig) -> None:
        self._config = config

    def run(self, ctx: GateContext) -> GateResult:
        raw_path = str(self._config.findings_file or "").strip()
        if not raw_path:
            return GateResult(
                gate_id=self.gate_id,
                status="skipped",
                metadata={"reason": "no findings file configured"},
            )

        resolved = _resolve_inside_repo(ctx.repo_root, raw_path)
        if resolved is None:
            return _error_result(
                raw_path,
                "LLM judge findings file must resolve inside the repository root",
            )
        if not resolved.is_file():
            return _error_result(raw_path, "LLM judge findings file not found")

        try:
            raw_findings = _load_raw_findings(resolved)
        except ValueError as exc:
            return _error_result(raw_path, str(exc))
        except OSError as exc:
            return _error_result(raw_path, f"failed to read LLM judge findings: {exc}")

        filtered = filter_llm_findings(
            raw_findings,
            gate_id=self.gate_id,
            tool=self._config.tool or "llm",
            confidence_floor=self._config.confidence_floor,
            confidence_floors=self._config.confidence_floors,
        )
        findings = [
            replace(finding, decision=self._config.behavior)
            for finding in filtered.accepted
        ]
        return GateResult(
            gate_id=self.gate_id,
            findings=findings,
            status="ok",
            metadata={
                "findings_file": raw_path,
                "accepted": len(filtered.accepted),
                "rejected": len(filtered.rejected),
                "rejections": _rejection_counts(filtered),
                "behavior": self._config.behavior,
            },
        )


def _resolve_inside_repo(repo_root: Path, raw_path: str) -> Path | None:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(repo_root.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def _load_raw_findings(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        out: list[dict[str, Any]] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_no}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"invalid JSONL at line {line_no}: expected object")
            out.append(row)
        return out

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON findings file: {exc}") from exc
    if isinstance(payload, dict):
        raw = payload.get("findings") or payload.get("Findings") or []
    else:
        raw = payload
    if not isinstance(raw, list):
        raise ValueError("LLM judge findings payload must be a list or {findings: [...]}")
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"LLM judge finding at index {idx} must be an object")
    return raw


def _error_result(raw_path: str, reason: str) -> GateResult:
    return GateResult(
        gate_id="llm_judge",
        status="error",
        error_message=reason,
        findings=[
            Finding(
                gate_id="llm_judge",
                tool="contract-loader",
                severity="P1",
                file=raw_path,
                line=0,
                title="LLM judge input could not be validated",
                description=reason,
                rule_id="llm_judge:invalid-input",
                confidence=1.0,
                decision="deny",
            )
        ],
        metadata={"reason": reason, "findings_file": raw_path},
    )


def _rejection_counts(result: FilterResult) -> dict[str, int]:
    counts = {
        "confidence": 0,
        "exclusion": 0,
        "precedent": 0,
        "category": 0,
        "schema": 0,
    }
    for rejected in result.rejected:
        if rejected.category in counts:
            counts[rejected.category] += 1
    return counts
