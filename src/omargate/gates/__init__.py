"""Local gate execution for Omar Gate 2.0.

This package extracts gate execution from the backend-only bridge model
into an action-runner-local pipeline. Each gate implements the Gate
protocol and emits a list of Finding objects. run_gates() invokes a
configured sequence of gates against a shared context and aggregates
their results.

Gates added incrementally per CODEX_OMARGATE_COMBINE_SPEC.md Phase 1:
- PR #A1 (this one): package scaffold + static gate (tsc + eslint + prettier)
- PR #A2: security gate (gitleaks + semgrep + osv-scanner + actionlint + checkov + tflint)
- PR #A3: policy gate (policy.yaml forbid patterns + coverage floor)
- PR #A4: token-budget state machine integration
- PR #A5: sandbox envelope integration
- PR #A6: LLM-judge gate (security-review contract, layer 7)

This PR lands the package as pure-library. Wiring into main.py's bridge
dispatch happens in a follow-up PR so this change has zero regression
risk on the existing backend-bridge behavior.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence

from .findings import Finding

__all__ = [
    "Finding",
    "Gate",
    "GateContext",
    "GateResult",
    "run_gates",
]


@dataclass(frozen=True)
class GateContext:
    """Inputs shared across every gate in a single run."""

    repo_root: Path
    changed_files: tuple[str, ...] = ()  # paths relative to repo_root
    base_ref: str = "origin/main"
    head_ref: str = "HEAD"


@dataclass
class GateResult:
    """Output of a single gate invocation."""

    gate_id: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0
    status: str = "ok"  # "ok" | "error" | "skipped"
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Gate(Protocol):
    """Structural protocol every gate class conforms to."""

    gate_id: str

    def run(self, ctx: GateContext) -> GateResult: ...


def run_gates(
    gates: Sequence[Gate],
    ctx: GateContext,
) -> list[GateResult]:
    """Run gates sequentially against a shared context.

    An error in one gate does not short-circuit subsequent gates — each
    gate reports its own status. Callers aggregate + decide block policy.
    """
    results: list[GateResult] = []
    for gate in gates:
        started = time.perf_counter()
        gate_id = getattr(gate, "gate_id", gate.__class__.__name__)
        try:
            result = gate.run(ctx)
        except Exception as exc:  # defensive: one gate must not sink the run
            result = GateResult(
                gate_id=gate_id,
                status="error",
                error_message=f"{type(exc).__name__}: {exc}",
            )
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        results.append(result)
    return results
