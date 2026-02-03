from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .models import Counts, GateConfig, GateResult
from .utils import sha256_file

def evaluate_gate(run_dir: Path, config: GateConfig) -> GateResult:
    """Evaluate gate decision from local artifacts only (NO network calls)."""

    summary_path = run_dir / "PACK_SUMMARY.json"
    findings_path = run_dir / "FINDINGS.jsonl"

    if not summary_path.exists():
        return GateResult(
            status="error",
            reason="FAIL-CLOSED: PACK_SUMMARY.json missing. Run did not complete.",
            block_merge=True,
            counts=Counts(),
        )

    try:
        summary: Dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return GateResult(
            status="error",
            reason="FAIL-CLOSED: PACK_SUMMARY.json corrupted.",
            block_merge=True,
            counts=Counts(),
        )

    if not summary.get("writer_complete", False):
        return GateResult(
            status="error",
            reason="FAIL-CLOSED: Run did not complete (writer_complete=false).",
            block_merge=True,
            counts=Counts(),
        )

    # Optional integrity check
    if findings_path.exists():
        expected_hash = summary.get("findings_file_sha256")
        if expected_hash:
            actual_hash = sha256_file(findings_path)
            if actual_hash != expected_hash:
                return GateResult(
                    status="error",
                    reason="FAIL-CLOSED: Findings file hash mismatch (tampering or corruption).",
                    block_merge=True,
                    counts=Counts(),
                )

    counts = Counts(
        p0=int(summary.get("counts", {}).get("P0", 0)),
        p1=int(summary.get("counts", {}).get("P1", 0)),
        p2=int(summary.get("counts", {}).get("P2", 0)),
        p3=int(summary.get("counts", {}).get("P3", 0)),
    )

    gate = config.severity_gate.upper()
    if gate == "P0":
        block = counts.p0 > 0
    elif gate == "P1":
        block = (counts.p0 + counts.p1) > 0
    elif gate == "P2":
        block = (counts.p0 + counts.p1 + counts.p2) > 0
    else:
        block = False

    if block:
        return GateResult(
            status="blocked",
            reason=f"Found {counts.p0} P0, {counts.p1} P1 findings",
            block_merge=True,
            counts=counts,
        )
    return GateResult(
        status="passed",
        reason=f"No blocking findings (P0={counts.p0}, P1={counts.p1})",
        block_merge=False,
        counts=counts,
    )
