from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .models import Counts, GateConfig, GateResult, GateStatus
from .utils import sha256_file

def _resolve_summary_path(run_dir_or_summary: Path) -> Path:
    if run_dir_or_summary.is_dir():
        return run_dir_or_summary / "PACK_SUMMARY.json"
    return run_dir_or_summary


def _validate_pack_summary(summary_path: Path) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """Validate PACK_SUMMARY.json integrity."""
    if not summary_path.exists():
        return False, "FAIL-CLOSED: PACK_SUMMARY.json missing. Run did not complete.", None

    try:
        summary: Dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"FAIL-CLOSED: PACK_SUMMARY.json corrupted ({exc}).", None

    if not summary.get("writer_complete", False):
        return (
            False,
            "FAIL-CLOSED: Run did not complete (writer_complete=false).",
            None,
        )

    required_fields = ["run_id", "counts", "findings_file", "findings_file_sha256"]
    missing = [field for field in required_fields if field not in summary]
    if missing:
        return False, f"FAIL-CLOSED: Missing fields: {missing}.", None

    counts = summary.get("counts")
    if not isinstance(counts, dict):
        return False, "FAIL-CLOSED: counts must be an object.", None
    missing_counts = [sev for sev in ("P0", "P1", "P2", "P3") if sev not in counts]
    if missing_counts:
        return False, f"FAIL-CLOSED: counts missing severities: {missing_counts}.", None

    findings_file = summary.get("findings_file")
    findings_path = summary_path.parent / findings_file
    if not findings_path.exists():
        return False, f"FAIL-CLOSED: Findings file missing: {findings_file}.", None

    expected_hash = summary.get("findings_file_sha256")
    if not expected_hash:
        return False, "FAIL-CLOSED: findings_file_sha256 missing.", None

    actual_hash = sha256_file(findings_path)
    if actual_hash != expected_hash:
        return (
            False,
            "FAIL-CLOSED: Findings file hash mismatch (tampering or corruption).",
            None,
        )

    return True, None, summary


def evaluate_gate(run_dir: Path, config: GateConfig) -> GateResult:
    """Evaluate gate decision from local artifacts only (NO network calls)."""

    summary_path = _resolve_summary_path(run_dir)
    valid, error, summary = _validate_pack_summary(summary_path)
    if not valid:
        return GateResult(
            status=GateStatus.ERROR,
            reason=error or "FAIL-CLOSED: PACK_SUMMARY.json invalid.",
            block_merge=True,
            counts=Counts(),
        )

    counts = Counts(
        p0=int(summary.get("counts", {}).get("P0", 0)),
        p1=int(summary.get("counts", {}).get("P1", 0)),
        p2=int(summary.get("counts", {}).get("P2", 0)),
        p3=int(summary.get("counts", {}).get("P3", 0)),
    )
    dedupe_key = summary.get("dedupe_key")

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
            status=GateStatus.BLOCKED,
            reason=f"Found {counts.p0} P0, {counts.p1} P1 findings",
            block_merge=True,
            counts=counts,
            dedupe_key=dedupe_key,
        )
    return GateResult(
        status=GateStatus.PASSED,
        reason=f"No blocking findings (P0={counts.p0}, P1={counts.p1})",
        block_merge=False,
        counts=counts,
        dedupe_key=dedupe_key,
    )
