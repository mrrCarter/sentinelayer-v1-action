from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import List, Dict, Any

from .models import Finding
from .utils import ensure_writable_dir, sha256_hex, json_dumps

def _finding_to_dict(finding: Any) -> Dict[str, Any]:
    if isinstance(finding, dict):
        return finding
    if is_dataclass(finding):
        return asdict(finding)
    return dict(getattr(finding, "__dict__", {}))


def write_findings_jsonl(path: Path, findings: List[Finding]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for finding in findings:
            payload = _finding_to_dict(finding)
            f.write(json.dumps(payload, sort_keys=True) + "\n")

def write_pack_summary(
    run_dir: Path,
    run_id: str,
    writer_complete: bool,
    findings_path: Path,
    counts: Dict[str, int],
    tool_versions: Dict[str, str],
    stages_completed: List[str],
    review_brief_path: Path | None = None,
    error: str | None = None,
    errors: List[str] | None = None,
    fingerprint_count: int | None = None,
    dedupe_key: str | None = None,
    policy_pack: str | None = None,
    policy_pack_version: str | None = None,
    duration_ms: int | None = None,
) -> Path:
    errors_list = list(errors or [])
    if error:
        errors_list.append(error)

    summary = {
        "schema_version": "1.0",
        "run_id": run_id,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "writer_complete": bool(writer_complete),
        "counts": {**counts, "total": int(sum(counts.values()))},
        "findings_file": findings_path.name,
        "findings_file_sha256": sha256_hex(findings_path.read_bytes()) if findings_path.exists() else None,
        "tool_versions": tool_versions,
        "stages_completed": stages_completed,
        "duration_ms": duration_ms,
        "artifacts": {
            "findings_jsonl": True,
            "review_brief": review_brief_path is not None,
        },
        "error": error,
        "errors": errors_list,
    }
    if fingerprint_count is not None:
        summary["fingerprint_count"] = int(fingerprint_count)
    if dedupe_key is not None:
        summary["dedupe_key"] = dedupe_key
    if policy_pack is not None:
        summary["policy_pack"] = policy_pack
    if policy_pack_version is not None:
        summary["policy_pack_version"] = policy_pack_version

    out = run_dir / "PACK_SUMMARY.json"
    out.write_text(json_dumps(summary), encoding="utf-8")
    return out

def _default_run_base() -> Path:
    """
    Get base directory for run artifacts.

    Prefer the GitHub workspace when it is writable so artifacts are available to
    later workflow steps. Fall back to /tmp if the workspace is not writable
    (common in local runners like act on Windows).
    """
    override = os.environ.get("SENTINELAYER_RUNS_DIR")
    if override:
        return Path(override)

    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        candidate = Path(workspace) / ".sentinellayer" / "runs"
        if ensure_writable_dir(candidate):
            return candidate

    return Path("/tmp/sentinellayer_runs")


def get_run_dir(run_id: str) -> Path:
    """
    Get run directory in a location that persists after container exits.

    Uses a writable $GITHUB_WORKSPACE if available (mounted volume).
    Falls back to /tmp when the workspace isn't writable.
    """
    base = _default_run_base()
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def new_run_dir(base: Path | None = None) -> Path:
    base_dir = base or _default_run_base()
    base_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    run_dir = base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
