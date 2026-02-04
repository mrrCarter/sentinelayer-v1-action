from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import List, Dict, Any

from .models import Finding
from .utils import sha256_hex, json_dumps

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
    error: str | None = None,
) -> Path:
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
        "duration_ms": None,
        "error": error,
    }
    out = run_dir / "PACK_SUMMARY.json"
    out.write_text(json_dumps(summary), encoding="utf-8")
    return out

def new_run_dir(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
