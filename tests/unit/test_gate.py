from __future__ import annotations

import json
from pathlib import Path

from omargate.gate import evaluate_gate
from omargate.models import GateConfig


def _write_summary(run_dir: Path, payload: dict) -> None:
    (run_dir / "PACK_SUMMARY.json").write_text(json.dumps(payload), encoding="utf-8")


def test_gate_missing_summary_blocks(tmp_path: Path) -> None:
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == "error"


def test_gate_corrupted_summary_blocks(tmp_path: Path) -> None:
    (tmp_path / "PACK_SUMMARY.json").write_text("{ not json", encoding="utf-8")
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == "error"


def test_gate_incomplete_summary_blocks(tmp_path: Path) -> None:
    _write_summary(tmp_path, {"writer_complete": False})
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == "error"


def test_gate_hash_mismatch_blocks(tmp_path: Path) -> None:
    findings = tmp_path / "FINDINGS.jsonl"
    findings.write_text("{}", encoding="utf-8")
    _write_summary(
        tmp_path,
        {
            "writer_complete": True,
            "findings_file_sha256": "deadbeef",
            "counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == "error"


def test_gate_p0_blocks_on_p1_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        {
            "writer_complete": True,
            "counts": {"P0": 1, "P1": 0, "P2": 0, "P3": 0},
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == "blocked"


def test_gate_p1_passes_on_p0_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        {
            "writer_complete": True,
            "counts": {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P0"))
    assert result.block_merge is False
    assert result.status == "passed"
