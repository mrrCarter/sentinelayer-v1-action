from __future__ import annotations

import json
from pathlib import Path

from omargate.gate import evaluate_gate
from omargate.models import GateConfig, GateStatus
from omargate.utils import sha256_hex


def _write_summary(run_dir: Path, payload: dict) -> None:
    (run_dir / "PACK_SUMMARY.json").write_text(json.dumps(payload), encoding="utf-8")

def _write_findings(run_dir: Path, content: str = "{}") -> Path:
    findings = run_dir / "FINDINGS.jsonl"
    findings.write_text(content, encoding="utf-8")
    return findings


def _valid_summary(run_dir: Path, counts: dict) -> dict:
    findings = _write_findings(run_dir)
    return {
        "run_id": "test-run",
        "writer_complete": True,
        "counts": counts,
        "findings_file": findings.name,
        "findings_file_sha256": sha256_hex(findings.read_bytes()),
    }


def test_gate_missing_summary_blocks(tmp_path: Path) -> None:
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_corrupted_summary_blocks(tmp_path: Path) -> None:
    (tmp_path / "PACK_SUMMARY.json").write_text("{ not json", encoding="utf-8")
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_incomplete_summary_blocks(tmp_path: Path) -> None:
    _write_summary(tmp_path, {"writer_complete": False})
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_hash_mismatch_blocks(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path)
    _write_summary(
        tmp_path,
        {
            "run_id": "test-run",
            "writer_complete": True,
            "counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
            "findings_file": findings.name,
            "findings_file_sha256": "deadbeef",
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_missing_required_fields_blocks(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path)
    _write_summary(
        tmp_path,
        {
            "run_id": "test-run",
            "writer_complete": True,
            "findings_file": findings.name,
            "findings_file_sha256": sha256_hex(findings.read_bytes()),
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_p0_blocks_on_p1_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        _valid_summary(tmp_path, {"P0": 1, "P1": 0, "P2": 0, "P3": 0}),
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.BLOCKED


def test_gate_p1_passes_on_p0_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        _valid_summary(tmp_path, {"P0": 0, "P1": 1, "P2": 0, "P3": 0}),
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P0"))
    assert result.block_merge is False
    assert result.status == GateStatus.PASSED


def test_gate_sets_dedupe_key_from_summary(tmp_path: Path) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dedupe_key"] = "dedupe-xyz"
    _write_summary(tmp_path, payload)
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.dedupe_key == "dedupe-xyz"
