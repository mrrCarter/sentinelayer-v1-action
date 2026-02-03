from __future__ import annotations

import json
from pathlib import Path

from omargate.idempotency import compute_idempotency_key
from omargate.models import Finding
from omargate.packaging import new_run_dir, write_findings_jsonl, write_pack_summary
from omargate.utils import sha256_hex


def test_idempotency_key_is_stable() -> None:
    key1 = compute_idempotency_key(
        repo="octo/repo",
        pr_number=1,
        head_sha="abc",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )
    key2 = compute_idempotency_key(
        repo="octo/repo",
        pr_number=1,
        head_sha="abc",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )

    assert key1 == key2
    assert len(key1) == 64


def test_packaging_writes_summary(tmp_path: Path) -> None:
    run_dir = new_run_dir(tmp_path)
    findings = [
        Finding(
            finding_id="F1",
            severity="P2",
            category="test",
            file_path="file.py",
            line_start=1,
            line_end=2,
            message="msg",
            recommendation="fix",
            fingerprint="fp",
            confidence=0.9,
        )
    ]

    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, findings)
    summary_path = write_pack_summary(
        run_dir=run_dir,
        run_id=run_dir.name,
        writer_complete=True,
        findings_path=findings_path,
        counts={"P0": 0, "P1": 0, "P2": 1, "P3": 0},
        tool_versions={"action": "1.0"},
        stages_completed=["packaging"],
        error=None,
    )

    data = json.loads(summary_path.read_text(encoding="utf-8"))
    assert data["counts"]["total"] == 1
    assert data["findings_file_sha256"] == sha256_hex(findings_path.read_bytes())
