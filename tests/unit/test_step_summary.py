from __future__ import annotations

from omargate.models import Counts, GateResult, GateStatus
from omargate.publish import write_step_summary


def test_step_summary_writes_file(tmp_path, monkeypatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    gate_result = GateResult(
        status=GateStatus.PASSED,
        reason="All good",
        block_merge=False,
        counts=Counts(p0=0, p1=0, p2=1, p3=2),
        dedupe_key="dedupe-123",
    )
    summary = {"counts": {"P0": 0, "P1": 0, "P2": 1, "P3": 2}}
    findings = [
        {
            "severity": "P2",
            "file_path": "app.py",
            "line_start": 5,
            "message": "Example issue",
        }
    ]

    write_step_summary(gate_result, summary, findings, "test-run", "1.0.0")

    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "Omar Gate" in content
    assert "P0" in content
