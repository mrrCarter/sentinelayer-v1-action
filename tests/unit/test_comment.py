from __future__ import annotations

from omargate.comment import MARKER_PREFIX, render_pr_comment
from omargate.models import Counts, GateResult, GateStatus


def _gate_result() -> GateResult:
    return GateResult(
        status=GateStatus.PASSED,
        reason="No blocking findings",
        block_merge=False,
        counts=Counts(p0=0, p1=1, p2=2, p3=3),
        dedupe_key="dedupe-123456",
    )


def test_comment_contains_marker() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        cost_usd=1.23,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
            }
        ],
        warnings=["Sample warning"],
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
    )

    assert MARKER_PREFIX in body
    assert "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->" in body


def test_comment_contains_all_sections() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        cost_usd=1.23,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
            }
        ],
        warnings=None,
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
    )

    assert "| 🔴 P0 |" in body
    assert "### Next Steps" in body
    assert "Top Findings" in body
    assert "run_id=run-abcd" in body
