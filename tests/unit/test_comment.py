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
        estimated_cost_usd=0.0032,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
                "fix_plan": "Pseudo-code: escape untrusted output before rendering and add an XSS regression test.",
            }
        ],
        warnings=["Sample warning"],
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        severity_gate="P1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
        llm_engine="openai",
        llm_model="gpt-4o",
        actual_cost_usd=0.05,
        head_sha="deadbeef",
        server_url="https://github.com",
    )

    assert MARKER_PREFIX in body
    assert "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->" in body
    assert "Cost (est.):** `$0.0032`" in body
    assert "**Fix:**" in body
    assert "Apply Fix:** Coming soon." in body


def test_comment_contains_all_sections() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        estimated_cost_usd=1.23,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
                "fix_plan": "Pseudo-code: escape untrusted output before rendering.",
            }
        ],
        warnings=None,
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        severity_gate="P1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
    )

    assert "| Severity | Count | Blocks Merge? |" in body
    assert "### Next Steps" in body
    assert "Top Findings" in body
    assert "**Fix:**" in body
    assert "run_id=run-abcd" in body
    assert "Artifacts & Full Report" in body


def test_comment_footer_shows_llm_model() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.05,
        version="1.2.0",
        deterministic_count=10,
        llm_count=3,
        dedupe_key="dedupe-123456",
        llm_engine="openai",
        llm_model="gpt-4o",
    )

    assert "**LLM:** `openai` (`gpt-4o`)" in body
    assert "raw_findings(det=10, llm=3)" in body


def test_comment_footer_default_model_none() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=None,
        version="1.2.0",
    )

    assert "**LLM:** `disabled` (`n/a`)" in body


def test_comment_renders_codebase_synopsis() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.01,
        version="1.2.0",
        codebase_snapshot={
            "stats": {"in_scope_files": 10, "source_loc_total": 1000},
            "languages": [{"language": "python", "files": 8, "loc": 900}],
            "hotspots": [],
        },
        codebase_synopsis="README: Deterministic gate for CI pipelines.",
    )

    assert "Codebase Synopsis" in body
    assert "README: Deterministic gate for CI pipelines." in body
