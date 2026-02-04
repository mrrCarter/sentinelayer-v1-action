from __future__ import annotations

from pathlib import Path

import pytest

from omargate.analyze.orchestrator import AnalysisOrchestrator
from omargate.artifacts import CATEGORIES, generate_review_brief, render_review_brief
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger


def _make_ingest(paths: list[str]) -> dict:
    return {
        "stats": {"in_scope_files": len(paths)},
        "files": [
            {
                "path": path,
                "lines": 120,
                "category": "source",
                "language": "python",
                "size_bytes": 100,
                "is_hotspot": False,
                "hotspot_reasons": [],
            }
            for path in paths
        ],
        "hotspots": {key: [] for key in CATEGORIES},
    }


def _sample_findings() -> list[dict]:
    return [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth/session.py",
            "line_start": 10,
            "line_end": 12,
            "message": "Session check missing",
            "recommendation": "Add session validation",
        }
    ]


def test_review_brief_generates_markdown(tmp_path: Path) -> None:
    run_id = "run-123"
    findings = _sample_findings()
    ingest = _make_ingest(["src/auth/session.py"])

    out_path = generate_review_brief(
        run_dir=tmp_path,
        run_id=run_id,
        findings=findings,
        ingest=ingest,
        scan_mode="deep",
        version="1.0.0",
    )

    content = out_path.read_text(encoding="utf-8")
    assert out_path.name == "REVIEW_BRIEF.md"
    assert "# 🛡️ Omar Gate Review Brief" in content
    assert "## Summary" in content
    assert run_id in content


def test_review_brief_ranks_p0_first() -> None:
    findings = [
        {
            "severity": "P0",
            "category": "auth",
            "file_path": "src/auth/critical.py",
            "line_start": 1,
            "line_end": 2,
            "message": "Critical auth bypass",
            "recommendation": "Fix auth guard",
        },
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth/normal.py",
            "line_start": 5,
            "line_end": 6,
            "message": "Auth issue",
            "recommendation": "Fix",
        },
    ]
    ingest = _make_ingest(["src/auth/critical.py", "src/auth/normal.py"])

    content = render_review_brief(
        run_id="run-456",
        findings=findings,
        ingest=ingest,
        scan_mode="deep",
        version="1.0.0",
    )

    start = content.index("## Risk Hotspots")
    end = content.index("## Suggested Review Order")
    risk_section = content[start:end]
    critical_index = risk_section.index("`src/auth/critical.py`")
    normal_index = risk_section.index("`src/auth/normal.py`")
    assert critical_index < normal_index


def test_review_brief_detects_categories() -> None:
    findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth/session.py",
            "line_start": 10,
            "line_end": 12,
            "message": "Auth issue",
            "recommendation": "Fix auth",
        },
        {
            "severity": "P2",
            "category": "payment",
            "file_path": "src/billing/stripe.py",
            "line_start": 5,
            "line_end": 6,
            "message": "Payment issue",
            "recommendation": "Fix payment",
        },
    ]
    ingest = _make_ingest(["src/auth/session.py", "src/billing/stripe.py"])

    content = render_review_brief(
        run_id="run-789",
        findings=findings,
        ingest=ingest,
        scan_mode="deep",
        version="1.0.0",
    )

    assert "🔐 Auth & Session" in content
    assert "💳 Payment & Billing" in content


def test_review_brief_no_persona_names() -> None:
    content = render_review_brief(
        run_id="run-000",
        findings=_sample_findings(),
        ingest=_make_ingest(["src/auth/session.py"]),
        scan_mode="deep",
        version="1.0.0",
    )

    lowered = content.lower()
    assert "maya" not in lowered
    assert "nina" not in lowered
    assert "persona" not in lowered


@pytest.mark.anyio
async def test_review_brief_failure_non_gating(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk-test")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")

    def fake_ingest(*_args, **_kwargs) -> dict:
        return _make_ingest(["src/app.py"])

    def fake_scans(_self, _ingest) -> list[dict]:
        return []

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("omargate.analyze.orchestrator.run_ingest", fake_ingest)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", fake_scans)
    monkeypatch.setattr("omargate.analyze.orchestrator.generate_review_brief", boom)

    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=False,
    )

    result = await orchestrator.run(
        scan_mode="deep",
        run_dir=tmp_path,
        run_id="run-brief-fail",
        version="1.0.0",
    )

    assert result.review_brief_path is None
    assert any("Review brief generation failed" in warning for warning in result.warnings)
