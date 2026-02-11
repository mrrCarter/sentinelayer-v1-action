from __future__ import annotations

from pathlib import Path

import pytest

from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger


def _orchestrator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AnalysisOrchestrator:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    return AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=False,
    )


def test_llm_p1_without_corroboration_is_downgraded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/auth.py", "lines": 200}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 48,
            "line_end": 49,
            "message": "OAuth callback does not validate state",
            "confidence": 0.95,
            "source": "codex",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=[],
        ingest=ingest,
    )

    assert len(guarded) == 1
    assert guarded[0]["severity"] == "P2"
    assert "LLM-only" in guarded[0]["message"]


def test_llm_p1_with_corroboration_stays_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/auth.py", "lines": 200}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 50,
            "line_end": 50,
            "message": "State parameter not validated",
            "confidence": 0.9,
            "source": "codex",
        }
    ]
    deterministic_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 53,
            "line_end": 53,
            "message": "Auth flow guard missing",
            "source": "deterministic",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=deterministic_findings,
        ingest=ingest,
    )

    assert len(guarded) == 1
    assert guarded[0]["severity"] == "P1"


def test_llm_findings_for_unknown_files_are_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/known.py", "lines": 10}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "backend",
            "file_path": "src/missing.py",
            "line_start": 999,
            "message": "Missing timeout",
            "source": "llm",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=[],
        ingest=ingest,
    )

    assert guarded == []


@pytest.mark.anyio
async def test_codex_only_disables_api_fallback_on_codex_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "true")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    def _fake_det(_self, _ingest):
        return []

    async def _fake_codex(*_args, **_kwargs):
        return LLMAnalysisResult(
            findings=[],
            success=False,
            usage=None,
            warning="codex failed",
        )

    called = {"llm": False}

    async def _fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return LLMAnalysisResult(
            findings=[],
            success=True,
            usage=None,
            warning=None,
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", _fake_det)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_codex_audit", _fake_codex)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_llm)

    result = await orchestrator.run(scan_mode="deep")

    assert called["llm"] is False
    assert any("codex_only=true" in warning for warning in result.warnings)
