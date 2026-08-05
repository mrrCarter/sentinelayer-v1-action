from __future__ import annotations

import json
from dataclasses import dataclass

import pytest


@dataclass
class _DummyCtx:
    repo_owner: str = "acme"
    repo_name: str = "app"
    repo_full_name: str = "acme/app"
    pr_number: int | None = 123
    head_sha: str = "abc123"
    base_sha: str | None = None
    head_ref: str | None = None
    base_ref: str | None = None
    is_fork: bool = False
    fork_owner: str | None = None
    actor: str = "tester"


@pytest.mark.anyio
async def test_preflight_exit_dedupe_uploads_telemetry(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_check_dedupe(*_args, **_kwargs):
        return True, None

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    class DummyGH:
        def __init__(self, token: str, repo: str):
            self.token = token
            self.repo = repo

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om, "check_dedupe", fake_check_dedupe)
    monkeypatch.setattr(om, "_estimate_cost", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(om, "_short_circuit_mirror_prior_check_run", lambda **_kwargs: 0)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "GitHubClient", DummyGH)

    exit_code = await om.async_main()
    assert exit_code == 0

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "dedupe"
    assert payload["run"]["exit_code"] == 0
    assert payload["gate"]["preflight_exits"] == [{"reason": "dedupe", "exit_code": 0}]


@pytest.mark.anyio
async def test_analysis_exception_uploads_telemetry_before_raising(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_check_dedupe(*_args, **_kwargs):
        return False, None

    async def fake_check_rate_limits(*_args, **_kwargs):
        return True, "ok"

    async def fake_check_cost_approval(*_args, **_kwargs):
        return True, "approved"

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    class DummyGH:
        def __init__(self, token: str, repo: str):
            self.token = token
            self.repo = repo

    class DummyOrchestrator:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, **_kwargs):
            raise RuntimeError("llm fail")

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setenv("INPUT_SCAN_MODE", "deep")  # avoid diff fetch
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om, "_estimate_cost", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(om, "check_dedupe", fake_check_dedupe)
    monkeypatch.setattr(om, "check_fork_policy", lambda *_args, **_kwargs: (True, "full", "not_fork"))
    monkeypatch.setattr(om, "check_rate_limits", fake_check_rate_limits)
    monkeypatch.setattr(om, "check_cost_approval", fake_check_cost_approval)
    monkeypatch.setattr(om, "check_branch_protection", lambda *_args, **_kwargs: (True, "ok"))
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "GitHubClient", DummyGH)
    monkeypatch.setattr(om, "AnalysisOrchestrator", DummyOrchestrator)

    with pytest.raises(RuntimeError, match="llm fail"):
        await om.async_main()

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "unhandled"
    assert payload["run"]["exit_code"] == 2
    assert "analysis" in payload["errors"]
    assert "unhandled" in payload["errors"]


@pytest.mark.anyio
async def test_publish_marks_failed_required_llm_as_retryable(monkeypatch, tmp_path) -> None:
    from omargate import main as om
    from omargate.analyze.orchestrator import AnalysisResult
    from omargate.models import Counts, GateResult, GateStatus

    check_runs: list[dict] = []

    async def fake_true(*_args, **_kwargs):
        return True, "ok"

    async def fake_dedupe(*_args, **_kwargs):
        return False, None

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    async def fake_upload_telemetry_always(**_kwargs) -> None:
        return None

    class DummyGH:
        def __init__(self, token: str, repo: str):
            self.token = token
            self.repo = repo

        def create_or_update_pr_comment(self, *_args, **_kwargs) -> str:
            return "https://example.test/comment"

        def create_check_run(self, **kwargs) -> str:
            check_runs.append(kwargs)
            return "https://example.test/check"

    analysis = AnalysisResult(
        findings=[],
        quick_learn=None,
        ingest={},
        counts={"P0": 0, "P1": 0, "P2": 0, "P3": 0},
        ingest_stats={},
        deterministic_count=0,
        llm_count=0,
        llm_success=False,
        llm_usage=None,
        warnings=[],
        review_brief_path=None,
        scan_mode="deep",
        total_files_scanned=0,
        hotspots_found=[],
        llm_attempted=True,
        llm_output_valid=False,
        llm_failure_class="provider_failure",
    )

    class DummyOrchestrator:
        def __init__(self, *_args, **_kwargs):
            pass

        async def run(self, **_kwargs):
            return analysis

    def fake_write_pack_summary(*, run_dir, **_kwargs):
        path = run_dir / "PACK_SUMMARY.json"
        path.write_text(
            json.dumps({"counts": analysis.counts, "duration_ms": 1}),
            encoding="utf-8",
        )
        return path

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("INPUT_SCAN_MODE", "deep")
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_GITHUB_TOKEN", "gh_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    monkeypatch.setenv("INPUT_LLM_FAILURE_POLICY", "block")
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: _DummyCtx()))
    monkeypatch.setattr(om, "GitHubClient", DummyGH)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om, "check_dedupe", fake_dedupe)
    monkeypatch.setattr(om, "check_fork_policy", lambda *_args, **_kwargs: (True, None, "ok"))
    monkeypatch.setattr(om, "check_rate_limits", fake_true)
    monkeypatch.setattr(om, "check_cost_approval", fake_true)
    monkeypatch.setattr(om, "check_branch_protection", lambda *_args, **_kwargs: (True, "ok"))
    monkeypatch.setattr(om, "_estimate_cost", lambda **_kwargs: 0.0)
    monkeypatch.setattr(om, "AnalysisOrchestrator", DummyOrchestrator)
    monkeypatch.setattr(om, "build_codebase_snapshot", lambda _ingest: {})
    monkeypatch.setattr(om, "build_codebase_synopsis", lambda **_kwargs: "")
    monkeypatch.setattr(om, "write_codebase_ingest_artifacts", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(om, "write_pack_summary", fake_write_pack_summary)
    monkeypatch.setattr(om, "write_audit_report", lambda **_kwargs: None)
    monkeypatch.setattr(om, "write_artifact_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(om, "ensure_writable_dir", lambda _path: False)
    monkeypatch.setattr(
        om,
        "evaluate_gate",
        lambda *_args, **_kwargs: GateResult(
            status=GateStatus.BLOCKED,
            reason="Managed LLM unavailable",
            block_merge=True,
            counts=Counts(),
            dedupe_key="dedupe",
        ),
    )
    monkeypatch.setattr(om, "render_pr_comment", lambda **_kwargs: "comment")
    monkeypatch.setattr(om, "write_step_summary", lambda **_kwargs: None)
    monkeypatch.setattr(om, "_write_github_outputs", lambda **_kwargs: None)
    monkeypatch.setattr(om, "_emit_gate_annotation", lambda **_kwargs: None)
    monkeypatch.setattr(om, "_upload_telemetry_always", fake_upload_telemetry_always)

    exit_code = await om.async_main()

    assert exit_code == 1
    assert len(check_runs) == 1
    assert check_runs[0]["external_id"] is None
    assert "<!-- sentinelayer:dedupe-cacheable:false -->" in check_runs[0]["text"]


@pytest.mark.anyio
async def test_unhandled_exception_uploads_telemetry_before_raising(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "compute_idempotency_key", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        await om.async_main()

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "unhandled"
    assert payload["run"]["exit_code"] == 2
    assert "unhandled" in payload["errors"]

