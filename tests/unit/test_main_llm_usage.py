from __future__ import annotations

from types import SimpleNamespace

from omargate.config import OmarGateConfig
from omargate.main import _build_llm_evidence, _llm_fallback_used
from omargate.models import Counts, GateResult, GateStatus
from omargate.telemetry_runtime import _write_github_outputs


def test_llm_fallback_used_detects_configured_fallback_model() -> None:
    assert _llm_fallback_used(
        {"model": "gemini-2.5-flash"},
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_detects_managed_capacity_route() -> None:
    assert _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "managed_after_byo_capacity",
        },
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_ignores_primary_byo_route() -> None:
    assert not _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "byo",
        },
        model_fallback="gemini-2.5-flash",
    )


def test_build_llm_evidence_records_successful_codex_contract() -> None:
    analysis = SimpleNamespace(
        llm_usage={
            "engine": "codex",
            "provider": "openai",
            "model": "gpt-5.3-codex",
            "tokens_in": None,
            "tokens_out": None,
            "cost_usd": None,
            "latency_ms": 125,
        },
        llm_attempted=True,
        llm_success=True,
        llm_output_valid=True,
        llm_no_findings_reported=True,
        llm_reported_finding_count=0,
        llm_count=0,
        llm_parse_error_count=0,
        llm_failure_class=None,
    )

    evidence = _build_llm_evidence(
        analysis,
        OmarGateConfig(openai_api_key="sk_test_dummy"),
    )

    assert evidence == {
        "schema_version": "1.0",
        "attempted": True,
        "success": True,
        "output_valid": True,
        "no_findings_reported": True,
        "reported_finding_count": 0,
        "accepted_finding_count": 0,
        "parse_error_count": 0,
        "failure_class": None,
        "usage_recorded": True,
        "engine": "codex",
        "provider": "openai",
        "model": "gpt-5.3-codex",
        "route": None,
        "tokens_in": None,
        "tokens_out": None,
        "latency_ms": 125,
        "fallback_used": False,
    }


def test_build_llm_evidence_preserves_failed_attempt_metadata() -> None:
    analysis = SimpleNamespace(
        llm_usage={
            "provider": "openai",
            "model": "gpt-5.3-codex",
            "latency_ms": 25,
            "route": "managed_after_byo_capacity_failed",
        },
        llm_attempted=True,
        llm_success=False,
        llm_output_valid=False,
        llm_no_findings_reported=False,
        llm_reported_finding_count=0,
        llm_count=1,
        llm_parse_error_count=0,
        llm_failure_class="provider_failure",
    )

    evidence = _build_llm_evidence(
        analysis,
        OmarGateConfig(openai_api_key="sk_test_dummy"),
    )

    assert evidence["success"] is False
    assert evidence["output_valid"] is False
    assert evidence["failure_class"] == "provider_failure"
    assert evidence["usage_recorded"] is True
    assert evidence["model"] == "gpt-5.3-codex"
    assert evidence["fallback_used"] is True


def test_github_outputs_expose_live_llm_evidence(tmp_path, monkeypatch) -> None:
    findings_path = tmp_path / "FINDINGS.jsonl"
    pack_summary_path = tmp_path / "PACK_SUMMARY.json"
    output_path = tmp_path / "github-output.txt"
    findings_path.write_text("", encoding="utf-8")
    pack_summary_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    _write_github_outputs(
        run_id="test-run",
        idem_key="idem",
        findings_path=findings_path,
        pack_summary_path=pack_summary_path,
        gate_result=GateResult(
            status=GateStatus.ERROR,
            reason="live LLM failed",
            block_merge=True,
            counts=Counts(p0=1),
        ),
        llm_attempted=True,
        llm_success=False,
        llm_output_valid=False,
        llm_no_findings_reported=False,
        llm_findings_count=0,
        llm_parse_error_count=2,
        llm_failure_class="invalid_output",
    )

    output = output_path.read_text(encoding="utf-8")
    assert "llm_attempted=true\n" in output
    assert "llm_success=false\n" in output
    assert "llm_output_valid=false\n" in output
    assert "llm_no_findings_reported=false\n" in output
    assert "llm_findings_count=0\n" in output
    assert "llm_parse_error_count=2\n" in output
    assert "llm_failure_class=invalid_output\n" in output
