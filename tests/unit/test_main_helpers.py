from __future__ import annotations

from types import SimpleNamespace

from omargate.main import (
    _build_dedupe_publication_contract,
    _check_name,
    _build_spec_compliance_from_findings,
    _counts_from_check_run_output,
    _exit_code_from_gate_result,
    _gate_result_from_check_run,
    _github_publish_enabled,
    _latest_completed_check_run,
    _llm_result_is_dedupe_cacheable,
    _map_category_to_spec_sections,
    _select_check_run_for_dedupe,
    _select_check_run_for_mirror,
)
from omargate.config import OmarGateConfig
from omargate.models import GateStatus
from omargate.utils import parse_iso8601


def test_parse_iso8601_handles_z_suffix() -> None:
    ts = parse_iso8601("2026-02-08T05:31:22.137538Z")
    assert ts is not None
    assert ts.tzinfo is not None


def test_check_name_uses_comment_tag_when_set() -> None:
    assert _check_name("") == "Omar Gate"
    assert _check_name("gemini") == "Omar Gate (gemini)"


def test_github_publish_enabled_defaults_true(monkeypatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    assert _github_publish_enabled(OmarGateConfig()) is True


def test_github_publish_enabled_honors_false(monkeypatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_PUBLISH_GITHUB", "false")
    assert _github_publish_enabled(OmarGateConfig()) is False


def test_latest_completed_check_run_picks_newest_completed() -> None:
    runs = [
        {"status": "completed", "completed_at": "2026-02-08T05:30:00Z", "id": 1},
        {"status": "in_progress", "completed_at": "2026-02-08T05:40:00Z", "id": 2},
        {"status": "completed", "completed_at": "2026-02-08T05:31:00Z", "id": 3},
    ]
    latest = _latest_completed_check_run(runs)
    assert latest is not None
    assert latest.get("id") == 3


def test_dedupe_selection_excludes_retryable_check_results() -> None:
    retryable = {
        "status": "completed",
        "external_id": "abc",
        "output": {
            "text": "<!-- sentinelayer:dedupe-cacheable:false -->"
        },
    }

    assert _select_check_run_for_dedupe([retryable], "abc") is None


def test_rate_limit_mirror_skips_newer_retryable_check_result() -> None:
    retryable = {
        "id": "bad",
        "status": "completed",
        "completed_at": "2026-02-08T05:31:00Z",
        "output": {"text": "<!-- sentinelayer:dedupe-cacheable:false -->"},
    }
    valid = {
        "id": "good",
        "status": "completed",
        "completed_at": "2026-02-08T05:30:00Z",
        "output": {"text": "<!-- sentinelayer:dedupe-cacheable:true -->"},
    }

    selected = _select_check_run_for_mirror([retryable, valid])

    assert selected is valid


def test_rate_limit_mirror_refuses_only_retryable_check_result() -> None:
    retryable = {
        "status": "completed",
        "completed_at": "2026-02-08T05:31:00Z",
        "output": {"text": "<!-- sentinelayer:dedupe-cacheable:false -->"},
    }

    assert _select_check_run_for_mirror([retryable]) is None


def test_rate_limit_mirror_refuses_newer_unmarked_legacy_result() -> None:
    legacy_retryable = {
        "id": "legacy-poison",
        "status": "completed",
        "completed_at": "2026-02-08T05:31:00Z",
        "output": {"text": "provider 429"},
    }
    current_valid = {
        "id": "current-valid",
        "status": "completed",
        "completed_at": "2026-02-08T05:30:00Z",
        "output": {"text": "<!-- sentinelayer:dedupe-cacheable:true -->"},
    }

    selected = _select_check_run_for_mirror([legacy_retryable, current_valid])

    assert selected is current_valid


def test_rate_limit_mirror_refuses_only_unmarked_legacy_result() -> None:
    legacy = {
        "status": "completed",
        "completed_at": "2026-02-08T05:31:00Z",
        "output": {"text": "legacy result"},
    }

    assert _select_check_run_for_mirror([legacy]) is None


def test_llm_dedupe_cacheability_requires_complete_or_disabled_review() -> None:
    assert _llm_result_is_dedupe_cacheable(
        attempted=True,
        success=True,
        output_valid=True,
        failure_class=None,
        require_llm_success=True,
        harness_attempted=True,
        harness_success=True,
        require_harness_success=True,
    )
    assert not _llm_result_is_dedupe_cacheable(
        attempted=True,
        success=False,
        output_valid=False,
        failure_class="provider_failure",
        require_llm_success=True,
        harness_attempted=True,
        harness_success=True,
        require_harness_success=True,
    )
    assert _llm_result_is_dedupe_cacheable(
        attempted=False,
        success=False,
        output_valid=False,
        failure_class="not_attempted",
        require_llm_success=False,
        harness_attempted=False,
        harness_success=False,
        require_harness_success=False,
    )


def test_dedupe_cacheability_requires_enabled_harness_to_complete() -> None:
    common = {
        "attempted": True,
        "success": True,
        "output_valid": True,
        "failure_class": None,
        "require_llm_success": True,
        "harness_attempted": True,
        "require_harness_success": True,
    }

    assert not _llm_result_is_dedupe_cacheable(
        harness_success=False,
        **common,
    )
    assert _llm_result_is_dedupe_cacheable(
        harness_success=True,
        **common,
    )
    assert _llm_result_is_dedupe_cacheable(
        attempted=True,
        success=True,
        output_valid=True,
        failure_class=None,
        require_llm_success=True,
        harness_attempted=False,
        harness_success=False,
        require_harness_success=False,
    )


def test_failed_required_harness_publishes_retryable_cache_contract() -> None:
    analysis = SimpleNamespace(
        llm_attempted=True,
        llm_success=True,
        llm_output_valid=True,
        llm_failure_class=None,
        harness_attempted=True,
        harness_success=False,
    )
    config = OmarGateConfig(
        openai_api_key="sk_test_dummy",
        run_harness=True,
        llm_failure_policy="block",
    )

    cacheable, external_id, marker = _build_dedupe_publication_contract(
        analysis,
        config,
        "exact-subject-key",
    )

    assert cacheable is False
    assert external_id is None
    assert marker == "<!-- sentinelayer:dedupe-cacheable:false -->"


def test_counts_from_check_run_output_prefers_marker() -> None:
    summary = "🔴 P0=9 • 🟠 P1=9 • 🟡 P2=9 • ⚪ P3=9"
    text = (
        "Some reason\n\n"
        "<!-- sentinelayer:counts:{\"P0\":1,\"P1\":2,\"P2\":3,\"P3\":4} -->"
    )
    counts = _counts_from_check_run_output(summary=summary, text=text)
    assert (counts.p0, counts.p1, counts.p2, counts.p3) == (1, 2, 3, 4)


def test_counts_from_check_run_output_falls_back_to_summary() -> None:
    summary = "🔴 P0=1 • 🟠 P1=2 • 🟡 P2=3 • ⚪ P3=4"
    counts = _counts_from_check_run_output(summary=summary, text="")
    assert (counts.p0, counts.p1, counts.p2, counts.p3) == (1, 2, 3, 4)


def test_gate_result_from_check_run_strips_counts_marker_from_reason() -> None:
    run = {
        "conclusion": "success",
        "external_id": "abc",
        "output": {
            "summary": "🔴 P0=0 • 🟠 P1=0 • 🟡 P2=0 • ⚪ P3=0",
            "text": (
                "No blocking findings\n\n"
                "<!-- sentinelayer:counts:{\"P0\":0,\"P1\":0,\"P2\":0,\"P3\":0} -->\n"
                "<!-- sentinelayer:dedupe-cacheable:true -->"
            ),
        },
    }
    result = _gate_result_from_check_run(
        run, fallback_reason="Fallback", extra_note="Mirrored"
    )
    assert result.status == GateStatus.PASSED
    assert "sentinelayer:counts" not in result.reason
    assert "dedupe-cacheable" not in result.reason
    assert "Mirrored" in result.reason


def test_exit_code_from_gate_result_needs_approval_is_13() -> None:
    run = {
        "conclusion": "action_required",
        "external_id": "abc",
        "output": {
            "summary": "🔴 P0=0 • 🟠 P1=0 • 🟡 P2=0 • ⚪ P3=0",
            "text": "Approval required",
        },
    }
    result = _gate_result_from_check_run(run, fallback_reason="Fallback", extra_note="")
    assert result.status == GateStatus.NEEDS_APPROVAL
    assert _exit_code_from_gate_result(result) == 13


def test_map_category_to_spec_sections() -> None:
    assert _map_category_to_spec_sections("security.xss") == {"5"}
    assert _map_category_to_spec_sections("quality.lint") == {"7"}


def test_build_spec_compliance_from_findings() -> None:
    payload = _build_spec_compliance_from_findings(
        spec_context={
            "spec_hash": "a" * 64,
            "security_rules": "-",
            "quality_gates": "-",
            "domain_rules": "",
        },
        findings=[
            {"category": "security.auth", "severity": "P1"},
            {"category": "quality.lint", "severity": "P2"},
        ],
    )
    assert payload is not None
    assert payload.spec_hash == "a" * 64
    assert payload.sections_checked == ["5", "7"]
    assert payload.sections_violated == ["5", "7"]

