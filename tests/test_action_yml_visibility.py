"""Asserts action.yml composite always uploads findings + annotates on block.

Uses text-based assertions to avoid a PyYAML dependency in the bridge-unit-tests
CI environment. The action.yml structure is stable enough that line-level
matching is more reliable than parsing.
"""

from __future__ import annotations

import re
from pathlib import Path


def _action_yml_text() -> str:
    repo_root = Path(__file__).resolve().parent.parent
    return (repo_root / "action.yml").read_text(encoding="utf-8")


def test_upload_artifact_step_runs_always_with_pinned_sha() -> None:
    text = _action_yml_text()

    # Find an actions/upload-artifact reference.
    upload_match = re.search(
        r"uses:\s*actions/upload-artifact@([0-9a-f]{40})",
        text,
    )
    assert upload_match, (
        "action.yml must include actions/upload-artifact pinned to a 40-char SHA"
    )

    # Locate the YAML step that contains the upload-artifact use.
    # Heuristic: 25 lines around the match should contain the if/with/path block.
    idx = upload_match.start()
    context_window = text[max(0, idx - 600) : idx + 800]

    assert "if: always()" in context_window, (
        "upload-artifact step must run with `if: always()` so FINDINGS.jsonl uploads "
        "on block (gate exit 1). Context:\n" + context_window
    )
    assert ".sentinelayer/artifacts" in context_window, (
        "upload-artifact path must include .sentinelayer/artifacts/** so staged "
        "FINDINGS.jsonl + AUDIT_REPORT.md reach workflow artifacts"
    )
    assert ".sentinelayer/runs" in context_window, (
        "upload-artifact path must also include .sentinelayer/runs/** as fallback "
        "in case prepare_artifacts_for_upload skipped"
    )
    assert "if-no-files-found: warn" in context_window, (
        "missing-files should warn, not fail — preflight failures must not break the run"
    )


def test_block_annotation_step_runs_when_gate_blocks() -> None:
    text = _action_yml_text()

    # Look for a step name that mentions block + annotation.
    name_match = re.search(
        r"-\s+name:\s*[^\n]*block[^\n]*annotation",
        text,
        flags=re.IGNORECASE,
    )
    if not name_match:
        # Fallback: scan for any step that emits an ::error:: directive on block.
        name_match = re.search(r"-\s+name:\s*Surface[^\n]+", text, flags=re.IGNORECASE)
    assert name_match, (
        "action.yml must include a step that surfaces block status as a runner annotation"
    )

    idx = name_match.start()
    context_window = text[idx : idx + 800]

    assert "if: always()" in context_window or "always() &&" in context_window, (
        "block annotation step must run with always() so the banner shows on exit 1"
    )
    assert "blocked" in context_window or "error" in context_window, (
        "block annotation should be gated on gate_status blocked/error"
    )
    assert "::error" in context_window, (
        "block annotation must emit a runner ::error:: directive so a red banner "
        "appears in the GitHub PR view"
    )
    assert "p0_count" in context_window.lower() or "P0=" in context_window, (
        "block annotation should reference P0 count so the user knows scope of issue"
    )
    assert "omar-gate-findings" in context_window, (
        "block annotation should point at the artifact name for download instructions"
    )


def test_existing_omar_step_id_is_omar() -> None:
    """The block annotation step references steps.omar.outputs.gate_status — id must persist."""
    text = _action_yml_text()
    assert re.search(r"^\s+id:\s*omar\b", text, flags=re.MULTILINE), (
        "the Execute Omar Gate step must keep id=omar so downstream annotation "
        "step can reference steps.omar.outputs.gate_status"
    )
