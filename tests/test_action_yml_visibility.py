"""Asserts action.yml composite always uploads findings + annotates on block."""

from __future__ import annotations

from pathlib import Path

import yaml


def _load_action_yml() -> dict:
    repo_root = Path(__file__).resolve().parent.parent
    action_yml = repo_root / "action.yml"
    return yaml.safe_load(action_yml.read_text(encoding="utf-8"))


def _composite_steps() -> list[dict]:
    data = _load_action_yml()
    runs = data.get("runs") or {}
    assert runs.get("using") == "composite", "action.yml must remain a composite action"
    return runs.get("steps") or []


def test_upload_artifact_step_runs_always_with_pinned_sha() -> None:
    steps = _composite_steps()
    upload_steps = [
        s
        for s in steps
        if isinstance(s.get("uses"), str)
        and s["uses"].startswith("actions/upload-artifact@")
    ]
    assert upload_steps, "action.yml must include actions/upload-artifact"

    for step in upload_steps:
        condition = str(step.get("if") or "").strip()
        assert "always()" in condition, (
            f"upload-artifact step must run with if: always() to surface findings "
            f"on block (exit 1). Found if={condition!r} in step={step.get('name')!r}"
        )

        uses = step["uses"]
        ref = uses.split("@", 1)[1]
        assert len(ref) >= 40 and all(c in "0123456789abcdef" for c in ref[:40]), (
            f"upload-artifact must be pinned to a 40-char commit SHA, got: {ref}"
        )

        params = step.get("with") or {}
        path_value = params.get("path") or ""
        assert ".sentinelayer/artifacts" in path_value, (
            "upload-artifact path must include .sentinelayer/artifacts/** so staged "
            "FINDINGS.jsonl + AUDIT_REPORT.md reach workflow artifacts"
        )
        assert ".sentinelayer/runs" in path_value, (
            "upload-artifact path must also include .sentinelayer/runs/** as fallback "
            "in case prepare_artifacts_for_upload skipped"
        )
        assert params.get("if-no-files-found") == "warn", (
            "missing-files should warn, not fail — preflight failures must not break the run"
        )


def test_block_annotation_step_runs_when_gate_blocks() -> None:
    steps = _composite_steps()
    annot_steps = [
        s
        for s in steps
        if isinstance(s.get("name"), str)
        and "annotation" in s["name"].lower()
        and "block" in s["name"].lower()
    ]
    assert annot_steps, (
        "action.yml must include a runner-annotation step that surfaces block status"
    )

    for step in annot_steps:
        condition = str(step.get("if") or "").strip()
        assert "always()" in condition, (
            f"block annotation must run with always() — found if={condition!r}"
        )
        assert "blocked" in condition or "error" in condition, (
            f"block annotation should be gated on gate_status blocked/error, got "
            f"if={condition!r}"
        )
        run_block = str(step.get("run") or "")
        assert "::error" in run_block, (
            "block annotation must emit a runner ::error:: directive so a red banner "
            "appears in the GitHub PR view"
        )
        assert "p0_count" in run_block.lower() or "P0" in run_block, (
            "block annotation should reference P0 count so the user knows scope of issue"
        )
        assert "omar-gate-findings" in run_block, (
            "block annotation should point at the artifact name for download instructions"
        )


def test_existing_omar_step_id_is_omar() -> None:
    """Annotation references steps.omar.outputs.gate_status — this id must persist."""
    steps = _composite_steps()
    omar_steps = [s for s in steps if s.get("id") == "omar"]
    assert omar_steps, (
        "the Execute Omar Gate step must keep id=omar so downstream annotation "
        "step can reference steps.omar.outputs.gate_status"
    )
