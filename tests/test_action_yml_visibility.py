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
    assert "steps.artifact_name.outputs.name" in context_window, (
        "upload-artifact name must come from the resolver step so multiple Omar "
        "invocations in one workflow run can use unique artifact names"
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
    assert "steps.artifact_name.outputs.name" in context_window, (
        "block annotation should point at the resolved artifact name for download instructions"
    )


def test_artifact_name_resolver_supports_safe_suffixes() -> None:
    text = _action_yml_text()

    assert "artifact_name_suffix" in text, (
        "action.yml must expose artifact_name_suffix for workflows invoking Omar twice"
    )
    assert "id: artifact_name" in text, (
        "action.yml must resolve the upload artifact name before upload/annotation"
    )
    assert "tr -c 'A-Za-z0-9_.-'" in text, (
        "artifact_name_suffix must be sanitized before it reaches upload-artifact"
    )
    assert "omar-gate-findings-${{ github.run_id }}-${{ github.run_attempt }}" in text, (
        "base artifact name must retain run_id and run_attempt for traceability"
    )


def test_llm_failure_policy_documents_deterministic_only() -> None:
    text = _action_yml_text()

    assert "deterministic_only" in text, (
        "workflow break-glass uses deterministic_only, so action.yml must document it "
        "as a supported llm_failure_policy value"
    )


def test_existing_omar_step_id_is_omar() -> None:
    """The block annotation step references steps.omar.outputs.gate_status — id must persist."""
    text = _action_yml_text()
    assert re.search(r"^\s+id:\s*omar\b", text, flags=re.MULTILINE), (
        "the Execute Omar Gate step must keep id=omar so downstream annotation "
        "step can reference steps.omar.outputs.gate_status"
    )


def test_local_gates_exposes_persona_dispatch_inputs_safely() -> None:
    text = _action_yml_text()

    for input_name in (
        "local_gates_persona_dispatch",
        "local_gates_persona_cli_path",
        "local_gates_persona_dispatch_dry_run",
    ):
        assert re.search(rf"^\s{{2}}{input_name}:\s*$", text, flags=re.MULTILINE), (
            f"action.yml must expose {input_name} so workflows can opt into local "
            "persona dispatch without editing the action"
        )

    assert re.search(
        r"local_gates_persona_dispatch:\n(?:    .+\n)*    default: 'false'",
        text,
    ), "persona dispatch must be opt-in so existing workflows remain deterministic"
    assert re.search(
        r"local_gates_persona_dispatch_dry_run:\n(?:    .+\n)*    default: 'false'",
        text,
    ), "persona dispatch dry-run must not silently change behavior unless requested"
    assert "INPUT_LOCAL_GATES_PERSONA_DISPATCH" in text, (
        "the composite action must pass persona dispatch enablement into the "
        "local gate step"
    )
    assert "INPUT_LOCAL_GATES_PERSONA_CLI_PATH" in text, (
        "the composite action must pass the optional create-sentinelayer CLI path "
        "into the local gate step"
    )
    assert "INPUT_LOCAL_GATES_PERSONA_DISPATCH_DRY_RUN" in text, (
        "the composite action must pass dry-run mode into the local gate step"
    )
    assert "persona_args=()" in text, (
        "persona dispatch flags must be built as a bash array, not string-concatenated"
    )
    assert "persona_args+=(--enable-persona-dispatch)" in text
    assert 'persona_args+=(--persona-cli-path "${persona_cli_path}")' in text
    assert "persona_args+=(--persona-dispatch-dry-run)" in text
    assert '"${persona_args[@]}"' in text, (
        "local_gates must receive persona args via array expansion so custom CLI "
        "paths with spaces are safe"
    )


def test_local_gates_exposes_policy_path_safely() -> None:
    text = _action_yml_text()

    assert re.search(r"^\s{2}local_gates_policy_path:\s*$", text, flags=re.MULTILINE), (
        "action.yml must expose local_gates_policy_path so workflows can point "
        "the local runner at a checked-in policy file"
    )
    assert re.search(
        r"local_gates_policy_path:\n(?:    .+\n)*    default: ''",
        text,
    ), "policy path must default empty so local_gates auto-discovers policy.yaml/yml/json"
    assert "INPUT_LOCAL_GATES_POLICY_PATH" in text, (
        "the composite action must pass the optional policy path into local_gates"
    )
    assert "policy_args=()" in text, (
        "policy flags must be built as a bash array, not string-concatenated"
    )
    assert 'policy_args+=(--policy-file "${policy_path}")' in text
    assert '"${policy_args[@]}"' in text, (
        "local_gates must receive policy args via array expansion so custom policy "
        "paths with spaces are safe"
    )
