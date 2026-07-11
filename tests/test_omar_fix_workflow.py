"""Visibility tests for the optional `/omar fix <finding_id>` workflow."""

from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _workflow_text() -> str:
    return (
        _repo_root() / "examples" / "workflows" / "omar-fix-comment.yml"
    ).read_text(encoding="utf-8")


def test_fix_workflow_authorizes_commenter_before_checkout() -> None:
    text = _workflow_text()

    assert "actions: read" in text
    assert "issues: write" in text
    assert "pull-requests: write" in text
    assert "collaborators/${COMMENT_AUTHOR}/permission" in text, (
        "the workflow must verify real repo permission, not trust author association"
    )
    assert "admin|maintain|write)" in text
    assert "authorized=1" in text
    assert "if: steps.authz.outputs.authorized == '1'" in text
    assert text.index("name: Authorize commenter") < text.index("name: Checkout PR head")


def test_fix_workflow_finds_run_scoped_findings_artifacts() -> None:
    text = _workflow_text()

    assert 'startswith("omar-gate-findings-")' in text, (
        "the workflow must follow the run-scoped artifact naming contract from action.yml"
    )
    assert 'gh run download "${run_id}" -n "${artifact_name}"' in text
    assert "findings_file=" in text
    assert "-name FINDINGS.jsonl" in text
    assert "-n omar-gate-findings -D" not in text, (
        "the old fixed artifact name misses current omar-gate-findings-<run>-<attempt>"
    )


def test_fix_workflow_acknowledges_expected_declines_without_failing() -> None:
    text = _workflow_text()

    assert "set +e" in text
    assert "cli_rc=$?" in text
    assert 'if [ "${cli_rc}" -eq 2 ]; then' in text, (
        "only runner/input errors should fail the workflow; declines still need PR ack"
    )
    assert "plan_file=/tmp/omar-fix-plan.json" in text
    assert "has_plan=" in text
    assert "if: steps.plan.outputs.has_plan == '1'" in text


def test_fix_command_is_documented_publicly() -> None:
    readme = (_repo_root() / "README.md").read_text(encoding="utf-8")
    docs = (
        _repo_root() / "docs" / "comment-command-reference.md"
    ).read_text(encoding="utf-8")
    spec = (_repo_root() / "SPEC.md").read_text(encoding="utf-8")

    for text in (readme, docs, spec):
        assert "/omar fix <finding_id>" in text
    for text in (readme, docs):
        assert "examples/workflows/omar-fix-comment.yml" in text
    assert "write, maintain, or admin permission" in spec
    assert "run-scoped `omar-gate-findings-*` artifact" in spec
