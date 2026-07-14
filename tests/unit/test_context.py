from __future__ import annotations

from pathlib import Path

import pytest

from omargate.context import GitHubContext


def test_action_declares_and_forwards_pr_number() -> None:
    action = (Path(__file__).parents[2] / "action.yml").read_text(encoding="utf-8")

    assert "\n  pr_number:\n" in action
    assert "INPUT_PR_NUMBER: ${{ inputs.pr_number }}" in action


def test_context_parses_pr_event(
    monkeypatch: pytest.MonkeyPatch,
    event_pr_path: Path,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_pr_path))
    monkeypatch.setenv("GITHUB_SHA", "fallbacksha")
    monkeypatch.setenv("GITHUB_ACTOR", "octo")
    monkeypatch.setenv("INPUT_PR_NUMBER", "999")

    ctx = GitHubContext.from_environment()

    assert ctx.pr_number == 42
    assert ctx.head_sha == "headsha123"
    assert ctx.base_sha == "basesha456"
    assert ctx.pr_title == "Fix bug"
    assert ctx.is_fork is False


def test_context_detects_fork(
    monkeypatch: pytest.MonkeyPatch,
    event_fork_pr_path: Path,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_fork_pr_path))
    monkeypatch.setenv("GITHUB_SHA", "fallbacksha")

    ctx = GitHubContext.from_environment()

    assert ctx.is_fork is True
    assert ctx.fork_owner == "forkuser"


def test_context_handles_push_event(
    monkeypatch: pytest.MonkeyPatch,
    event_push_path: Path,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_push_path))
    monkeypatch.setenv("GITHUB_SHA", "fallbacksha")
    monkeypatch.setenv("INPUT_PR_NUMBER", "51")

    ctx = GitHubContext.from_environment()

    assert ctx.pr_number is None
    assert ctx.head_sha == "pushsha789"
    assert ctx.head_ref == "refs/heads/main"


def test_context_uses_explicit_pr_for_workflow_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "dispatchsha123")
    monkeypatch.setenv("INPUT_PR_NUMBER", " 256 ")

    ctx = GitHubContext.from_environment()

    assert ctx.pr_number == 256
    assert ctx.head_sha == "dispatchsha123"


@pytest.mark.parametrize("pr_number", ["0", "-1", "1.5", "abc", "+1"])
def test_context_rejects_invalid_workflow_dispatch_pr_number(
    monkeypatch: pytest.MonkeyPatch,
    pr_number: str,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "dispatchsha123")
    monkeypatch.setenv("INPUT_PR_NUMBER", pr_number)

    with pytest.raises(RuntimeError, match="positive decimal integer"):
        GitHubContext.from_environment()
