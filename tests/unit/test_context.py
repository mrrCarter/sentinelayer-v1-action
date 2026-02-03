from __future__ import annotations

from pathlib import Path

import pytest

from omargate.context import GitHubContext


def test_context_parses_pr_event(
    monkeypatch: pytest.MonkeyPatch,
    event_pr_path: Path,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_pr_path))
    monkeypatch.setenv("GITHUB_SHA", "fallbacksha")
    monkeypatch.setenv("GITHUB_ACTOR", "octo")

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

    ctx = GitHubContext.from_environment()

    assert ctx.pr_number is None
    assert ctx.head_sha == "pushsha789"
    assert ctx.head_ref == "refs/heads/main"
