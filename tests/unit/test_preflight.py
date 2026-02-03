from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from omargate.config import OmarGateConfig
from omargate.context import GitHubContext
from omargate.logging import OmarLogger
from omargate.preflight import (
    check_cost_approval,
    check_dedupe,
    check_fork_policy,
    check_rate_limits,
    estimate_cost,
)


class DummyGitHub:
    def __init__(
        self,
        runs: Optional[List[Dict[str, Any]]] = None,
        pr_head: str = "headsha",
        labels: Optional[List[str]] = None,
    ) -> None:
        self._runs = runs or []
        self._pr_head = pr_head
        self._labels = labels or []

    def list_check_runs(self, head_sha: str, check_name: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._runs

    def find_check_run_by_external_id(
        self, head_sha: str, external_id: str, check_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        for run in self._runs:
            if run.get("external_id") == external_id:
                return run
        return None

    def get_pull_request(self, pr_number: int) -> Dict[str, Any]:
        return {"head": {"sha": self._pr_head}}

    def has_label(self, pr_number: int, label: str) -> bool:
        return label in self._labels


def test_fork_policy_blocks_by_default() -> None:
    config = OmarGateConfig(openai_api_key="sk-test", fork_policy="block")
    ctx = GitHubContext(
        repo_owner="octo",
        repo_name="repo",
        repo_full_name="octo/repo",
        event_name="pull_request",
        pr_number=1,
        pr_title="Fork",
        head_sha="head",
        base_sha="base",
        head_ref="feat",
        base_ref="main",
        is_fork=True,
        fork_owner="forkuser",
        actor="octo",
    )

    allowed, mode, reason = check_fork_policy(ctx, config)
    assert allowed is False
    assert mode == "blocked"
    assert reason == "fork_pr_blocked_by_policy"


def test_fork_policy_limited_mode() -> None:
    config = OmarGateConfig(openai_api_key="sk-test", fork_policy="limited")
    ctx = GitHubContext(
        repo_owner="octo",
        repo_name="repo",
        repo_full_name="octo/repo",
        event_name="pull_request",
        pr_number=1,
        pr_title="Fork",
        head_sha="head",
        base_sha="base",
        head_ref="feat",
        base_ref="main",
        is_fork=True,
        fork_owner="forkuser",
        actor="octo",
    )

    allowed, mode, reason = check_fork_policy(ctx, config)
    assert allowed is True
    assert mode == "limited"
    assert reason == "fork_pr_limited_mode"


def test_cost_estimation() -> None:
    cost = estimate_cost(file_count=10, total_lines=100, model="gpt-4o")
    assert cost == pytest.approx(0.006)


def test_cost_approval_with_label() -> None:
    config = OmarGateConfig(
        openai_api_key="sk-test",
        approval_mode="pr_label",
        approval_label="sentinellayer:approved",
        require_cost_confirmation=0.01,
    )
    ctx = GitHubContext(
        repo_owner="octo",
        repo_name="repo",
        repo_full_name="octo/repo",
        event_name="pull_request",
        pr_number=1,
        pr_title="PR",
        head_sha="head",
        base_sha="base",
        head_ref="feat",
        base_ref="main",
        is_fork=False,
        fork_owner=None,
        actor="octo",
    )
    gh = DummyGitHub(labels=["sentinellayer:approved"])

    approved, status = asyncio.run(check_cost_approval(1.0, config, ctx, gh))
    assert approved is True
    assert status == "label_approved"


def test_dedupe_detects_existing_run() -> None:
    gh = DummyGitHub(
        runs=[
            {"external_id": "abc", "status": "completed", "html_url": "https://example.com/run/1"}
        ]
    )
    should_skip, url = asyncio.run(check_dedupe(gh, "headsha", "abc"))
    assert should_skip is True
    assert url == "https://example.com/run/1"


def test_rate_limit_cooldown_blocks() -> None:
    now = datetime.now(timezone.utc)
    gh = DummyGitHub(
        runs=[{"completed_at": (now - timedelta(minutes=1)).isoformat()}],
        pr_head="headsha",
    )
    config = OmarGateConfig(openai_api_key="sk-test", min_scan_interval_minutes=5, max_daily_scans=0)
    logger = OmarLogger("test-run")

    allowed, reason = asyncio.run(check_rate_limits(gh, pr_number=1, config=config, logger=logger))
    assert allowed is False
    assert reason == "cooldown_not_met"


def test_rate_limit_daily_cap_blocks() -> None:
    now = datetime.now(timezone.utc)
    gh = DummyGitHub(
        runs=[{"completed_at": (now - timedelta(hours=2)).isoformat()}],
        pr_head="headsha",
    )
    config = OmarGateConfig(openai_api_key="sk-test", min_scan_interval_minutes=0, max_daily_scans=1)
    logger = OmarLogger("test-run")

    allowed, reason = asyncio.run(check_rate_limits(gh, pr_number=1, config=config, logger=logger))
    assert allowed is False
    assert reason == "daily_cap_exceeded"
