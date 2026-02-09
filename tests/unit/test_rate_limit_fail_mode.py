from __future__ import annotations

import asyncio

from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger
from omargate.preflight import check_rate_limits


class ErrorGitHub:
    def __init__(self) -> None:
        self.token = "gh_test_token"

    def get_pull_request(self, pr_number: int):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")


def test_rate_limit_api_error_fail_closed_requires_approval() -> None:
    config = OmarGateConfig(
        openai_api_key="sk_test_dummy",
        max_daily_scans=1,
        min_scan_interval_minutes=5,
        rate_limit_fail_mode="closed",
    )
    logger = OmarLogger("test-run")
    allowed, reason = asyncio.run(check_rate_limits(ErrorGitHub(), pr_number=1, config=config, logger=logger))
    assert allowed is False
    assert reason == "api_error_require_approval"


def test_rate_limit_api_error_fail_open_skips_enforcement() -> None:
    config = OmarGateConfig(
        openai_api_key="sk_test_dummy",
        max_daily_scans=1,
        min_scan_interval_minutes=5,
        rate_limit_fail_mode="open",
    )
    logger = OmarLogger("test-run")
    allowed, reason = asyncio.run(check_rate_limits(ErrorGitHub(), pr_number=1, config=config, logger=logger))
    assert allowed is True
    assert reason == "api_error_skip_limits"

