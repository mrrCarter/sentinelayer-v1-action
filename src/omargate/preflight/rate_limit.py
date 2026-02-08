from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from ..config import OmarGateConfig
from ..github import GitHubClient
from ..logging import OmarLogger


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


async def check_rate_limits(
    gh: GitHubClient,
    pr_number: Optional[int],
    config: OmarGateConfig,
    logger: OmarLogger,
) -> Tuple[bool, str]:
    """
    Check cooldown and daily limits.

    Returns:
        (should_proceed, reason_if_blocked)

    FAIL-OPEN: Rate limits are cost control. If GitHub API is unavailable (or token is missing),
    skip enforcement and allow the scan to proceed.
    """
    if config.max_daily_scans == 0 and config.min_scan_interval_minutes == 0:
        return True, "limits_disabled"

    if not pr_number:
        return True, "not_pr"

    if not getattr(gh, "token", ""):
        logger.warning("rate_limit_skip", reason="missing_github_token")
        return True, "missing_github_token_skip_limits"

    try:
        pr = gh.get_pull_request(pr_number)
        head_sha = (pr.get("head") or {}).get("sha")
        if not head_sha:
            logger.warning("rate_limit_skip", reason="missing_head_sha")
            return True, "missing_head_sha_skip_limits"
        runs = gh.list_check_runs(head_sha, "Omar Gate")
    except Exception as exc:
        logger.warning("rate_limit_api_error_skip", error=str(exc))
        return True, "api_error_skip_limits"

    now = datetime.now(timezone.utc)
    completed_times = [
        ts for ts in (_parse_iso8601(r.get("completed_at")) for r in runs) if ts
    ]

    if completed_times:
        latest = max(completed_times)
        cooldown = timedelta(minutes=config.min_scan_interval_minutes)
        if cooldown.total_seconds() > 0 and (now - latest) < cooldown:
            return False, "cooldown_not_met"

    if config.max_daily_scans > 0:
        cutoff = now - timedelta(days=1)
        daily_count = sum(1 for ts in completed_times if ts >= cutoff)
        if daily_count >= config.max_daily_scans:
            return False, "daily_cap_exceeded"

    return True, "ok"
