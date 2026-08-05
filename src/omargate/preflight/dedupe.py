from __future__ import annotations

from typing import Optional, Tuple

from ..github import GitHubClient
from ..idempotency import check_run_is_dedupe_cacheable


async def check_dedupe(
    gh: GitHubClient,
    head_sha: str,
    dedupe_key: str,
    check_name: str = "Omar Gate",
) -> Tuple[bool, Optional[str]]:
    """
    Check if a completed run exists for this dedupe key.

    Returns:
        (should_skip, existing_run_url)
    """
    try:
        run = gh.find_check_run_by_external_id(head_sha, dedupe_key, check_name)
        if (
            run
            and run.get("status") == "completed"
            and check_run_is_dedupe_cacheable(run)
        ):
            return True, run.get("html_url") or run.get("details_url")

        # Fallback to marker parsing in output fields if external_id was not set.
        for candidate in gh.list_check_runs(head_sha, check_name):
            if (
                candidate.get("status") != "completed"
                or not check_run_is_dedupe_cacheable(candidate)
            ):
                continue
            output = candidate.get("output") or {}
            summary = output.get("summary") or ""
            text = output.get("text") or ""
            if dedupe_key in summary or dedupe_key in text:
                return True, candidate.get("html_url") or candidate.get("details_url")
    except Exception:
        return False, None

    return False, None
