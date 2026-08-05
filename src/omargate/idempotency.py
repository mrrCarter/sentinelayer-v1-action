from __future__ import annotations

import hashlib
import re


_DEDUPE_CACHEABILITY_RE = re.compile(
    r"<!--\s*sentinelayer:dedupe-cacheable:(true|false)\s*-->",
    re.IGNORECASE,
)


def dedupe_cacheability_marker(cacheable: bool) -> str:
    """Return the machine-readable cache policy embedded in a check run."""

    value = "true" if cacheable else "false"
    return f"<!-- sentinelayer:dedupe-cacheable:{value} -->"


def check_run_is_dedupe_cacheable(run: dict, *, allow_legacy: bool = True) -> bool:
    """Return whether a check may be reused under the requested contract."""

    output = run.get("output") or {}
    fields = (
        output.get("title"),
        output.get("summary"),
        output.get("text"),
    )
    markers = {
        match.casefold()
        for field in fields
        for match in _DEDUPE_CACHEABILITY_RE.findall(str(field or ""))
    }
    if "false" in markers:
        return False
    if "true" in markers:
        return True
    # Keyed dedupe may retain legacy compatibility because
    # ACTION_IDEMPOTENCY_VERSION is rotated when this contract changes. An
    # unkeyed latest-result mirror must pass allow_legacy=False instead.
    return allow_legacy


def compute_idempotency_key(
    repo: str,
    pr_number: int,
    head_sha: str,
    scan_mode: str,
    policy_pack: str,
    policy_pack_version: str,
    action_major_version: str,
    comment_tag: str = "",
) -> str:
    # P0: do NOT truncate; show shortened form only for display
    payload = (
        f"{repo}:{pr_number}:{head_sha}:{scan_mode}:{policy_pack}:"
        f"{policy_pack_version}:{action_major_version}"
    )
    tag = str(comment_tag or "").strip().lower()
    tag = re.sub(r"[^a-z0-9_-]+", "-", tag)
    tag = re.sub(r"-{2,}", "-", tag).strip("-_")
    if tag:
        payload = f"{payload}:{tag}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
