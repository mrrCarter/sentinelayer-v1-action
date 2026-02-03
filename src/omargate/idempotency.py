from __future__ import annotations

import hashlib

def compute_idempotency_key(
    repo: str,
    pr_number: int,
    head_sha: str,
    scan_mode: str,
    policy_pack: str,
    policy_pack_version: str,
    action_major_version: str,
) -> str:
    # P0: do NOT truncate; show shortened form only for display
    payload = f"{repo}:{pr_number}:{head_sha}:{scan_mode}:{policy_pack}:{policy_pack_version}:{action_major_version}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
