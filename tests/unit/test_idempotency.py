from __future__ import annotations

import hashlib

from omargate.idempotency import compute_idempotency_key


def _legacy_hash() -> str:
    payload = "octo/repo:7:deadbeef:pr-diff:omar:v1:1"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_idempotency_key_empty_comment_tag_matches_legacy() -> None:
    key = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="",
    )
    assert key == _legacy_hash()


def test_idempotency_key_changes_when_comment_tag_is_set() -> None:
    base = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )
    tagged = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="gemini",
    )
    assert tagged != base
    assert tagged == compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="gemini",
    )
