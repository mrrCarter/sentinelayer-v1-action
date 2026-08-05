from __future__ import annotations

import hashlib

from omargate.idempotency import (
    check_run_is_dedupe_cacheable,
    compute_idempotency_key,
    dedupe_cacheability_marker,
)
from omargate.main import ACTION_IDEMPOTENCY_VERSION


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


def test_live_llm_evidence_contract_invalidates_legacy_dedupe_keys() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
    }

    legacy = compute_idempotency_key(action_major_version="1", **common)
    evidence_contract = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        **common,
    )

    assert evidence_contract != legacy


def test_eq009_contract_invalidates_v1310_dedupe_keys() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
    }

    v1310 = compute_idempotency_key(
        action_major_version="1:llm-evidence-v1",
        **common,
    )
    v1311 = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        **common,
    )

    assert (
        ACTION_IDEMPOTENCY_VERSION
        == "3:llm-evidence-v1:eq009-v3:retryable-infra-v1"
    )
    assert v1311 != v1310


def test_retryable_check_marker_overrides_legacy_dedupe_identity() -> None:
    run = {
        "external_id": "same-content",
        "output": {
            "summary": "P0=1",
            "text": dedupe_cacheability_marker(False),
        },
    }

    assert check_run_is_dedupe_cacheable(run) is False


def test_cacheable_and_legacy_check_markers_remain_eligible() -> None:
    assert check_run_is_dedupe_cacheable(
        {"output": {"text": dedupe_cacheability_marker(True)}}
    )
    assert check_run_is_dedupe_cacheable({"output": {"text": "legacy"}})
