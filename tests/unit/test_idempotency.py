from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from omargate.config import OmarGateConfig
from omargate.idempotency import (
    build_analysis_subject_contract,
    check_run_is_dedupe_cacheable,
    compute_idempotency_key,
    compute_tool_contract_digest,
    dedupe_cacheability_marker,
    resolve_spec_context_contract,
)
from omargate.main import ACTION_IDEMPOTENCY_VERSION


SUBJECT_CONTRACT = {"schema_version": "test", "profile": "strict"}


def _base_hash() -> str:
    contract_json = json.dumps(
        SUBJECT_CONTRACT,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    contract_digest = hashlib.sha256(contract_json.encode("utf-8")).hexdigest()
    payload = json.dumps(
        {
            "schema_version": "1",
            "repo": "octo/repo",
            "pr_number": 7,
            "head_sha": "deadbeef",
            "scan_mode": "pr-diff",
            "policy_pack": "omar",
            "policy_pack_version": "v1",
            "action_contract_version": "1",
            "subject_contract_sha256": contract_digest,
            "comment_tag": "",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_idempotency_key_empty_comment_tag_is_stable() -> None:
    key = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        subject_contract=SUBJECT_CONTRACT,
        comment_tag="",
    )
    assert key == _base_hash()


def test_idempotency_key_changes_when_comment_tag_is_set() -> None:
    base = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        subject_contract=SUBJECT_CONTRACT,
    )
    tagged = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        subject_contract=SUBJECT_CONTRACT,
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
        subject_contract=SUBJECT_CONTRACT,
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

    legacy = compute_idempotency_key(
        action_major_version="1",
        subject_contract=SUBJECT_CONTRACT,
        **common,
    )
    evidence_contract = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        subject_contract=SUBJECT_CONTRACT,
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
        subject_contract=SUBJECT_CONTRACT,
        **common,
    )
    v1311 = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        subject_contract=SUBJECT_CONTRACT,
        **common,
    )

    assert (
        ACTION_IDEMPOTENCY_VERSION
        == "5:llm-evidence-v1:eq009-v3:retryable-infra-v1:subject-contract-v1:canonical-id-v1"
    )
    assert v1311 != v1310


def test_full_identity_has_no_delimiter_collision() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
        "subject_contract": SUBJECT_CONTRACT,
    }
    left = compute_idempotency_key(
        policy_pack="a:b",
        policy_pack_version="c",
        **common,
    )
    right = compute_idempotency_key(
        policy_pack="a",
        policy_pack_version="b:c",
        **common,
    )

    assert left != right


def _subject_for(**overrides: object) -> dict:
    values: dict[str, object] = {
        "openai_api_key": "sk_test_dummy",
        "sentinelayer_spec_id": "a" * 64,
        "severity_gate": "P0",
        "llm_failure_policy": "allow_with_warning",
    }
    values.update(overrides)
    config = OmarGateConfig(**values)
    return build_analysis_subject_contract(
        config,
        effective_scan_mode="deep",
        fork_execution_mode="full",
        tool_contract_sha256="b" * 64,
        spec_context_state="loaded",
        spec_context_sha256="c" * 64,
    )


def _key_for_subject(subject_contract: dict) -> str:
    return compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="deep",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        subject_contract=subject_contract,
    )


def test_subject_contract_prevents_warn_result_reuse_under_block_policy() -> None:
    warning_key = _key_for_subject(_subject_for(llm_failure_policy="allow_with_warning"))
    blocking_key = _key_for_subject(_subject_for(llm_failure_policy="block"))

    assert warning_key != blocking_key


def test_subject_contract_prevents_p0_result_reuse_under_p1_gate() -> None:
    p0_key = _key_for_subject(_subject_for(severity_gate="P0"))
    p1_key = _key_for_subject(_subject_for(severity_gate="P1"))

    assert p0_key != p1_key


def test_subject_contract_binds_spec_model_harness_and_execution_mode() -> None:
    base = _key_for_subject(_subject_for())
    variants = [
        _key_for_subject(_subject_for(sentinelayer_spec_id="c" * 64)),
        _key_for_subject(_subject_for(codex_model="gpt-5.4")),
        _key_for_subject(_subject_for(run_harness=False)),
        _key_for_subject(
            build_analysis_subject_contract(
                OmarGateConfig(
                    openai_api_key="sk_test_dummy",
                    sentinelayer_spec_id="a" * 64,
                    severity_gate="P0",
                    llm_failure_policy="allow_with_warning",
                ),
                effective_scan_mode="deep",
                fork_execution_mode="limited",
                tool_contract_sha256="b" * 64,
                spec_context_state="loaded",
                spec_context_sha256="c" * 64,
            )
        ),
    ]

    assert all(candidate != base for candidate in variants)


def test_subject_contract_binds_actual_spec_context_availability() -> None:
    config = OmarGateConfig(
        openai_api_key="sk_test_dummy",
        sentinelayer_spec_id="a" * 64,
    )
    unavailable = build_analysis_subject_contract(
        config,
        effective_scan_mode="deep",
        fork_execution_mode="full",
        tool_contract_sha256="b" * 64,
        spec_context_state="unavailable",
        spec_context_sha256="",
    )
    loaded = build_analysis_subject_contract(
        config,
        effective_scan_mode="deep",
        fork_execution_mode="full",
        tool_contract_sha256="b" * 64,
        spec_context_state="loaded",
        spec_context_sha256="d" * 64,
    )

    assert _key_for_subject(unavailable) != _key_for_subject(loaded)


def test_spec_context_contract_validates_identity_and_canonicalizes_content() -> None:
    spec_id = "a" * 64
    first = {"spec_hash": spec_id, "policy": {"b": 2, "a": 1}}
    reordered = {"policy": {"a": 1, "b": 2}, "spec_hash": spec_id.upper()}

    assert resolve_spec_context_contract(spec_id, None) == ("unavailable", "")
    assert resolve_spec_context_contract("", None) == ("not_configured", "")
    assert resolve_spec_context_contract(spec_id, first) == resolve_spec_context_contract(
        spec_id,
        reordered,
    )

    with pytest.raises(RuntimeError, match="does not match"):
        resolve_spec_context_contract(spec_id, {"spec_hash": "b" * 64})


def test_subject_contract_is_canonical_and_excludes_secret_values() -> None:
    first = _subject_for(
        openai_api_key="sk_first_secret",
        pip_audit_ignore_ids=" cve-2024-0001, GHSA-AAAA-BBBB-CCCC ",
    )
    second = _subject_for(
        openai_api_key="sk_second_secret",
        pip_audit_ignore_ids="ghsa-aaaa-bbbb-cccc,CVE-2024-0001,CVE-2024-0001",
    )

    assert first == second
    serialized = json.dumps(first, sort_keys=True)
    assert "sk_first_secret" not in serialized
    assert "sk_second_secret" not in serialized


def test_subject_contract_binds_credential_route_availability_not_values() -> None:
    no_live_route = _key_for_subject(_subject_for(openai_api_key=""))
    first_byo_route = _key_for_subject(
        _subject_for(openai_api_key="sk_first_secret")
    )
    second_byo_route = _key_for_subject(
        _subject_for(openai_api_key="sk_second_secret")
    )

    assert no_live_route != first_byo_route
    assert first_byo_route == second_byo_route


def test_tool_contract_digest_binds_source_prompts_action_and_lock(
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "src" / "omargate"
    prompts_root = tmp_path / "prompts"
    package_root.mkdir(parents=True)
    prompts_root.mkdir()
    (package_root / "scanner.py").write_text("RULE = 1\n", encoding="utf-8")
    prompt_path = prompts_root / "SECURITY_REVIEW.md"
    prompt_path.write_text("review v1\n", encoding="utf-8")
    (tmp_path / "action.yml").write_text("name: Omar Gate\n", encoding="utf-8")
    (tmp_path / "requirements.lock.txt").write_text("httpx==1\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")
    (tmp_path / ".dockerignore").write_text(".git\n", encoding="utf-8")
    (tmp_path / "entrypoint.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    initial = compute_tool_contract_digest(tmp_path)
    assert initial == compute_tool_contract_digest(tmp_path)

    prompt_path.write_text("review v2\n", encoding="utf-8")
    assert compute_tool_contract_digest(tmp_path) != initial


def test_docker_runtime_contains_the_complete_tool_contract() -> None:
    action_root = Path(__file__).resolve().parents[2]
    dockerfile = (action_root / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (action_root / ".dockerignore").read_text(encoding="utf-8")

    assert "COPY src /app/src" in dockerfile
    assert "COPY prompts /app/prompts" in dockerfile
    assert (
        "COPY action.yml requirements.lock.txt Dockerfile .dockerignore entrypoint.sh /app/"
        in dockerfile
    )
    assert "!prompts/*.md" in dockerignore
    assert "!prompts/**/*.md" in dockerignore


def test_container_layout_produces_the_same_tool_contract_digest(
    tmp_path: Path,
) -> None:
    action_root = Path(__file__).resolve().parents[2]
    shutil.copytree(action_root / "src" / "omargate", tmp_path / "src" / "omargate")
    shutil.copytree(action_root / "prompts", tmp_path / "prompts")
    for relative_path in (
        "action.yml",
        "requirements.lock.txt",
        "Dockerfile",
        ".dockerignore",
        "entrypoint.sh",
    ):
        shutil.copy2(action_root / relative_path, tmp_path / relative_path)

    assert compute_tool_contract_digest(tmp_path) == compute_tool_contract_digest(
        action_root
    )


def test_retryable_check_marker_overrides_legacy_dedupe_identity() -> None:
    run = {
        "external_id": "same-content",
        "output": {
            "summary": "P0=1",
            "text": dedupe_cacheability_marker(False),
        },
    }

    assert check_run_is_dedupe_cacheable(run) is False


def test_unkeyed_reuse_requires_explicit_current_cacheability_marker() -> None:
    legacy = {"output": {"text": "legacy"}}
    current = {
        "output": {"text": "<!-- sentinelayer:dedupe-cacheable:true -->"}
    }

    assert check_run_is_dedupe_cacheable(legacy) is True
    assert check_run_is_dedupe_cacheable(legacy, allow_legacy=False) is False
    assert check_run_is_dedupe_cacheable(current, allow_legacy=False) is True


def test_cacheable_and_legacy_check_markers_remain_eligible() -> None:
    assert check_run_is_dedupe_cacheable(
        {"output": {"text": dedupe_cacheability_marker(True)}}
    )
    assert check_run_is_dedupe_cacheable({"output": {"text": "legacy"}})
