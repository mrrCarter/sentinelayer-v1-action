from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .config import OmarGateConfig


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


def compute_tool_contract_digest(action_root: Path) -> str:
    """Hash the executable scanner, prompt bundle, and pinned dependencies."""

    root = action_root.resolve()
    package_root = root / "src" / "omargate"
    prompts_root = root / "prompts"
    if not package_root.is_dir() or not prompts_root.is_dir():
        raise RuntimeError("Unable to resolve Omar Gate tool contract roots")

    files = [
        path
        for source_root in (package_root, prompts_root)
        for path in source_root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix.lower() not in {".pyc", ".pyo"}
    ]
    for relative_path in ("action.yml", "requirements.lock.txt"):
        path = root / relative_path
        if not path.is_file():
            raise RuntimeError(f"Missing Omar Gate tool contract file: {relative_path}")
        files.append(path)

    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _normalize_pip_audit_ignore_ids(value: str) -> list[str]:
    return sorted(
        {
            item.strip().upper()
            for item in str(value or "").split(",")
            if item.strip()
        }
    )


def build_analysis_subject_contract(
    config: "OmarGateConfig",
    *,
    effective_scan_mode: str,
    fork_execution_mode: str,
    tool_contract_sha256: str,
) -> dict[str, Any]:
    """Return the non-secret policy/tool profile whose evidence may be reused."""

    tool_digest = str(tool_contract_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", tool_digest):
        raise ValueError("tool_contract_sha256 must be a 64-character lowercase hex digest")

    severity_gate = str(config.severity_gate or "P1").strip().upper()
    return {
        "schema_version": "1",
        "tool_contract_sha256": tool_digest,
        "effective_scan_mode": str(effective_scan_mode or "").strip().lower(),
        "fork_execution_mode": str(fork_execution_mode or "").strip().lower(),
        "severity_gate": severity_gate,
        "llm_failure_policy": str(config.llm_failure_policy or "").strip().lower(),
        "llm": {
            "provider": str(config.llm_provider or "").strip().lower(),
            "primary_model": str(config.model or "").strip(),
            "fallback_model": str(config.model_fallback or "").strip(),
            "use_codex": bool(config.use_codex),
            "codex_only": bool(config.codex_only),
            "codex_model": str(config.codex_model or "").strip(),
            "codex_timeout_seconds": int(config.codex_timeout),
            "effective_managed_proxy": bool(config.use_managed_llm_proxy()),
            "max_input_tokens": int(config.max_input_tokens),
        },
        "harness": {
            "enabled": bool(config.run_harness),
            "pip_audit_ignore_ids": _normalize_pip_audit_ignore_ids(
                config.pip_audit_ignore_ids
            ),
        },
        "sentinelayer_spec_id": str(config.sentinelayer_spec_id or "")
        .strip()
        .lower(),
    }


def compute_idempotency_key(
    repo: str,
    pr_number: int,
    head_sha: str,
    scan_mode: str,
    policy_pack: str,
    policy_pack_version: str,
    action_major_version: str,
    *,
    subject_contract: Mapping[str, Any],
    comment_tag: str = "",
) -> str:
    # P0: do NOT truncate; show shortened form only for display
    payload = (
        f"{repo}:{pr_number}:{head_sha}:{scan_mode}:{policy_pack}:"
        f"{policy_pack_version}:{action_major_version}"
    )
    contract_json = json.dumps(
        subject_contract,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    contract_digest = hashlib.sha256(contract_json.encode("utf-8")).hexdigest()
    payload = f"{payload}:subject={contract_digest}"
    tag = str(comment_tag or "").strip().lower()
    tag = re.sub(r"[^a-z0-9_-]+", "-", tag)
    tag = re.sub(r"-{2,}", "-", tag).strip("-_")
    if tag:
        payload = f"{payload}:{tag}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
