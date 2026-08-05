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
    for relative_path in (
        "action.yml",
        "requirements.lock.txt",
        "Dockerfile",
        ".dockerignore",
        "entrypoint.sh",
    ):
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


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def resolve_spec_context_contract(
    configured_spec_id: str,
    spec_context: Mapping[str, Any] | None,
) -> tuple[str, str]:
    """Validate fetched spec identity and return availability plus content digest."""

    expected = str(configured_spec_id or "").strip().lower()
    if not expected:
        return "not_configured", ""
    if spec_context is None:
        return "unavailable", ""

    observed = str(spec_context.get("spec_hash") or "").strip().lower()
    if observed != expected:
        raise RuntimeError(
            "Fetched Sentinelayer spec context does not match the configured spec id"
        )
    canonical_context = dict(spec_context)
    canonical_context["spec_hash"] = expected
    digest = hashlib.sha256(
        _canonical_json(canonical_context).encode("utf-8")
    ).hexdigest()
    return "loaded", digest


def build_analysis_subject_contract(
    config: "OmarGateConfig",
    *,
    effective_scan_mode: str,
    fork_execution_mode: str,
    tool_contract_sha256: str,
    spec_context_state: str,
    spec_context_sha256: str,
) -> dict[str, Any]:
    """Return the non-secret policy/tool profile whose evidence may be reused."""

    tool_digest = str(tool_contract_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", tool_digest):
        raise ValueError("tool_contract_sha256 must be a 64-character lowercase hex digest")

    spec_state = str(spec_context_state or "").strip().lower()
    if spec_state not in {"not_configured", "unavailable", "loaded"}:
        raise ValueError("invalid spec_context_state")
    spec_digest = str(spec_context_sha256 or "").strip().lower()
    if spec_state == "loaded":
        if not re.fullmatch(r"[0-9a-f]{64}", spec_digest):
            raise ValueError("loaded spec context requires a SHA-256 digest")
    elif spec_digest:
        raise ValueError("unloaded spec context cannot carry a digest")

    severity_gate = str(config.severity_gate or "P1").strip().upper()
    credential_routes_available = {
        "openai_byo": bool(config.openai_api_key.get_secret_value()),
        "anthropic_byo": bool(config.anthropic_api_key.get_secret_value()),
        "google_byo": bool(config.google_api_key.get_secret_value()),
        "xai_byo": bool(config.xai_api_key.get_secret_value()),
        "sentinelayer_managed": bool(
            config.sentinelayer_token.get_secret_value()
        ),
    }
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
            "managed_capacity_fallback": bool(
                config.sentinelayer_managed_llm
                and config.sentinelayer_token.get_secret_value()
            ),
            "credential_routes_available": credential_routes_available,
            "max_input_tokens": int(config.max_input_tokens),
        },
        "harness": {
            "enabled": bool(config.run_harness),
            "pip_audit_ignore_ids": _normalize_pip_audit_ignore_ids(
                config.pip_audit_ignore_ids
            ),
        },
        "sentinelayer_spec": {
            "id": str(config.sentinelayer_spec_id or "").strip().lower(),
            "context_state": spec_state,
            "context_sha256": spec_digest,
        },
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
    contract_json = _canonical_json(subject_contract)
    contract_digest = hashlib.sha256(contract_json.encode("utf-8")).hexdigest()
    tag = str(comment_tag or "").strip().lower()
    tag = re.sub(r"[^a-z0-9_-]+", "-", tag)
    tag = re.sub(r"-{2,}", "-", tag).strip("-_")
    payload = _canonical_json(
        {
            "schema_version": "1",
            "repo": str(repo),
            "pr_number": int(pr_number),
            "head_sha": str(head_sha),
            "scan_mode": str(scan_mode),
            "policy_pack": str(policy_pack),
            "policy_pack_version": str(policy_pack_version),
            "action_contract_version": str(action_major_version),
            "subject_contract_sha256": contract_digest,
            "comment_tag": tag,
        }
    )
    # P0: do NOT truncate; show shortened form only for display.
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
