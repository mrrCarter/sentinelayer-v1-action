"""CLI entry point for the `/omar fix <finding_id>` comment handler (#A26).

Invoked as:
    python -m omargate.fix_handoff_cli \\
        --path <repo> \\
        --findings-file <path/to/FINDINGS.jsonl> \\
        --comment-body-file <path/to/comment.md> \\
        [--already-attempted a,b,c] \\
        [--fixes-in-build 0] \\
        [--per-build-limit 3]

Outputs JSON on stdout shaped as:
    {
        "command": { "finding_id": "...", "persona_override": "..." | null,
                     "reason": "..." | null } | null,
        "decision": { "accepted": bool, "reason": "...",
                      "rate_limited": bool, "already_attempted": bool } | null,
        "plan": { "finding_id": "...", "persona": "...", "repo_root": "...",
                  "files": ["..."], "prompt_context": "...",
                  "token_budget_usd": 2.0, "branch_name": "...",
                  "base_branch": "main" } | null,
        "followup_pr_body": "..." | null,
        "error": "..." | null
    }

Exit codes:
    0 — command parsed, decision accepted, plan emitted
    1 — command parsed but rejected (rate limit / dupe / no persona)
    2 — runner error (invalid input, IO failure)
    3 — no `/omar fix` command found in the comment (benign no-op)

The workflow invoker is responsible for actually spawning the persona CLI
in code-gen mode against plan.files + plan.prompt_context, cutting the
branch, committing the diff, and opening the follow-up PR. This module
only handles parse / decide / plan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from .gates.findings import Finding
from .gates.fix_handoff import (
    DEFAULT_MAX_TOKEN_BUDGET_USD,
    DEFAULT_PER_BUILD_FIX_LIMIT,
    build_fix_plan,
    compose_followup_pr_body,
    parse_fix_command,
    should_accept_fix,
)
from .scaffold import parse_scaffold_ownership as _parse_scaffold_ownership


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omargate.fix_handoff_cli",
        description=(
            "Parse a PR comment, match against Omar Gate findings, and emit "
            "a persona-codegen dispatch plan on stdout."
        ),
    )
    parser.add_argument("--path", default=".", help="Repository root (default: cwd)")
    parser.add_argument(
        "--findings-file",
        required=True,
        help="Path to FINDINGS.jsonl produced by local_gates (one JSON finding per line).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--comment-body",
        help="The full body of the triggering PR comment (pass via $(cat comment.md) or similar).",
    )
    group.add_argument(
        "--comment-body-file",
        help="Path to a file containing the triggering PR comment body.",
    )
    parser.add_argument(
        "--already-attempted",
        default="",
        help=(
            "Comma-separated list of finding ids already attempted in the "
            "current build — used for dedupe."
        ),
    )
    parser.add_argument(
        "--fixes-in-build",
        type=int,
        default=0,
        help="Count of fix attempts already accepted in this build (for rate-limit enforcement).",
    )
    parser.add_argument(
        "--per-build-limit",
        type=int,
        default=DEFAULT_PER_BUILD_FIX_LIMIT,
        help=f"Max fix attempts per build (default: {DEFAULT_PER_BUILD_FIX_LIMIT}).",
    )
    parser.add_argument(
        "--base-branch",
        default="main",
        help="Base branch the follow-up PR should target (default: main).",
    )
    parser.add_argument(
        "--token-budget-usd",
        type=float,
        default=DEFAULT_MAX_TOKEN_BUDGET_USD,
        help=f"Token budget for the codegen attempt (default: ${DEFAULT_MAX_TOKEN_BUDGET_USD:.2f}).",
    )
    return parser


def _load_findings(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_num, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # Malformed row — skip but don't abort; FINDINGS.jsonl should be
                # resilient to occasional bad bytes from concurrent writers.
                continue
            findings.append(
                Finding(
                    gate_id=str(row.get("gateId") or row.get("gate_id") or ""),
                    tool=str(row.get("tool") or ""),
                    severity=str(row.get("severity") or "P2"),  # type: ignore[arg-type]
                    file=str(row.get("file") or ""),
                    line=int(row.get("line") or 0),
                    title=str(row.get("title") or ""),
                    description=str(row.get("description") or ""),
                    rule_id=row.get("ruleId") or row.get("rule_id"),
                    confidence=float(row.get("confidence") or 1.0),
                    recommended_fix=row.get("recommendedFix") or row.get("recommended_fix"),
                    evidence=row.get("evidence"),
                )
            )
    return findings


def _match_finding_by_id(findings: Iterable[Finding], finding_id: str) -> Finding | None:
    normalized = finding_id.strip()
    if not normalized:
        return None
    # 1. Match on rule_id (most stable — the Omar comment uses this).
    for f in findings:
        if f.rule_id and str(f.rule_id) == normalized:
            return f
    # 2. Fallback: match on "<gate_id>:<file>:<line>" composite.
    for f in findings:
        composite = f"{f.gate_id}:{f.file.replace('/', '-')}:{f.line}"
        if composite == normalized:
            return f
    return None


def _parse_attempted(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _emit(payload: dict, exit_code: int) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.write("\n")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 2)

    repo_root = Path(args.path).resolve()
    if not repo_root.is_dir():
        return _emit(
            {"error": f"--path does not exist or is not a directory: {repo_root}"},
            2,
        )

    findings_path = Path(args.findings_file)
    if not findings_path.is_file():
        return _emit(
            {"error": f"--findings-file does not exist: {findings_path}"},
            2,
        )

    if args.comment_body_file:
        try:
            comment_body = Path(args.comment_body_file).read_text(encoding="utf-8")
        except OSError as exc:
            return _emit({"error": f"failed to read comment body: {exc}"}, 2)
    else:
        comment_body = args.comment_body or ""

    command = parse_fix_command(comment_body)
    if command is None:
        return _emit(
            {
                "command": None,
                "decision": None,
                "plan": None,
                "followup_pr_body": None,
                "error": None,
            },
            3,
        )

    decision = should_accept_fix(
        command.finding_id,
        already_attempted_finding_ids=_parse_attempted(args.already_attempted),
        fixes_in_current_build=args.fixes_in_build,
        per_build_limit=args.per_build_limit,
    )
    command_payload = {
        "finding_id": command.finding_id,
        "persona_override": command.persona_override,
        "reason": command.reason,
    }
    decision_payload = {
        "accepted": decision.accepted,
        "reason": decision.reason,
        "rate_limited": decision.rate_limited,
        "already_attempted": decision.already_attempted,
    }
    if not decision.accepted:
        return _emit(
            {
                "command": command_payload,
                "decision": decision_payload,
                "plan": None,
                "followup_pr_body": None,
                "error": None,
            },
            1,
        )

    findings = _load_findings(findings_path)
    finding = _match_finding_by_id(findings, command.finding_id)
    if finding is None:
        return _emit(
            {
                "command": command_payload,
                "decision": decision_payload,
                "plan": None,
                "followup_pr_body": None,
                "error": f"finding id {command.finding_id!r} not found in {findings_path}",
            },
            1,
        )

    ownership_map = _parse_scaffold_ownership(
        repo_root / ".sentinelayer" / "scaffold.yaml"
    )
    plan = build_fix_plan(
        finding,
        repo_root=str(repo_root),
        base_branch=args.base_branch,
        ownership_map=ownership_map,
        override=command.persona_override,
        token_budget_usd=args.token_budget_usd,
    )
    if plan is None:
        return _emit(
            {
                "command": command_payload,
                "decision": decision_payload,
                "plan": None,
                "followup_pr_body": None,
                "error": "no persona resolvable for this finding (no override + no ownership + tool is not a known persona)",
            },
            1,
        )

    plan_payload = {
        "finding_id": plan.finding_id,
        "persona": plan.persona,
        "repo_root": plan.repo_root,
        "files": list(plan.files),
        "prompt_context": plan.prompt_context,
        "token_budget_usd": plan.token_budget_usd,
        "branch_name": plan.branch_name,
        "base_branch": plan.base_branch,
    }
    followup_body = compose_followup_pr_body(
        finding=finding,
        persona=plan.persona,
        summary="",  # actual summary is filled in by the caller after codegen runs
    )
    return _emit(
        {
            "command": command_payload,
            "decision": decision_payload,
            "plan": plan_payload,
            "followup_pr_body": followup_body,
            "error": None,
        },
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
