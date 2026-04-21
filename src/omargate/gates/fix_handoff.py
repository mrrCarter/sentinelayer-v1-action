"""Audit → fix handoff (#A26). User opts into a persona-driven fix attempt.

When a PR reviewer comments `/omar fix <finding_id>` (optionally with
`--persona <id>`), this module:
  1. Parses the command out of the comment body.
  2. Checks a per-build rate limit (so a noisy reviewer can't explode cost).
  3. Selects the owning persona for the finding (or uses the --persona
     override) and builds a code-gen-mode dispatch plan.
  4. Packages a result object for the webhook handler to use when
     spawning the persona CLI and opening the follow-up PR.

The actual subprocess spawn + branch-creation + gh-pr-create calls live
at the webhook/action layer (too coupled to the GitHub runtime to unit-
test here). This module exposes only the parsing / decision-making /
plan-building surface so it's fully unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .findings import Finding

# Kept in sync with persona_dispatch.KNOWN_PERSONAS (same PR family, #A25/#A26).
# Inlined here so this module is importable before persona_dispatch lands on
# main; both resolve to the same 13 canonical personas.
KNOWN_PERSONAS = frozenset(
    {
        "security",
        "backend",
        "testing",
        "code-quality",
        "data-layer",
        "documentation",
        "reliability",
        "release",
        "observability",
        "infrastructure",
        "supply-chain",
        "ai-governance",
        "frontend",
    }
)


__all__ = [
    "FixCommand",
    "FixDecision",
    "FixPlan",
    "DEFAULT_PER_BUILD_FIX_LIMIT",
    "compose_followup_pr_body",
    "build_fix_plan",
    "parse_fix_command",
    "should_accept_fix",
    "select_persona_for_finding",
]


DEFAULT_PER_BUILD_FIX_LIMIT = 3
DEFAULT_MAX_TOKEN_BUDGET_USD = 2.0

# `/omar fix <finding_id>` or `/omar fix <finding_id> --persona <persona_id>`
_FIX_CMD_PATTERN = re.compile(
    r"""
    (?:^|\s)                                   # start of string or whitespace
    /omar                                      # bot handle
    \s+                                        # separator
    fix                                        # verb
    \s+                                        # separator
    (?P<finding_id>[A-Za-z0-9._:/\-]+)         # finding id
    (?:\s+--persona\s+(?P<persona>[A-Za-z0-9_\-]+))?   # optional persona override
    (?:\s+--reason\s+(?P<reason>.{1,200}))?    # optional reason
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class FixCommand:
    """Parsed representation of a `/omar fix …` PR comment."""

    finding_id: str
    persona_override: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class FixDecision:
    """Whether we're going to honor a fix command."""

    accepted: bool
    reason: str                          # human-readable rationale
    rate_limited: bool = False
    already_attempted: bool = False


@dataclass(frozen=True)
class FixPlan:
    """Code-gen-mode dispatch plan for a single finding."""

    finding_id: str
    persona: str
    repo_root: str
    files: tuple[str, ...]
    prompt_context: str
    token_budget_usd: float = DEFAULT_MAX_TOKEN_BUDGET_USD
    branch_name: str = ""
    base_branch: str = "main"


def parse_fix_command(comment_body: str) -> FixCommand | None:
    """Return the parsed command or None if the body is not a fix request."""
    if not comment_body or not isinstance(comment_body, str):
        return None
    match = _FIX_CMD_PATTERN.search(comment_body)
    if not match:
        return None
    finding_id = (match.group("finding_id") or "").strip()
    persona = (match.group("persona") or "").strip().lower() or None
    reason = (match.group("reason") or "").strip() or None
    if persona is not None and persona not in KNOWN_PERSONAS:
        # Unknown persona override → fall back to ownership-map lookup
        persona = None
    if not finding_id:
        return None
    return FixCommand(finding_id=finding_id, persona_override=persona, reason=reason)


def should_accept_fix(
    finding_id: str,
    *,
    already_attempted_finding_ids: Sequence[str] = (),
    fixes_in_current_build: int = 0,
    per_build_limit: int = DEFAULT_PER_BUILD_FIX_LIMIT,
) -> FixDecision:
    """Apply the rate limit + dedupe rules."""
    if finding_id in set(already_attempted_finding_ids):
        return FixDecision(
            accepted=False,
            reason=f"finding {finding_id} already attempted in this build",
            already_attempted=True,
        )
    if fixes_in_current_build >= per_build_limit:
        return FixDecision(
            accepted=False,
            reason=f"per-build fix limit ({per_build_limit}) reached",
            rate_limited=True,
        )
    return FixDecision(accepted=True, reason=f"accepted /omar fix {finding_id}")


def select_persona_for_finding(
    finding: Finding,
    *,
    ownership_map: dict[str, str] | None = None,
    override: str | None = None,
) -> str | None:
    """Resolve the persona to dispatch to.

    Precedence:
      1. Explicit --persona override from the comment, if valid.
      2. Ownership map lookup on the finding's file.
      3. The finding's own `tool` field if that's a known persona id.
      4. None — caller should surface a 'no owner' reply.
    """
    if override and override in KNOWN_PERSONAS:
        return override
    file_path = str(finding.file or "").strip().replace("\\", "/")
    if ownership_map and file_path:
        candidate = str(ownership_map.get(file_path, "")).strip().lower()
        if candidate in KNOWN_PERSONAS:
            return candidate
    tool = str(finding.tool or "").strip().lower()
    if tool in KNOWN_PERSONAS:
        return tool
    return None


def build_fix_plan(
    finding: Finding,
    *,
    repo_root: str,
    base_branch: str = "main",
    ownership_map: dict[str, str] | None = None,
    override: str | None = None,
    token_budget_usd: float = DEFAULT_MAX_TOKEN_BUDGET_USD,
) -> FixPlan | None:
    """Build the code-gen dispatch plan for the webhook handler to run."""
    persona = select_persona_for_finding(
        finding,
        ownership_map=ownership_map,
        override=override,
    )
    if not persona:
        return None
    file_path = str(finding.file or "").strip().replace("\\", "/")
    files = (file_path,) if file_path else ()
    branch_name = _build_branch_name(finding, persona)
    prompt_context = _build_prompt_context(finding)
    return FixPlan(
        finding_id=_finding_id(finding),
        persona=persona,
        repo_root=str(repo_root),
        files=files,
        prompt_context=prompt_context,
        token_budget_usd=float(token_budget_usd),
        branch_name=branch_name,
        base_branch=base_branch,
    )


def compose_followup_pr_body(
    *,
    finding: Finding,
    persona: str,
    summary: str,
    tokens_used: int = 0,
    cost_usd: float = 0.0,
) -> str:
    """Render the markdown body for the follow-up PR."""
    fid = _finding_id(finding)
    lines = [
        f"### Fix attempt for `{fid}`",
        "",
        f"- **Persona:** `{persona}` (code-gen mode)",
        f"- **Finding:** {finding.title}",
        f"- **File:** `{finding.file}:{finding.line}`",
        f"- **Severity:** `{finding.severity}`",
        f"- **Tokens:** {tokens_used}",
        f"- **Cost:** ${cost_usd:.4f}",
        "",
        "#### Summary",
        "",
        summary.strip() or "_(persona did not provide a summary)_",
        "",
        "---",
        "",
        "_This PR was generated by Omar Gate's `/omar fix` handoff (#A26). "
        "Close it if the approach is wrong; merge if the fix is correct._",
    ]
    return "\n".join(lines)


def _finding_id(finding: Finding) -> str:
    if finding.rule_id:
        return str(finding.rule_id)
    base = finding.file.replace("/", "-").replace("\\", "-")
    return f"{finding.gate_id}:{base}:{finding.line}"


def _build_branch_name(finding: Finding, persona: str) -> str:
    # Deterministic-enough to dedupe across retries; keep it git-safe.
    fid = _finding_id(finding)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", fid).strip("-").lower()[:60]
    return f"omar-fix/{persona}/{slug}"


def _build_prompt_context(finding: Finding) -> str:
    return "\n".join(
        [
            f"FINDING: {finding.title}",
            f"FILE: {finding.file}:{finding.line}",
            f"SEVERITY: {finding.severity}",
            f"GATE: {finding.gate_id} / {finding.tool}",
            f"DESCRIPTION: {finding.description}" if finding.description else "",
            f"EVIDENCE: {finding.evidence}" if finding.evidence else "",
            f"RECOMMENDED FIX: {finding.recommended_fix}" if finding.recommended_fix else "",
        ]
    ).strip()
