from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ...ingest.quick_learn import QuickLearnSummary


# Persona is proprietary to the Omar Pack and must remain inline (not externalized).
_PERSONA_SYSTEM_PROMPT = """You are Omar Singh, a senior CI/CD and release engineering specialist.

Background: You spent years building deployment pipelines at scale. You believe that
if something isn't automated, it doesn't exist. You are strict about deterministic
builds, gating checks, and rollback readiness.

Your core question for every review: "Can we deploy this safely, repeatedly, and
recover quickly if it fails?"

What you are strict about:
- Deterministic, reproducible builds
- Proper gating checks (lint -> test -> security -> build -> deploy)
- Artifact integrity and provenance
- Rollback procedures being tested and documented
- Pipeline stages being complete (no skipped gates)

Red flags you ALWAYS escalate to P0:
- Production deployment without tests passing
- No rollback plan or procedure
- Secrets exposed in CI/CD workflows or logs
- Manual steps in what should be an automated pipeline

Your review style:
- You read code changes through the lens of "what happens when this deploys?"
- You check that error handling covers deployment failure scenarios
- You verify that config changes won't break other environments
- You look for missing validation at system boundaries
- You consider the blast radius of every change

Backend reliability checks (always apply):
- Every network call must have a timeout
- Write/mutation endpoints must be idempotent
- Rate limiting must fail-closed (never fail-open)
- Error responses must follow a consistent schema with requestId
- Auth/authz enforcement must be present on all protected routes
- Retries must have bounds (no infinite retry loops)
- External service calls need circuit breaker or fallback patterns
"""


TRUNCATION_MARKER = "... (truncated)"


@dataclass(frozen=True)
class BuiltCodexPrompt:
    prompt: str
    token_count: int
    files_included: List[str]
    files_truncated: List[str]


class CodexPromptBuilder:
    """
    Build the non-interactive Codex prompt with a strict token budget.

    The prompt includes:
    - Omar persona (inline system-style instructions)
    - Quick Learn project summary
    - Deterministic findings summary
    - PR diff or hotspot files (budget controlled)
    - Stack-aware engineering quality checklist
    - JSONL-only output contract
    """

    def __init__(self, max_tokens: int = 100000, chars_per_token: float = 4.0) -> None:
        self.max_tokens = int(max_tokens)
        self.chars_per_token = float(chars_per_token)

    def estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        return int(len(text) / self.chars_per_token)

    def build_prompt(
        self,
        *,
        repo_root: Path,
        quick_learn: Optional[QuickLearnSummary],
        deterministic_findings: List[dict],
        tech_stack: list[str],
        scan_mode: str,
        diff_content: Optional[str] = None,
        hotspot_files: Optional[List[str]] = None,
    ) -> BuiltCodexPrompt:
        repo_root = repo_root.resolve()
        deterministic_findings = deterministic_findings or []
        tech_stack = tech_stack or []

        parts: List[str] = []
        used_tokens = 0
        files_included: List[str] = []
        files_truncated: List[str] = []

        def add(text: str, allow_truncate: bool = False) -> None:
            nonlocal used_tokens
            if not text:
                return
            remaining = self.max_tokens - used_tokens
            if remaining <= 0:
                return
            tokens = self.estimate_tokens(text)
            if tokens <= remaining:
                parts.append(text)
                used_tokens += tokens
                return
            if not allow_truncate:
                return
            max_chars = int(remaining * self.chars_per_token)
            if max_chars <= 0:
                return
            truncated = text[:max_chars]
            if "\n" in truncated:
                truncated = truncated.rsplit("\n", 1)[0] + "\n"
            parts.append(truncated)
            used_tokens += self.estimate_tokens(truncated)

        add(self._build_persona_section())
        add(self._build_project_context(quick_learn), allow_truncate=True)
        add(self._build_deterministic_summary(deterministic_findings))
        add(self._build_task_instructions(tech_stack))

        if scan_mode == "pr-diff" and diff_content:
            add("## Code to Review (PR Diff)\n", allow_truncate=False)
            add(f"{diff_content.strip()}\n\n", allow_truncate=True)
        else:
            selected = self._select_hotspot_files(hotspot_files or [])
            if selected:
                add("## Code to Review (Hotspot Files)\n")
                for rel_path in selected:
                    content = self._read_file_bounded(repo_root / rel_path)
                    if not content:
                        continue
                    header = f"### File: {rel_path}\n"
                    header_tokens = self.estimate_tokens(header)
                    if self.max_tokens - used_tokens <= header_tokens:
                        break
                    add(header)
                    before = used_tokens
                    add(f"```text\n{content}\n```\n\n", allow_truncate=True)
                    files_included.append(rel_path)
                    if used_tokens == before:
                        # Couldn't fit content; drop the header we added.
                        parts.pop()
                        used_tokens -= header_tokens
                        files_included.pop()
                        break
                    if content.endswith(TRUNCATION_MARKER):
                        files_truncated.append(rel_path)

        add(self._build_output_contract())

        prompt = "".join(parts)
        token_count = min(self.max_tokens, used_tokens)
        return BuiltCodexPrompt(
            prompt=prompt,
            token_count=token_count,
            files_included=files_included,
            files_truncated=files_truncated,
        )

    def _build_persona_section(self) -> str:
        return (
            "# System\n"
            f"{_PERSONA_SYSTEM_PROMPT.strip()}\n\n"
            "# Security & Engineering Audit\n\n"
        )

    def _build_project_context(self, quick_learn: Optional[QuickLearnSummary]) -> str:
        if not quick_learn:
            return "## Project Context\nunknown\n\n"
        stack = ", ".join(quick_learn.tech_stack) if quick_learn.tech_stack else "unknown"
        entry_points = (
            ", ".join(quick_learn.entry_points) if quick_learn.entry_points else "unknown"
        )
        desc = (quick_learn.description or "").strip()
        if len(desc) > 100:
            desc = desc[:97] + "..."
        return (
            "## Project Context\n"
            f"- Project: {quick_learn.project_name or 'unknown'}\n"
            f"- Description: {desc}\n"
            f"- Tech stack: {stack}\n"
            f"- Architecture: {quick_learn.architecture or 'unknown'}\n"
            f"- Entry points: {entry_points}\n\n"
        )

    def _build_deterministic_summary(self, findings: List[dict]) -> str:
        if not findings:
            return "## Already Found (Deterministic)\n0 findings.\n\n"
        lines = [
            "## Already Found (Deterministic)",
            f"{len(findings)} findings already identified by automated scanners.",
            "Focus on issues that require code understanding beyond pattern matching.",
            "",
        ]
        for f in findings[:20]:
            lines.append(
                "- {severity}: {message} ({file}:{line})".format(
                    severity=f.get("severity", "?"),
                    message=(f.get("message", "?") or "").strip(),
                    file=f.get("file_path", "?"),
                    line=f.get("line_start", "?"),
                )
            )
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        return "\n".join(lines) + "\n\n"

    def _build_task_instructions(self, tech_stack: list[str]) -> str:
        checklist = self._build_engineering_checklist(tech_stack)
        stack = ", ".join(tech_stack) if tech_stack else "unknown"
        return (
            "## Your Task\n"
            "Review the code for:\n"
            "1. Security vulnerabilities (P0-P3)\n"
            "2. Deployment and release safety (can this be safely shipped?)\n"
            "3. Backend reliability (timeouts, idempotency, error handling, rate limits)\n"
            "4. Logic errors, race conditions, and architectural issues\n"
            "5. Missing input validation and edge cases at system boundaries\n\n"
            "## Severity Scale\n"
            "- P0: Critical\n"
            "- P1: High\n"
            "- P2: Medium\n"
            "- P3: Low\n\n"
            f"## Engineering Quality Checks ({stack})\n"
            f"{checklist}\n\n"
        )

    def _build_engineering_checklist(self, tech_stack: list[str]) -> str:
        stack = [t.lower() for t in (tech_stack or [])]
        joined = " ".join(stack)

        checks: list[str] = [
            "- Deterministic builds (lockfiles, pinned deps, no floating versions)",
            "- Proper gating (lint -> test -> security -> build -> deploy), no skipped steps",
            "- Artifact integrity/provenance, versioning, and rollback readiness",
            "- Secrets are never printed in CI logs or embedded in config",
            "- Network calls have timeouts; retries are bounded with backoff",
            "- Rate limiting fails closed; auth/authz is enforced on protected routes",
            "- Mutations are idempotent where applicable; request/trace IDs are consistent",
        ]

        is_frontend = any(m in joined for m in ("react", "next", "vue", "angular"))
        is_backend = any(m in joined for m in ("node", "express", "django", "fastapi", "go", "python"))

        if is_frontend:
            checks.extend(
                [
                    "- Avoid dangerouslySetInnerHTML or sanitize strictly",
                    "- useEffect dependencies and cleanup correctness",
                    "- No console.log/debug artifacts in production code paths",
                    "- Avoid per-render inline object/function props in hot components",
                ]
            )

        if is_backend:
            checks.extend(
                [
                    "- Avoid SQL string concatenation; use parameterized queries",
                    "- Avoid eval/new Function; prevent RCE",
                    "- External service calls have fallbacks/circuit breakers",
                    "- Auth endpoints have rate limiting and do not fail open",
                ]
            )

        return "\n".join(checks)

    def _build_output_contract(self) -> str:
        return (
            "## Output Format\n"
            "Output ONLY valid JSONL (one JSON object per line). Use this schema:\n"
            '{"severity":"P1","category":"auth","file_path":"src/auth.ts","line_start":42,'
            '"line_end":45,"message":"...","recommendation":"...","confidence":0.85}\n'
            "\nIf no findings, output exactly:\n"
            '{"no_findings": true}\n'
            "\nDo not include markdown fences or commentary.\n"
        )

    def _select_hotspot_files(self, hotspot_files: List[str]) -> List[str]:
        seen: set[str] = set()
        selected: List[str] = []
        for rel_path in hotspot_files:
            if not rel_path or rel_path in seen:
                continue
            normalized = rel_path.replace("\\", "/")
            if self._is_excluded_path(normalized):
                continue
            seen.add(rel_path)
            selected.append(rel_path)
            if len(selected) >= 12:
                break
        return selected

    def _is_excluded_path(self, rel_path: str) -> bool:
        p = rel_path.lower()
        if p.startswith("tests/") or "/tests/" in p:
            return True
        if "__tests__" in p or ".spec." in p or ".test." in p:
            return True
        if p.startswith("dist/") or "/dist/" in p or p.startswith("build/") or "/build/" in p:
            return True
        if p.endswith(".min.js") or p.endswith(".min.css"):
            return True
        return False

    def _read_file_bounded(self, file_path: Path, max_lines: int = 350, max_bytes: int = 250_000) -> str:
        try:
            if file_path.stat().st_size > max_bytes:
                return ""
        except OSError:
            return ""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        lines = content.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True
        bounded = "\n".join(lines)
        if truncated:
            if bounded and not bounded.endswith("\n"):
                bounded += "\n"
            bounded += TRUNCATION_MARKER
        return bounded

