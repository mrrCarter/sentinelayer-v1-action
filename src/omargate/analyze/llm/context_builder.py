from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


TRUNCATION_MARKER = "... (truncated)"


@dataclass
class ContextBudget:
    max_tokens: int
    used_tokens: int
    remaining_tokens: int


@dataclass
class BuiltContext:
    content: str
    token_count: int
    files_included: List[str]
    files_truncated: List[str]
    files_skipped: List[str]
    hotspots_included: List[str]


class ContextBuilder:
    """Build LLM context from ingest data and deterministic findings."""

    def __init__(self, max_tokens: int = 80000, chars_per_token: float = 4.0) -> None:
        self.max_tokens = max_tokens
        self.chars_per_token = chars_per_token

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation."""
        if not text:
            return 0
        return int(len(text) / self.chars_per_token)

    def build_context(
        self,
        ingest: dict,
        deterministic_findings: List[dict],
        repo_root: Path,
        scan_mode: str = "pr-diff",
        diff_content: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
    ) -> BuiltContext:
        """
        Build context for LLM analysis.

        Each section added until budget exhausted.
        """
        ingest = ingest or {}
        context_parts: List[str] = []
        used_tokens = 0

        files_included: List[str] = []
        files_truncated: List[str] = []
        files_skipped: List[str] = []
        hotspots_included: List[str] = []

        def add_with_budget(text: str, allow_truncate: bool = False) -> tuple[bool, bool, int]:
            nonlocal used_tokens
            if not text:
                return False, False, 0
            remaining = self.max_tokens - used_tokens
            if remaining <= 0:
                return False, False, 0
            tokens = self.estimate_tokens(text)
            if tokens <= remaining:
                context_parts.append(text)
                used_tokens += tokens
                return True, False, tokens
            if not allow_truncate:
                return False, False, 0
            max_chars = int(remaining * self.chars_per_token)
            if max_chars <= 0:
                return False, False, 0
            truncated_text = text[:max_chars]
            if "\n" in truncated_text:
                truncated_text = truncated_text.rsplit("\n", 1)[0] + "\n"
            truncated_tokens = self.estimate_tokens(truncated_text)
            if truncated_tokens <= 0:
                return False, False, 0
            context_parts.append(truncated_text)
            used_tokens += truncated_tokens
            return True, True, truncated_tokens

        system_context = self._build_system_context(ingest)
        add_with_budget(system_context)

        deterministic_context = self._build_deterministic_context(deterministic_findings)
        add_with_budget(deterministic_context)

        if scan_mode == "pr-diff" and diff_content:
            diff_section = f"## PR Diff\n{diff_content.strip()}\n"
            add_with_budget(diff_section, allow_truncate=True)

        priority_files = self._prioritize_files(ingest, changed_files, scan_mode)
        hotspot_set = set()
        for files in ingest.get("hotspots", {}).values():
            hotspot_set.update(files)

        for rel_path in priority_files:
            if rel_path in files_included or rel_path in files_skipped:
                continue
            file_path = repo_root / rel_path
            content = self._read_file_bounded(file_path)
            if not content:
                files_skipped.append(rel_path)
                continue

            header = f"## File: {rel_path}\n"
            header_tokens = self.estimate_tokens(header)
            remaining = self.max_tokens - used_tokens
            if remaining <= header_tokens:
                files_skipped.append(rel_path)
                continue

            header_added, _, _ = add_with_budget(header)
            if not header_added:
                files_skipped.append(rel_path)
                continue

            added, truncated, _ = add_with_budget(f"{content}\n", allow_truncate=True)
            if not added:
                context_parts.pop()
                used_tokens -= header_tokens
                files_skipped.append(rel_path)
                continue

            files_included.append(rel_path)
            if truncated or content.endswith(TRUNCATION_MARKER):
                files_truncated.append(rel_path)
            if rel_path in hotspot_set:
                hotspots_included.append(rel_path)

        content = "".join(context_parts)
        token_count = min(self.max_tokens, used_tokens)

        return BuiltContext(
            content=content,
            token_count=token_count,
            files_included=files_included,
            files_truncated=files_truncated,
            files_skipped=files_skipped,
            hotspots_included=hotspots_included,
        )

    def _build_system_context(self, ingest: dict) -> str:
        """Build system context header."""
        stats = ingest.get("stats", {})
        dependencies = ingest.get("dependencies", {})
        return (
            "## Repository Overview\n"
            f"- Total files: {stats.get('total_files', '?')}\n"
            f"- In-scope files: {stats.get('in_scope_files', '?')}\n"
            f"- Total lines: {stats.get('total_lines', '?')}\n"
            f"- Package manager: {dependencies.get('package_manager', 'unknown')}\n\n"
            "## Hotspot Categories\n"
            f"{self._format_hotspots(ingest.get('hotspots', {}))}\n"
        )

    def _build_deterministic_context(self, findings: List[dict]) -> str:
        """Summarize deterministic findings for LLM context."""
        if not findings:
            return "## Deterministic Scan Results\nNo issues detected by pattern scanners.\n"

        lines = ["## Deterministic Scan Results", f"Found {len(findings)} issues:", ""]
        for finding in findings[:20]:
            lines.append(
                "- {severity}: {message} in {file_path}:{line_start}".format(
                    severity=finding.get("severity", "?"),
                    message=finding.get("message", "?"),
                    file_path=finding.get("file_path", "?"),
                    line_start=finding.get("line_start", "?"),
                )
            )
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        return "\n".join(lines) + "\n"

    def _format_hotspots(self, hotspots: Dict[str, List[str]]) -> str:
        if not hotspots:
            return "- (none detected)"
        lines = []
        for category, files in hotspots.items():
            if not files:
                continue
            lines.append(f"- {category}: {len(files)} files")
        if not lines:
            return "- (none detected)"
        return "\n".join(lines)

    def _read_file_bounded(self, file_path: Path, max_lines: int = 500) -> str:
        """Read file content with line limit."""
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

    def _prioritize_files(
        self, ingest: dict, changed_files: Optional[List[str]], scan_mode: str
    ) -> List[str]:
        """Return files in priority order for context inclusion."""
        priority: List[str] = []

        if scan_mode == "pr-diff" and changed_files:
            for rel_path in changed_files:
                if rel_path not in priority:
                    priority.append(rel_path)

        for files in ingest.get("hotspots", {}).values():
            for rel_path in files:
                if rel_path not in priority:
                    priority.append(rel_path)

        for file_info in ingest.get("files", []):
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            if file_info.get("category") != "source":
                continue
            if rel_path in priority:
                continue
            priority.append(rel_path)

        return priority
