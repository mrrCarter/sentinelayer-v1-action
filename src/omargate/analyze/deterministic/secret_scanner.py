from __future__ import annotations

from bisect import bisect_right
from typing import List, Tuple

import math
import re

from .pattern_scanner import Finding, mask_secret_in_snippet

MAX_SNIPPET_CHARS = 500
ENTROPY_THRESHOLD = 4.0

# Matches obvious code identifiers that should not be flagged as secrets.
# Only skip strings that clearly follow naming conventions with underscores
# (snake_case, SCREAMING_SNAKE). Pure alphanumeric strings are NOT skipped
# because high-entropy secrets can also be purely alphanumeric.
_CODE_IDENTIFIER_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+){2,}$"  # snake_case with 3+ segments
)
_COMMENT_LINE_RE = re.compile(r"^\s*(?://|#|\*|/\*)")

_SECRET_PATTERNS = [
    {
        "id": "SEC-004",
        "name": "AWS Access Key",
        "severity": "P0",
        "category": "secrets",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "message": "AWS access key detected",
        "recommendation": "Revoke and rotate the key, use environment variables",
    },
    {
        "id": "SEC-005",
        "name": "GitHub Token",
        "severity": "P0",
        "category": "secrets",
        "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "message": "GitHub token detected",
        "recommendation": "Revoke and rotate the token, use GitHub Secrets",
    },
    {
        "id": "SEC-013",
        "name": "Stripe Secret Key",
        "severity": "P1",
        "category": "secrets",
        "regex": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
        "message": "Stripe secret key detected",
        "recommendation": "Revoke and rotate the key, use a secrets manager",
    },
]

_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    frequencies = {}
    for char in s:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def _truncate_snippet(snippet: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    if len(snippet) <= max_chars:
        return snippet
    if max_chars <= 3:
        return snippet[:max_chars]
    return f"{snippet[: max_chars - 3]}..."


def _build_line_starts(content: str) -> List[int]:
    line_starts: List[int] = []
    offset = 0
    for line in content.splitlines(keepends=True):
        line_starts.append(offset)
        offset += len(line)
    if not line_starts:
        line_starts.append(0)
    return line_starts


def _index_to_line(line_starts: List[int], idx: int) -> int:
    return bisect_right(line_starts, idx)


def _snippet_from_lines(lines: List[str], line_start: int, line_end: int) -> str:
    if not lines:
        return ""
    start_idx = max(line_start - 1, 0)
    end_idx = min(line_end, len(lines))
    return "\n".join(lines[start_idx:end_idx])


def _overlaps(span: Tuple[int, int], spans: List[Tuple[int, int]]) -> bool:
    for other in spans:
        if span[0] < other[1] and other[0] < span[1]:
            return True
    return False


def scan_for_secrets(content: str, file_path: str) -> List[Finding]:
    line_starts = _build_line_starts(content)
    lines = content.splitlines()
    findings: List[Finding] = []
    matched_spans: List[Tuple[int, int]] = []

    for pattern in _SECRET_PATTERNS:
        for match in pattern["regex"].finditer(content):
            line_start = _index_to_line(line_starts, match.start())
            # Skip matches on comment lines (regex definitions, documentation, etc.)
            source_line = lines[line_start - 1] if line_start <= len(lines) else ""
            if _COMMENT_LINE_RE.match(source_line):
                continue
            # Skip matches inside regex literals (e.g. /AKIA[0-9A-Z]{16}/)
            if re.search(r"[/=]\s*/.+/", source_line):
                continue
            matched_spans.append(match.span())
            end_index = max(match.end() - 1, match.start())
            line_end = _index_to_line(line_starts, end_index)
            snippet = _snippet_from_lines(lines, line_start, line_end)
            snippet = mask_secret_in_snippet(snippet, "secrets")
            snippet = _truncate_snippet(snippet)
            findings.append(
                Finding(
                    id=f"{pattern['id']}-{file_path}-{line_start}",
                    pattern_id=pattern["id"],
                    severity=pattern["severity"],
                    category=pattern["category"],
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=snippet,
                    message=pattern["message"],
                    recommendation=pattern["recommendation"],
                    confidence=1.0,
                )
            )

    for match in _ENTROPY_CANDIDATE_RE.finditer(content):
        if _overlaps(match.span(), matched_spans):
            continue
        candidate = match.group(0)
        if calculate_entropy(candidate) < ENTROPY_THRESHOLD:
            continue
        # Skip common code identifiers (camelCase, snake_case, etc.)
        if _CODE_IDENTIFIER_RE.match(candidate):
            continue
        # Skip candidates on comment lines
        line_start = _index_to_line(line_starts, match.start())
        source_line = lines[line_start - 1] if line_start <= len(lines) else ""
        if _COMMENT_LINE_RE.match(source_line):
            continue
        end_index = max(match.end() - 1, match.start())
        line_end = _index_to_line(line_starts, end_index)
        snippet = _snippet_from_lines(lines, line_start, line_end)
        snippet = mask_secret_in_snippet(snippet, "secrets")
        snippet = _truncate_snippet(snippet)
        findings.append(
            Finding(
                id=f"SEC-ENTROPY-{file_path}-{line_start}",
                pattern_id="SEC-ENTROPY",
                severity="P1",
                category="secrets",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                snippet=snippet,
                message="High-entropy string detected",
                recommendation="Move secrets to a secure store and rotate credentials",
                confidence=1.0,
            )
        )

    return findings
