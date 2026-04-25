"""LLM-judge Finding contract (#A6).

Per CODEX_OMARGATE_COMBINE_SPEC.md §5.3: the layer-7 LLM judge emits
findings that must meet a stricter bar than deterministic gates. This
module enforces:
  - confidence >= per-severity floor (calibrated multi-tier)
  - category ∈ fixed enum
  - HARD_EXCLUSIONS: classes of findings we refuse to surface
  - PRECEDENTS: contexts where a pattern is known-safe and should not
    produce a finding

Per-severity confidence floors (PR 3 of the engine improvement plan,
2026-04-25): replaces the single 0.8 floor with a calibrated tier so
P3 noise drops sharply while P0 true-positives still surface at 0.6+.
The contents are lifted from src/commands/security-review.ts:143-176
(Claude Code CLI internals — clean-room reference per spec §3.3).

The module is pure — takes a list of raw Finding-shaped dicts produced
by an LLM and returns a filtered list of validated Finding objects plus
per-rejection diagnostics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .findings import Finding

__all__ = [
    "CONFIDENCE_FLOOR",
    "CONFIDENCE_FLOORS",
    "HARD_EXCLUSIONS",
    "PRECEDENTS",
    "SUPPORTED_CATEGORIES",
    "RejectedFinding",
    "FilterResult",
    "filter_llm_findings",
]

# Calibrated per-severity confidence floors. P0 has a low floor because
# critical findings shouldn't be silenced by minor confidence dips; P3
# has a near-1.0 floor because P3-tier noise is the largest false-positive
# class and should only surface when the LLM is essentially certain.
#
# Tier values from the engine improvement plan:
#   P0 = 0.60   critical: low floor, prefer over-reporting
#   P1 = 0.75   high: moderate floor
#   P2 = 0.85   medium: was the global floor in the prior contract
#   P3 = 0.95   low: only surface near-certain low-severity findings
CONFIDENCE_FLOORS: dict[str, float] = {
    "P0": 0.60,
    "P1": 0.75,
    "P2": 0.85,
    "P3": 0.95,
}

# Back-compat: callers that referenced CONFIDENCE_FLOOR directly continue
# to see the prior 0.8 default. New code should use CONFIDENCE_FLOORS or
# pass severity to the helper functions.
CONFIDENCE_FLOOR = 0.8

# Categories the LLM is allowed to emit. Anything outside this set is
# rejected. This keeps the emission surface narrow and prevents the LLM
# from inventing categories that don't map to our severity / dispatch
# logic.
SUPPORTED_CATEGORIES: frozenset[str] = frozenset({
    "sql_injection",
    "xss",
    "auth_bypass",
    "crypto_flaws",
    "data_exposure",
    "rce",
    "csrf",
    "ssrf",
    "path_traversal",
    "deserialization",
    "injection_other",
})

# Hard exclusions: we refuse to surface findings in these categories /
# contexts because they are classically noisy, theoretical, or out of
# scope for Omar Gate 2.0. LLM outputs that match are dropped into the
# hard_exclusion bucket. Matching uses word-boundary regex (see
# `_phrase_matches`) so "rate-limit bypass" no longer shadows distinct
# strings that merely contain those words in unrelated positions.
#
# Lifted from src/commands/security-review.ts:143-161 (HARD EXCLUSIONS
# 1-17). Expanded from 14 → 17 entries to mirror the source list.
HARD_EXCLUSIONS: tuple[str, ...] = (
    "denial of service",
    "secrets on disk",
    "rate-limit bypass",
    "resource exhaustion",
    "input validation on non-critical fields",
    "workflow race condition",
    "memory safety in memory-safe languages",
    "unit test file",
    "log spoofing",
    "ssrf when only path controlled",
    "regex injection",
    "insecure documentation",
    "missing audit logs",
    "prompt injection via user content in ai system prompts",
    # Added 2026-04-25 from src/commands/security-review.ts:
    "lack of hardening measures",
    "outdated third-party libraries",
    "regex dos",  # ReDoS / regex denial-of-service
)

# Precedents: patterns where a known-safe context should cause the
# finding to be dropped even if it matches a category. The LLM knows
# these patterns from its system prompt, but we enforce a defense in
# depth by checking the finding's title / description against these
# phrases.
#
# Lifted from src/commands/security-review.ts:163-175 (PRECEDENTS 1-12).
# Expanded from 6 → 12 entries to mirror the source list.
PRECEDENTS: tuple[str, ...] = (
    "logging urls is safe",
    "uuids are unguessable",
    "environment variables are trusted",
    "react auto-escapes xss",
    "angular auto-escapes xss",
    "client-side permission check is not a vulnerability",
    # Added 2026-04-25 from src/commands/security-review.ts:
    "resource management leaks are not vulnerabilities",
    "tabnabbing is low impact",
    "open redirects require very high confidence",
    "github action workflow vulnerabilities require concrete attack path",
    "ipython notebook vulnerabilities require concrete attack path",
    "shell script command injection requires untrusted input source",
)


@dataclass(frozen=True)
class RejectedFinding:
    """A raw LLM finding that didn't make it through the filter."""

    reason: str                 # why this was rejected
    category: str               # "confidence" | "exclusion" | "precedent" | "category" | "schema"
    raw: dict[str, Any]


@dataclass
class FilterResult:
    """Output of filter_llm_findings()."""

    accepted: list[Finding] = field(default_factory=list)
    rejected: list[RejectedFinding] = field(default_factory=list)

    @property
    def below_confidence_floor(self) -> list[RejectedFinding]:
        return [r for r in self.rejected if r.category == "confidence"]

    @property
    def hard_exclusion(self) -> list[RejectedFinding]:
        return [r for r in self.rejected if r.category == "exclusion"]

    @property
    def matched_precedent(self) -> list[RejectedFinding]:
        return [r for r in self.rejected if r.category == "precedent"]

    @property
    def invalid_category(self) -> list[RejectedFinding]:
        return [r for r in self.rejected if r.category == "category"]

    @property
    def schema_failure(self) -> list[RejectedFinding]:
        return [r for r in self.rejected if r.category == "schema"]


def _resolve_floor(
    severity: str,
    confidence_floor: float | None,
    confidence_floors: dict[str, float] | None,
) -> float:
    """Resolve the effective confidence floor for a given severity.

    Precedence:
      1. explicit per-severity dict entry (CONFIDENCE_FLOORS or override)
      2. legacy `confidence_floor: float` (single global) — for back-compat
      3. CONFIDENCE_FLOORS default for the severity
    """
    if confidence_floors and severity in confidence_floors:
        return confidence_floors[severity]
    if confidence_floor is not None:
        return confidence_floor
    return CONFIDENCE_FLOORS.get(severity, CONFIDENCE_FLOOR)


def filter_llm_findings(
    raw_findings: Iterable[dict[str, Any]],
    *,
    gate_id: str = "llm_judge",
    tool: str = "llm",
    confidence_floor: float | None = None,
    confidence_floors: dict[str, float] | None = None,
) -> FilterResult:
    """Validate + filter a list of LLM-emitted findings.

    Accepts dicts with the §5.3 output contract shape:
        {
          "severity": "P0" | "P1" | "P2" | "P3",
          "file": "path/to/file.ext",
          "line": int,
          "title": str,
          "description": str (optional),
          "category": "sql_injection" | ... | "injection_other",
          "confidence": float,
          "recommended_fix": str (optional),
          "evidence": str (optional),
        }

    Returns a FilterResult with accepted Finding objects and rejected
    diagnostics.
    """
    result = FilterResult()
    for raw in raw_findings or ():
        if not isinstance(raw, dict):
            result.rejected.append(
                RejectedFinding(
                    reason="not a dict",
                    category="schema",
                    raw={"value": repr(raw)[:200]},
                )
            )
            continue

        severity = str(raw.get("severity", "")).strip().upper()
        if severity not in {"P0", "P1", "P2", "P3"}:
            result.rejected.append(
                RejectedFinding(
                    reason=f"invalid severity: {severity!r}",
                    category="schema",
                    raw=dict(raw),
                )
            )
            continue

        category = str(raw.get("category", "")).strip().lower()
        if category and category not in SUPPORTED_CATEGORIES:
            result.rejected.append(
                RejectedFinding(
                    reason=f"unsupported category: {category!r}",
                    category="category",
                    raw=dict(raw),
                )
            )
            continue

        try:
            confidence = float(raw.get("confidence", 0.0))
        except (TypeError, ValueError):
            result.rejected.append(
                RejectedFinding(
                    reason=f"non-numeric confidence: {raw.get('confidence')!r}",
                    category="schema",
                    raw=dict(raw),
                )
            )
            continue

        effective_floor = _resolve_floor(severity, confidence_floor, confidence_floors)
        if confidence < effective_floor:
            result.rejected.append(
                RejectedFinding(
                    reason=(
                        f"confidence {confidence:.2f} below {severity} floor "
                        f"{effective_floor:.2f}"
                    ),
                    category="confidence",
                    raw=dict(raw),
                )
            )
            continue

        title = str(raw.get("title", "")).strip()
        description = str(raw.get("description", "")).strip()

        if not title:
            result.rejected.append(
                RejectedFinding(
                    reason="empty title",
                    category="schema",
                    raw=dict(raw),
                )
            )
            continue

        if _matches_hard_exclusion(title, description, category):
            result.rejected.append(
                RejectedFinding(
                    reason="matches hard exclusion",
                    category="exclusion",
                    raw=dict(raw),
                )
            )
            continue

        if _matches_precedent(title, description):
            result.rejected.append(
                RejectedFinding(
                    reason="matches known-safe precedent",
                    category="precedent",
                    raw=dict(raw),
                )
            )
            continue

        file_path = str(raw.get("file", "")).strip()
        try:
            line = int(raw.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0

        result.accepted.append(
            Finding(
                gate_id=gate_id,
                tool=tool,
                severity=severity,  # type: ignore[arg-type]
                file=file_path,
                line=line,
                title=title,
                description=description,
                rule_id=f"llm:{category}" if category else "llm:unknown",
                confidence=confidence,
                recommended_fix=str(raw.get("recommended_fix", "") or "").strip() or None,
                evidence=str(raw.get("evidence", "") or "").strip() or None,
            )
        )

    return result


def _phrase_matches(phrase: str, haystack: str) -> bool:
    """Word-boundary match: phrase must appear as a delimited token in haystack.

    Replaces the prior naive `phrase in haystack` substring check so that
    short phrases like "rate-limit bypass" don't shadow an unrelated
    finding that happens to contain those tokens in different positions.

    Both phrase and haystack are expected to be lower-case already. The
    pattern uses `\\b` boundaries on the outer edges of the escaped
    phrase, which means hyphenated phrases like "rate-limit bypass"
    match `rate-limit bypass` as a contiguous run but not when those
    words appear with intervening tokens.
    """
    pattern = r"\b" + re.escape(phrase) + r"\b"
    return re.search(pattern, haystack) is not None


def _matches_hard_exclusion(title: str, description: str, category: str) -> bool:
    haystack = f"{title} {description} {category}".lower()
    for phrase in HARD_EXCLUSIONS:
        if _phrase_matches(phrase, haystack):
            return True
    return False


def _matches_precedent(title: str, description: str) -> bool:
    haystack = f"{title} {description}".lower()
    for phrase in PRECEDENTS:
        if _phrase_matches(phrase, haystack):
            return True
    return False
