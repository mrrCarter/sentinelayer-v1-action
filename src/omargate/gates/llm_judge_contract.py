"""LLM-judge Finding contract (#A6).

Per CODEX_OMARGATE_COMBINE_SPEC.md §5.3: the layer-7 LLM judge emits
findings that must meet a stricter bar than deterministic gates. This
module enforces:
  - confidence >= 0.8 (hard floor)
  - category ∈ fixed enum
  - HARD_EXCLUSIONS: classes of findings we refuse to surface
  - PRECEDENTS: contexts where a pattern is known-safe and should not
    produce a finding

The module is pure — takes a list of raw Finding-shaped dicts produced
by an LLM and returns a filtered list of validated Finding objects plus
per-rejection diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .findings import Finding

__all__ = [
    "CONFIDENCE_FLOOR",
    "HARD_EXCLUSIONS",
    "PRECEDENTS",
    "SUPPORTED_CATEGORIES",
    "RejectedFinding",
    "FilterResult",
    "filter_llm_findings",
]

# Hard floor on the confidence field. LLM findings below this are
# silently dropped and counted in FilterResult.below_confidence_floor.
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
# hard_exclusion bucket.
HARD_EXCLUSIONS: tuple[str, ...] = (
    "denial of service",
    "secrets on disk",  # unless plaintext logging of secrets, handled via title-match
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
)

# Precedents: patterns where a known-safe context should cause the
# finding to be dropped even if it matches a category. The LLM knows
# these patterns from its system prompt, but we enforce a defense in
# depth by checking the finding's title / description against these
# phrases.
PRECEDENTS: tuple[str, ...] = (
    "logging urls is safe",
    "uuids are unguessable",
    "environment variables are trusted",
    "react auto-escapes xss",
    "angular auto-escapes xss",
    "client-side permission check is not a vulnerability",
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


def filter_llm_findings(
    raw_findings: Iterable[dict[str, Any]],
    *,
    gate_id: str = "llm_judge",
    tool: str = "llm",
    confidence_floor: float = CONFIDENCE_FLOOR,
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

        if confidence < confidence_floor:
            result.rejected.append(
                RejectedFinding(
                    reason=f"confidence {confidence:.2f} below floor {confidence_floor:.2f}",
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


def _matches_hard_exclusion(title: str, description: str, category: str) -> bool:
    haystack = f"{title} {description} {category}".lower()
    for phrase in HARD_EXCLUSIONS:
        if phrase in haystack:
            return True
    return False


def _matches_precedent(title: str, description: str) -> bool:
    haystack = f"{title} {description}".lower()
    for phrase in PRECEDENTS:
        if phrase in haystack:
            return True
    return False
