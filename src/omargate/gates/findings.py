"""Finding dataclass for Omar Gate 2.0 local gates.

Simplified mirror of the §5.3 security-review LLM contract from
CODEX_OMARGATE_COMBINE_SPEC.md. Deterministic gates (layers 1-6) emit
a subset of the full schema with confidence=1.0 for rule matches.
The LLM-judge gate (layer 7, PR #A6) extends this with the confidence
floor (>= 0.8) and HARD_EXCLUSIONS / PRECEDENTS filters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["P0", "P1", "P2", "P3"]


@dataclass(frozen=True)
class Finding:
    """A single gate finding.

    gate_id / tool are required provenance fields so findings can be
    deduplicated and re-attributed across gate layers.
    """

    gate_id: str           # "static", "security", "policy", "llm_judge", etc.
    tool: str              # "tsc", "eslint", "gitleaks", "semgrep", ...
    severity: Severity
    file: str              # relative path from repo_root
    line: int              # 1-based; 0 for file-level findings
    title: str
    description: str = ""
    rule_id: str | None = None       # "tsc:TS2345", "eslint:no-unused-vars", etc.
    confidence: float = 1.0          # 0.0-1.0; LLM-judge uses >= 0.8 floor
    recommended_fix: str | None = None
    evidence: str | None = None      # code excerpt at file:line


def serialize_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Serialize findings to the on-disk FINDINGS.jsonl shape (camelCase keys)."""
    return [
        {
            "gateId": f.gate_id,
            "tool": f.tool,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "title": f.title,
            "description": f.description,
            "ruleId": f.rule_id,
            "confidence": f.confidence,
            "recommendedFix": f.recommended_fix,
            "evidence": f.evidence,
        }
        for f in findings
    ]
