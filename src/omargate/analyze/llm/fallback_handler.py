from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal, Optional

from .llm_client import LLMResponse
from .response_parser import ParsedFinding

FailurePolicy = Literal["block", "deterministic_only", "allow_with_warning"]


@dataclass
class AnalysisResult:
    findings: List[ParsedFinding]
    llm_success: bool
    fallback_used: bool
    policy_applied: Optional[str]
    warning_message: Optional[str]
    usage: Optional[dict]


def handle_llm_failure(
    llm_response: LLMResponse,
    deterministic_findings: List[dict],
    policy: FailurePolicy,
) -> AnalysisResult:
    """
    Handle LLM failure according to configured policy.

    Policies:
    - "block": Fail closed, treat as P0 finding (blocks merge)
    - "deterministic_only": Use only deterministic findings, warn user
    - "allow_with_warning": Pass with warning comment, use deterministic only
    """
    if llm_response.success:
        raise ValueError("handle_llm_failure called with successful response")

    det_findings = [
        ParsedFinding(
            severity=finding["severity"],
            category=finding["category"],
            file_path=finding["file_path"],
            line_start=finding["line_start"],
            line_end=finding.get("line_end", finding["line_start"]),
            message=finding["message"],
            recommendation=finding.get("recommendation", ""),
            confidence=1.0,
            source="deterministic",
        )
        for finding in deterministic_findings
    ]

    if policy == "block":
        synthetic = ParsedFinding(
            severity="P0",
            category="LLM Failure",
            file_path="<system>",
            line_start=0,
            line_end=0,
            message=(
                "LLM analysis failed: "
                f"{llm_response.error}. Blocking merge per fail-closed policy."
            ),
            recommendation="Retry the scan or investigate the LLM error.",
            confidence=1.0,
            source="system",
        )
        return AnalysisResult(
            findings=[synthetic] + det_findings,
            llm_success=False,
            fallback_used=False,
            policy_applied="block",
            warning_message=None,
            usage=None,
        )

    if policy == "deterministic_only":
        return AnalysisResult(
            findings=det_findings,
            llm_success=False,
            fallback_used=False,
            policy_applied="deterministic_only",
            warning_message=(
                f"LLM analysis failed ({llm_response.error}). "
                "Only deterministic scan results shown."
            ),
            usage=None,
        )

    return AnalysisResult(
        findings=det_findings,
        llm_success=False,
        fallback_used=False,
        policy_applied="allow_with_warning",
        warning_message=(
            f"LLM analysis failed ({llm_response.error}). "
            "Proceeding with deterministic results only."
        ),
        usage=None,
    )
