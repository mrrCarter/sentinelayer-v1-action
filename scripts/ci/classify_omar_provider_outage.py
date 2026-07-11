from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProviderOutageClassifierError(ValueError):
    pass


@dataclass(frozen=True)
class ProviderOutageClassification:
    provider_outage_break_glass: bool
    reason: str
    blocking_count: int
    p0_count: int
    p1_count: int
    p2_count: int


_CAPACITY_MARKERS = (
    "429",
    "capacity",
    "consumer_suspended",
    "insufficient_quota",
    "permission_denied",
    "provider unavailable",
    "quota",
    "rate limit",
    "suspended",
)

_LLM_FAILURE_MARKERS = (
    "blocking merge per fail-closed policy",
    "fallback failed",
    "llm analysis failed",
    "primary failed",
)


def _load_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise ProviderOutageClassifierError(f"findings file not found: {path}")

    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ProviderOutageClassifierError(
                f"invalid findings JSON on line {line_number}"
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderOutageClassifierError(
                f"finding on line {line_number} is not a JSON object"
            )
        findings.append(payload)
    return findings


def _finding_source(finding: dict[str, Any]) -> str:
    return str(finding.get("source") or finding.get("provenance") or "").strip()


def _finding_path(finding: dict[str, Any]) -> str:
    scope = finding.get("scope")
    scope_payload = scope if isinstance(scope, dict) else {}
    return str(
        finding.get("file_path")
        or finding.get("path")
        or scope_payload.get("path")
        or ""
    ).strip()


def _finding_message(finding: dict[str, Any]) -> str:
    return " ".join(
        str(value or "")
        for value in (
            finding.get("message"),
            finding.get("impact"),
            finding.get("title"),
            finding.get("remediation_guidance"),
        )
    ).lower()


def classify_provider_outage(findings: list[dict[str, Any]]) -> ProviderOutageClassification:
    counts = {"P0": 0, "P1": 0, "P2": 0}
    blocking: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "").upper()
        if severity in counts:
            counts[severity] += 1
            blocking.append(finding)

    if counts["P1"] or counts["P2"]:
        return ProviderOutageClassification(
            provider_outage_break_glass=False,
            reason="blocking_non_p0_findings_present",
            blocking_count=len(blocking),
            p0_count=counts["P0"],
            p1_count=counts["P1"],
            p2_count=counts["P2"],
        )

    if counts["P0"] != 1 or len(blocking) != 1:
        return ProviderOutageClassification(
            provider_outage_break_glass=False,
            reason="expected_exactly_one_p0_llm_failure",
            blocking_count=len(blocking),
            p0_count=counts["P0"],
            p1_count=counts["P1"],
            p2_count=counts["P2"],
        )

    finding = blocking[0]
    category = str(finding.get("category") or "")
    source = _finding_source(finding)
    file_path = _finding_path(finding)
    message = _finding_message(finding)
    if category != "LLM Failure" or source != "system" or file_path != "<system>":
        return ProviderOutageClassification(
            provider_outage_break_glass=False,
            reason="p0_is_not_system_llm_failure",
            blocking_count=len(blocking),
            p0_count=counts["P0"],
            p1_count=counts["P1"],
            p2_count=counts["P2"],
        )

    if not all(marker in message for marker in _LLM_FAILURE_MARKERS):
        return ProviderOutageClassification(
            provider_outage_break_glass=False,
            reason="llm_failure_message_missing_fail_closed_markers",
            blocking_count=len(blocking),
            p0_count=counts["P0"],
            p1_count=counts["P1"],
            p2_count=counts["P2"],
        )

    if not any(marker in message for marker in _CAPACITY_MARKERS):
        return ProviderOutageClassification(
            provider_outage_break_glass=False,
            reason="llm_failure_not_provider_capacity_class",
            blocking_count=len(blocking),
            p0_count=counts["P0"],
            p1_count=counts["P1"],
            p2_count=counts["P2"],
        )

    return ProviderOutageClassification(
        provider_outage_break_glass=True,
        reason="single_system_llm_provider_outage",
        blocking_count=1,
        p0_count=1,
        p1_count=0,
        p2_count=0,
    )


def _write_github_outputs(path: Path | None, result: ProviderOutageClassification) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as output_file:
        output_file.write(
            "\n".join(
                [
                    f"provider_outage_break_glass={str(result.provider_outage_break_glass).lower()}",
                    f"reason={result.reason}",
                    f"blocking_count={result.blocking_count}",
                    f"p0_count={result.p0_count}",
                    f"p1_count={result.p1_count}",
                    f"p2_count={result.p2_count}",
                ]
            )
            + "\n"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify whether a failed managed Omar run is provider-outage-only."
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to Omar FINDINGS.jsonl from the managed run.",
    )
    parser.add_argument(
        "--github-output",
        default="",
        help="Optional GitHub Actions output file path.",
    )
    args = parser.parse_args(argv)

    try:
        findings = _load_findings(Path(args.findings))
        result = classify_provider_outage(findings)
    except ProviderOutageClassifierError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    _write_github_outputs(
        Path(args.github_output) if args.github_output else None,
        result,
    )
    print(
        "provider_outage_break_glass="
        f"{str(result.provider_outage_break_glass).lower()} reason={result.reason} "
        f"blocking={result.blocking_count} P0={result.p0_count} "
        f"P1={result.p1_count} P2={result.p2_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
