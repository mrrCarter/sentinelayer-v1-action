from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import List

from ...fix_plan import ensure_fix_plan


@dataclass
class ParsedFinding:
    severity: str
    category: str
    file_path: str
    line_start: int
    line_end: int
    message: str
    recommendation: str
    fix_plan: str
    confidence: float
    source: str = "llm"


@dataclass
class ParseResult:
    findings: List[ParsedFinding]
    parse_errors: List[str]
    raw_response: str
    no_findings_reported: bool


class ResponseParser:
    """Parse LLM response into structured findings."""

    REQUIRED_FIELDS = {"severity", "category", "file_path", "line_start", "message"}
    VALID_SEVERITIES = {"P0", "P1", "P2", "P3"}

    def parse(self, response_text: str) -> ParseResult:
        """
        Parse LLM response into findings.

        Handles:
        - JSONL format (one JSON per line)
        - JSON array format
        - Markdown code blocks containing JSON
        - {"no_findings": true} response
        - Malformed/partial JSON
        """
        raw = response_text or ""
        content = self._extract_json_content(raw)
        findings: List[ParsedFinding] = []
        errors: List[str] = []
        no_findings = False

        if not content:
            return ParseResult(findings=[], parse_errors=["Empty response"], raw_response=raw, no_findings_reported=False)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, dict):
            if parsed.get("no_findings") is True:
                return ParseResult(findings=[], parse_errors=[], raw_response=raw, no_findings_reported=True)
            if self._validate_finding(parsed):
                findings.append(self._normalize_finding(parsed))
            else:
                errors.append("Object: Missing required fields or invalid values")
            return ParseResult(findings, errors, raw, no_findings)

        if isinstance(parsed, list):
            for idx, item in enumerate(parsed):
                if not isinstance(item, dict):
                    errors.append(f"Item {idx + 1}: Not an object")
                    continue
                if item.get("no_findings") is True:
                    no_findings = True
                    continue
                if self._validate_finding(item):
                    findings.append(self._normalize_finding(item))
                else:
                    errors.append(f"Item {idx + 1}: Missing required fields or invalid values")
            return ParseResult(findings, errors, raw, no_findings)

        # Fallback to JSONL parsing
        findings_json, errors = self._parse_jsonl(content)
        for obj in findings_json:
            findings.append(self._normalize_finding(obj))

        if re.search(r'"no_findings"\s*:\s*true', content, re.IGNORECASE):
            no_findings = True

        return ParseResult(findings, errors, raw, no_findings)

    def _extract_json_content(self, text: str) -> str:
        """Extract JSON/JSONL from markdown code blocks if present."""
        match = re.search(r"```(?:json|jsonl)?\s*\n(.*?)```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()

    def _parse_jsonl(self, content: str) -> tuple[List[dict], List[str]]:
        """Parse JSONL format (one JSON object per line)."""
        findings = []
        errors = []

        for i, line in enumerate(content.split("\n")):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if self._validate_finding(obj):
                    findings.append(obj)
                elif obj.get("no_findings"):
                    continue
                else:
                    errors.append(f"Line {i + 1}: Missing required fields")
            except json.JSONDecodeError as exc:
                errors.append(f"Line {i + 1}: Invalid JSON - {exc}")

        return findings, errors

    def _validate_finding(self, obj: dict) -> bool:
        """Check if object has required fields and valid values."""
        if not all(field in obj for field in self.REQUIRED_FIELDS):
            return False
        if obj.get("severity") not in self.VALID_SEVERITIES:
            return False
        if not isinstance(obj.get("line_start"), int):
            return False
        return True

    def _normalize_finding(self, obj: dict) -> ParsedFinding:
        """Convert dict to ParsedFinding with defaults."""
        recommendation = obj.get("recommendation", "")
        return ParsedFinding(
            severity=obj["severity"],
            category=obj["category"],
            file_path=obj["file_path"],
            line_start=obj["line_start"],
            line_end=obj.get("line_end", obj["line_start"]),
            message=obj["message"],
            recommendation=recommendation,
            fix_plan=ensure_fix_plan(
                fix_plan=obj.get("fix_plan", ""),
                recommendation=recommendation,
                message=obj.get("message", ""),
            ),
            confidence=float(obj.get("confidence", 0.8)),
            source="llm",
        )
