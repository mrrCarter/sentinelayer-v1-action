from __future__ import annotations

from omargate.analyze.llm.response_parser import ResponseParser


def test_parser_valid_jsonl() -> None:
    """Parses valid JSONL response."""
    parser = ResponseParser()
    response = (
        '{"severity": "P1", "category": "XSS", "file_path": "src/app.tsx", "line_start": 42, '
        '"message": "Potential XSS", "fix_plan": "Pseudo-code: sanitize HTML before render and add an XSS regression test."}\n'
        '{"severity": "P2", "category": "Quality", "file_path": "src/utils.ts", "line_start": 10, "message": "TODO marker"}'
    )
    result = parser.parse(response)
    assert len(result.findings) == 2
    assert result.findings[0].severity == "P1"
    assert "sanitize HTML" in result.findings[0].fix_plan
    assert result.findings[1].fix_plan.startswith("Pseudo-code:")


def test_parser_handles_markdown_block() -> None:
    """Extracts JSON from markdown code blocks."""
    parser = ResponseParser()
    response = """Here are the findings:
```json
{"severity": "P0", "category": "Auth", "file_path": "src/auth.ts", "line_start": 1, "message": "Bypass"}
```"""
    result = parser.parse(response)
    assert len(result.findings) == 1
    assert result.findings[0].fix_plan.startswith("Pseudo-code:")


def test_parser_handles_no_findings() -> None:
    """Recognizes no_findings response."""
    parser = ResponseParser()
    response = '{"no_findings": true}'
    result = parser.parse(response)
    assert result.no_findings_reported
    assert len(result.findings) == 0


def test_parser_handles_malformed_json() -> None:
    """Records errors for malformed lines, continues parsing."""
    parser = ResponseParser()
    response = (
        '{"severity": "P1", "category": "XSS", "file_path": "a.ts", "line_start": 1, "message": "ok"}\n'
        "this is not json\n"
        '{"severity": "P2", "category": "Quality", "file_path": "b.ts", "line_start": 2, "message": "ok"}'
    )
    result = parser.parse(response)
    assert len(result.findings) == 2
    assert len(result.parse_errors) == 1


def test_parser_rejects_invalid_severity() -> None:
    """Rejects findings with invalid severity."""
    parser = ResponseParser()
    response = '{"severity": "CRITICAL", "category": "XSS", "file_path": "a.ts", "line_start": 1, "message": "bad"}'
    result = parser.parse(response)
    assert len(result.findings) == 0
    assert len(result.parse_errors) == 1


def test_parser_handles_missing_fields() -> None:
    """Rejects findings missing required fields."""
    parser = ResponseParser()
    response = '{"severity": "P1", "category": "XSS"}'
    result = parser.parse(response)
    assert len(result.findings) == 0
