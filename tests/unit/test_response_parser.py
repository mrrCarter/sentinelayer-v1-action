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
    assert result.findings[1].fix_plan == ""


def test_parser_handles_markdown_block() -> None:
    """Extracts JSON from markdown code blocks."""
    parser = ResponseParser()
    response = """Here are the findings:
```json
{"severity": "P0", "category": "Auth", "file_path": "src/auth.ts", "line_start": 1, "message": "Bypass"}
```"""
    result = parser.parse(response)
    assert len(result.findings) == 1
    assert result.findings[0].fix_plan == ""


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


def test_parser_preserves_detailed_fix_plan_verbatim() -> None:
    parser = ResponseParser()
    response = (
        '{"severity":"P1","category":"backend","file_path":"src/api.ts","line_start":17,'
        '"message":"Timeout missing","fix_plan":"Add HTTP_TIMEOUT_MS constant and pass timeout: HTTP_TIMEOUT_MS to axios.get in fetchProfile()."}'
    )
    result = parser.parse(response)
    assert len(result.findings) == 1
    assert result.findings[0].fix_plan == (
        "Add HTTP_TIMEOUT_MS constant and pass timeout: HTTP_TIMEOUT_MS to axios.get in fetchProfile()."
    )


def test_parser_rejects_escaping_or_absolute_file_paths() -> None:
    parser = ResponseParser()
    template = (
        '{{"severity":"P1","category":"security","file_path":"{path}",'
        '"line_start":1,"message":"bad path"}}'
    )

    for path in ("../secret.txt", "/etc/passwd", "C:\\secret.txt"):
        result = parser.parse(template.format(path=path))
        assert result.findings == []
        assert result.parse_errors


def test_parser_rejects_invalid_line_and_confidence_values() -> None:
    parser = ResponseParser()
    invalid = [
        '{"severity":"P1","category":"x","file_path":"a.py","line_start":0,"message":"x"}',
        '{"severity":"P1","category":"x","file_path":"a.py","line_start":2,"line_end":1,"message":"x"}',
        '{"severity":"P1","category":"x","file_path":"a.py","line_start":1,"message":"x","confidence":2}',
    ]

    for payload in invalid:
        result = parser.parse(payload)
        assert result.findings == []
        assert result.parse_errors


def test_parser_handles_non_object_jsonl_without_crashing() -> None:
    parser = ResponseParser()

    result = parser.parse('[]\n{"not":"a finding"}')

    assert result.findings == []
    assert len(result.parse_errors) == 2


def test_parser_caps_finding_count() -> None:
    parser = ResponseParser()
    item = {
        "severity": "P3",
        "category": "quality",
        "file_path": "src/a.py",
        "line_start": 1,
        "message": "bounded",
    }

    result = parser.parse(__import__("json").dumps([item] * 501))

    assert len(result.findings) == 500
    assert any("maximum finding count" in error for error in result.parse_errors)
