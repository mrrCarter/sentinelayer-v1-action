from __future__ import annotations

from omargate.github import findings_to_annotations


def test_findings_to_annotations_format() -> None:
    findings = [
        {
            "severity": "P0",
            "category": "XSS",
            "file_path": "app.tsx",
            "line_start": 42,
            "message": "Unsafe innerHTML",
        }
    ]
    annotations = findings_to_annotations(findings)

    assert len(annotations) == 1
    assert annotations[0]["path"] == "app.tsx"
    assert annotations[0]["start_line"] == 42
    assert annotations[0]["annotation_level"] == "failure"


def test_annotations_respect_limit() -> None:
    findings = [
        {
            "severity": "P3",
            "file_path": f"file{i}.ts",
            "line_start": i + 1,
            "message": "test",
        }
        for i in range(100)
    ]
    annotations = findings_to_annotations(findings)
    assert len(annotations) == 50
