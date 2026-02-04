import pytest
from pathlib import Path
from omargate.artifacts.audit_report import generate_audit_report, write_audit_report


@pytest.fixture
def sample_data():
    return {
        "run_id": "test-run-123",
        "summary": {
            "counts": {"P0": 1, "P1": 2, "P2": 3, "P3": 4, "total": 10},
            "policy_pack": "omar",
            "policy_pack_version": "1.0",
            "dedupe_key": "abc123def456",
            "duration_ms": 5000,
            "stages_completed": ["preflight", "ingest", "scan", "gate"],
            "tool_versions": {"action": "1.2.0"},
            "errors": [],
        },
        "findings": [
            {
                "severity": "P0",
                "category": "Auth Bypass",
                "file_path": "src/auth.ts",
                "line_start": 42,
                "line_end": 50,
                "message": "Missing authentication check",
                "recommendation": "Add auth middleware",
                "snippet": "if (user) { ... }",
                "confidence": 0.9,
                "source": "llm",
                "fingerprint": "abc123",
            }
        ],
        "ingest": {
            "stats": {"in_scope_files": 100, "total_lines": 10000},
            "hotspots": {"auth": ["src/auth.ts"], "payment": []},
            "dependencies": {"package_manager": "pnpm"},
        },
        "config": {"severity_gate": "P1"},
    }


def test_report_contains_summary(sample_data):
    """Report includes executive summary."""
    report = generate_audit_report(**sample_data)
    assert "Executive Summary" in report
    assert "P0" in report
    assert "BLOCKED" in report


def test_report_contains_findings(sample_data):
    """Report includes finding details."""
    report = generate_audit_report(**sample_data)
    assert "Auth Bypass" in report
    assert "src/auth.ts" in report
    assert "Missing authentication check" in report


def test_report_contains_metadata(sample_data):
    """Report includes scan metadata."""
    report = generate_audit_report(**sample_data)
    assert "test-run-123" in report
    assert "omar" in report


def test_report_hides_secret_snippets(sample_data):
    """Snippets for secrets findings are hidden."""
    sample_data["findings"][0]["category"] = "secrets"
    sample_data["findings"][0]["snippet"] = "api_key = 'super_secret'"
    report = generate_audit_report(**sample_data)
    assert "super_secret" not in report


def test_write_audit_report(sample_data, tmp_path: Path):
    """Audit report written to disk."""
    report_path = write_audit_report(tmp_path, **sample_data)
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Omar Gate Audit Report" in content
