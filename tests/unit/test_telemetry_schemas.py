from __future__ import annotations

import json

from omargate.telemetry import TelemetryCollector
from omargate.telemetry.schemas import (
    build_tier1_payload,
    build_tier2_payload,
    findings_to_summary,
)


def test_tier1_has_no_identifying_info() -> None:
    """Tier 1 payload contains no repo identity."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/secret-repo")
    payload = build_tier1_payload(collector)

    assert "repo_hash" in payload["repo"]

    payload_str = json.dumps(payload)
    assert "acme" not in payload_str
    assert "secret-repo" not in payload_str
    assert "owner" not in payload["repo"]
    assert "name" not in payload["repo"]


def test_tier2_includes_repo_identity() -> None:
    """Tier 2 payload includes repo identity."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/app")
    payload = build_tier2_payload(
        collector=collector,
        repo_owner="acme",
        repo_name="app",
        branch="main",
        pr_number=42,
        head_sha="abc123",
        is_fork_pr=False,
        policy_pack="omar",
        policy_pack_version="1.0",
        action_version="1.2.0",
        findings_summary=[],
        idempotency_key="xyz",
    )

    assert payload["repo"]["owner"] == "acme"
    assert payload["repo"]["name"] == "app"
    assert payload["tier"] == 2


def test_findings_summary_strips_sensitive_fields() -> None:
    """Finding summary removes snippets and messages."""
    findings = [
        {
            "id": "F001",
            "severity": "P1",
            "category": "XSS",
            "file_path": "app.tsx",
            "line_start": 42,
            "snippet": "dangerouslySetInnerHTML={{ __html: userInput }}",
            "message": "User input directly passed to innerHTML",
            "recommendation": "Sanitize input first",
        }
    ]

    summary = findings_to_summary(findings)

    assert len(summary) == 1
    assert summary[0]["severity"] == "P1"
    assert "snippet" not in summary[0]
    assert "message" not in summary[0]
    assert "recommendation" not in summary[0]
