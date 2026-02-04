from __future__ import annotations

import hashlib
import re


def normalize_snippet(snippet: str) -> str:
    """
    Normalize snippet for stable fingerprinting.

    Removes variance that shouldn't affect finding identity:
    - Line numbers
    - Extra whitespace
    - Comments
    - Case differences
    """
    if not snippet:
        return ""

    # Remove line numbers (e.g., "42 | code" or "42: code")
    snippet = re.sub(r"^\s*\d+\s*[|:]?\s*", "", snippet, flags=re.MULTILINE)

    # Remove single-line comments
    snippet = re.sub(r"//.*$", "", snippet, flags=re.MULTILINE)
    snippet = re.sub(r"#.*$", "", snippet, flags=re.MULTILINE)

    # Remove multi-line comments
    snippet = re.sub(r"/\*.*?\*/", "", snippet, flags=re.DOTALL)

    # Normalize whitespace (collapse multiple spaces/newlines to single space)
    snippet = re.sub(r"\s+", " ", snippet)

    # Lowercase for case-insensitive comparison
    snippet = snippet.lower().strip()

    return snippet


def compute_fingerprint(
    category: str,
    severity: str,
    file_path: str,
    line_start: int,
    snippet: str,
    policy_version: str,
    tenant_salt: str = "",
) -> str:
    """
    Compute stable fingerprint for a finding.

    Fingerprint enables:
    - Fixed vs resurfaced tracking across runs
    - Recurrence metrics and trends
    - HITL verification that fixes actually resolved findings

    Args:
        category: Finding category (e.g., "secrets", "injection")
        severity: P0/P1/P2/P3
        file_path: Relative path to file
        line_start: Starting line number
        snippet: Code snippet (will be normalized)
        policy_version: Policy pack version (findings may differ across versions)
        tenant_salt: Optional salt for tenant isolation (prevents cross-tenant comparison)

    Returns:
        32-character hex fingerprint
    """
    normalized = normalize_snippet(snippet)

    # Include policy_version so fingerprints don't falsely match across policy changes
    components = "|".join(
        [
            category,
            severity,
            file_path,
            str(line_start),
            normalized,
            policy_version,
            tenant_salt,
        ]
    )

    return hashlib.sha256(components.encode()).hexdigest()[:32]


def fingerprint_finding(finding: dict, policy_version: str, tenant_salt: str = "") -> str:
    """Convenience function to fingerprint a finding dict."""
    return compute_fingerprint(
        category=finding.get("category", "unknown"),
        severity=finding.get("severity", "P3"),
        file_path=finding.get("file_path", ""),
        line_start=finding.get("line_start", 0),
        snippet=finding.get("snippet", ""),
        policy_version=policy_version,
        tenant_salt=tenant_salt,
    )


def add_fingerprints_to_findings(
    findings: list[dict],
    policy_version: str,
    tenant_salt: str = "",
) -> list[dict]:
    """Add fingerprint field to all findings."""
    for finding in findings:
        if "fingerprint" not in finding:
            finding["fingerprint"] = fingerprint_finding(
                finding, policy_version, tenant_salt
            )
    return findings
