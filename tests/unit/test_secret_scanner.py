from __future__ import annotations

from omargate.analyze.deterministic.secret_scanner import calculate_entropy, scan_for_secrets


def test_entropy_detection() -> None:
    high_entropy = "aB3$kL9mNpQrStUvWxYz"
    low_entropy = "aaaaaaaaaa"  # 10 identical chars = 0 entropy
    assert calculate_entropy(high_entropy) > 3.5
    assert calculate_entropy(low_entropy) < 1.0


def test_aws_key_detection() -> None:
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_for_secrets(content, "config.py")
    assert any(finding.pattern_id == "SEC-004" for finding in findings)


def test_github_token_detection() -> None:
    content = 'token = "ghp_' + ("x" * 36) + '"'
    findings = scan_for_secrets(content, "deploy.sh")
    assert any(finding.pattern_id == "SEC-005" for finding in findings)


def test_entropy_scanner_emits_finding() -> None:
    content = 'const token = "Z9xQ1pLmN8vR2tYkS3wX"'
    findings = scan_for_secrets(content, "config.ts")
    entropy_findings = [finding for finding in findings if finding.pattern_id == "SEC-ENTROPY"]
    assert entropy_findings
    assert "****" in entropy_findings[0].snippet
