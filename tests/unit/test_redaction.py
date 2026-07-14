from __future__ import annotations

from omargate.redaction import sanitize_public_error


def test_sanitize_public_error_redacts_provider_ids_and_keys() -> None:
    raw = (
        "Fallback failed: 403 PERMISSION_DENIED. "
        "{'error': {'message': 'API key AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMY is invalid "
        "for consumer projects/123456789012 and project_id=my-prod-project'}} "
        "standalone projects/999999999999 "
        "https://example.test/v1?key=AIzaSyQUERYDUMMYDUMMYDUMMYDUMMY"
    )

    sanitized = sanitize_public_error(raw)

    assert "PERMISSION_DENIED" in sanitized
    assert "403" in sanitized
    assert "AIza" not in sanitized
    assert "123456789012" not in sanitized
    assert "999999999999" not in sanitized
    assert "my-prod-project" not in sanitized
    assert "projects/[redacted]" in sanitized
    assert "[redacted-provider-id]" in sanitized


def test_sanitize_public_error_keeps_capacity_context() -> None:
    raw = (
        "Primary failed: Error code: 429 - insufficient_quota; "
        "Fallback failed: 403 RESOURCE_EXHAUSTED consumer 987654321 suspended; "
        "retry after provider capacity is restored"
    )

    sanitized = sanitize_public_error(raw)

    assert "Primary failed" in sanitized
    assert "429" in sanitized
    assert "insufficient_quota" in sanitized
    assert "RESOURCE_EXHAUSTED" in sanitized
    assert "provider capacity" in sanitized
    assert "987654321" not in sanitized


def test_sanitize_public_error_redacts_cli_masked_openai_key() -> None:
    raw = "Incorrect API key provided: sk-test-***************lder"

    sanitized = sanitize_public_error(raw)

    assert "sk-test" not in sanitized
    assert "[redacted-secret]" in sanitized
