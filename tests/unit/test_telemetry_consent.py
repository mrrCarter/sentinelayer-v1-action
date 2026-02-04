from __future__ import annotations

from omargate.telemetry.consent import (
    ConsentConfig,
    get_max_tier,
    validate_payload_tier,
)


def test_consent_default_is_tier1() -> None:
    """Default consent allows Tier 1 only."""
    consent = ConsentConfig()
    assert get_max_tier(consent) == 1


def test_consent_telemetry_false_is_tier0() -> None:
    """telemetry=false disables all telemetry."""
    consent = ConsentConfig(telemetry=False)
    assert get_max_tier(consent) == 0


def test_consent_share_metadata_enables_tier2() -> None:
    """share_metadata=true enables Tier 2."""
    consent = ConsentConfig(share_metadata=True)
    assert get_max_tier(consent) == 2


def test_consent_share_artifacts_enables_tier3() -> None:
    """share_artifacts=true enables Tier 3."""
    consent = ConsentConfig(share_artifacts=True)
    assert get_max_tier(consent) == 3


def test_validate_payload_rejects_tier_violation() -> None:
    """Payload validation catches tier violations."""
    consent = ConsentConfig()

    tier2_payload = {"tier": 2, "repo": {"owner": "acme", "name": "app"}}
    assert validate_payload_tier(tier2_payload, consent) is False


def test_validate_payload_rejects_tier1_with_identity() -> None:
    """Tier 1 payload must not contain repo identity."""
    consent = ConsentConfig()

    bad_tier1 = {"tier": 1, "repo": {"repo_hash": "abc", "owner": "acme"}}
    assert validate_payload_tier(bad_tier1, consent) is False
