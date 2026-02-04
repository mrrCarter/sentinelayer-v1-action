from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

TelemetryTier = Literal[0, 1, 2, 3]


@dataclass
class ConsentConfig:
    """Consent settings from action config."""

    telemetry: bool = True  # Tier 1 opt-out (default ON)
    share_metadata: bool = False  # Tier 2 opt-in
    share_artifacts: bool = False  # Tier 3 opt-in
    training_consent: bool = False  # Tier 4 opt-in (separate)


def get_max_tier(consent: ConsentConfig) -> TelemetryTier:
    """
    Determine maximum allowed telemetry tier based on consent.

    Tier 0 = telemetry disabled entirely
    Tier 1 = anonymous only (default)
    Tier 2 = repo identity + finding metadata
    Tier 3 = full artifacts
    """
    if not consent.telemetry:
        return 0

    if consent.share_artifacts:
        return 3

    if consent.share_metadata:
        return 2

    return 1


def should_upload_tier(tier: TelemetryTier, consent: ConsentConfig) -> bool:
    """Check if a specific tier should be uploaded."""
    max_tier = get_max_tier(consent)
    return tier <= max_tier and tier > 0


def validate_payload_tier(payload: dict, consent: ConsentConfig) -> bool:
    """
    Validate that payload doesn't exceed consent level.

    Safety check before upload to ensure we never send
    data the user hasn't consented to.
    """
    payload_tier = payload.get("tier", 0)
    max_tier = get_max_tier(consent)

    if payload_tier > max_tier:
        return False

    if payload_tier >= 2:
        repo = payload.get("repo", {})
        if not repo.get("owner") or not repo.get("name"):
            return False

    if payload_tier == 1:
        repo = payload.get("repo", {})
        if repo.get("owner") or repo.get("name"):
            return False

    return True
