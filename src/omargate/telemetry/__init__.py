"""Telemetry package for SentinelLayer."""

from .collector import TelemetryCollector
from .consent import ConsentConfig, TelemetryTier, get_max_tier, should_upload_tier, validate_payload_tier
from .schemas import (
    build_tier1_payload,
    build_tier2_payload,
    build_tier3_manifest,
    findings_to_summary,
)
from .uploader import fetch_oidc_token, upload_artifacts, upload_telemetry

__all__ = [
    "TelemetryCollector",
    "ConsentConfig",
    "TelemetryTier",
    "get_max_tier",
    "should_upload_tier",
    "validate_payload_tier",
    "build_tier1_payload",
    "build_tier2_payload",
    "build_tier3_manifest",
    "findings_to_summary",
    "upload_artifacts",
    "upload_telemetry",
    "fetch_oidc_token",
]
