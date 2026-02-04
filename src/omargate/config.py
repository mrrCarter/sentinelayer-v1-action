from __future__ import annotations

from pydantic import Field, SecretStr, conint, confloat, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import ApprovalMode, ForkPolicy, LLMFailurePolicy, ScanMode, SeverityGate


class OmarGateConfig(BaseSettings):
    """Configuration loaded from GitHub Actions inputs."""

    model_config = SettingsConfigDict(env_prefix="INPUT_", frozen=True, extra="ignore")

    # Required
    openai_api_key: SecretStr = Field(..., description="OpenAI API key for LLM calls (BYO)")

    # GitHub integration (recommended)
    github_token: SecretStr = Field(default="", description="GitHub token used for API calls")

    # PlexAura integration (optional)
    plexaura_token: SecretStr = Field(default="", description="PlexAura API token")
    telemetry_tier: conint(ge=0, le=3) = Field(
        default=1,
        description="Telemetry tier: 0=off, 1=aggregate, 2=metadata, 3=full artifacts",
    )
    telemetry: bool = Field(
        default=True,
        description="Enable anonymous telemetry (opt-out)",
    )
    share_metadata: bool = Field(
        default=False,
        description="Opt-in to Tier 2 metadata (repo identity + finding metadata)",
    )
    share_artifacts: bool = Field(
        default=False,
        description="Opt-in to Tier 3 artifacts upload",
    )
    training_opt_in: bool = Field(default=False, description="Optional training consent")

    # Scan configuration
    scan_mode: ScanMode = Field(default="pr-diff")
    severity_gate: SeverityGate = Field(default="P1")

    # Model settings
    model: str = Field(default="gpt-4o")
    model_fallback: str = Field(default="gpt-4o-mini")
    llm_failure_policy: LLMFailurePolicy = Field(default="block")

    # Rate limiting / cost control
    max_daily_scans: conint(ge=0) = Field(default=20)
    min_scan_interval_minutes: conint(ge=0) = Field(default=5)
    max_input_tokens: conint(ge=0) = Field(default=100000)
    require_cost_confirmation: confloat(ge=0) = Field(default=5.00)
    approval_mode: ApprovalMode = Field(default="pr_label")
    approval_label: str = Field(default="sentinellayer:approved")

    # Fork handling
    fork_policy: ForkPolicy = Field(default="block")

    # Fixer options
    run_deterministic_fix: bool = Field(default=False)
    run_llm_fix: bool = Field(default=False)
    auto_commit_fixes: bool = Field(default=False)

    # Policy pack controls
    policy_pack: str = Field(default="omar")
    policy_pack_version: str = Field(default="v1")

    @field_validator("severity_gate", mode="before")
    @classmethod
    def _normalize_severity_gate(cls, value: str) -> str:
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.lower() == "none":
                return "none"
            return trimmed.upper()
        return value

    @field_validator(
        "scan_mode",
        "llm_failure_policy",
        "approval_mode",
        "fork_policy",
        mode="before",
    )
    @classmethod
    def _normalize_lowercase(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip().lower()
        return value
