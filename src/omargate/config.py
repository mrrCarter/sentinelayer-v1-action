from __future__ import annotations

from pydantic import Field, SecretStr, conint, confloat, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    ApprovalMode,
    ForkPolicy,
    LLMFailurePolicy,
    LLMProviderType,
    RateLimitFailMode,
    ScanMode,
    SeverityGate,
)


class OmarGateConfig(BaseSettings):
    """Configuration loaded from GitHub Actions inputs."""

    model_config = SettingsConfigDict(
        env_prefix="INPUT_",
        frozen=True,
        extra="ignore",
        protected_namespaces=(),  # Allow fields starting with 'model_'
    )

    # Required
    openai_api_key: SecretStr = Field(
        default="",
        description="OpenAI API key for LLM calls (BYO). Required when llm_provider=openai or use_codex=true.",
    )

    # LLM provider selection + keys (BYO)
    llm_provider: LLMProviderType = Field(
        default="openai",
        description="LLM provider: openai, anthropic, google, xai",
    )
    anthropic_api_key: SecretStr = Field(
        default="",
        description="Anthropic API key (required if llm_provider=anthropic)",
    )
    google_api_key: SecretStr = Field(
        default="",
        description="Google AI API key (required if llm_provider=google)",
    )
    xai_api_key: SecretStr = Field(
        default="",
        description="xAI API key (required if llm_provider=xai)",
    )

    # Codex CLI path (OpenAI-only); wiring added later.
    use_codex: bool = Field(default=True, description="Use Codex CLI for deep audit (falls back to API)")
    codex_only: bool = Field(
        default=False,
        description="When true, disable API fallback and use Codex CLI as the only LLM path",
    )
    codex_model: str = Field(default="gpt-5.2-codex", description="Model for Codex CLI")
    codex_timeout: conint(ge=60) = Field(
        default=300, description="Codex timeout in seconds for Codex execution"
    )
    run_harness: bool = Field(default=True, description="Run security test harness")

    # GitHub integration (recommended)
    github_token: SecretStr = Field(default="", description="GitHub token used for API calls")

    # Sentinelayer integration (optional)
    sentinelayer_token: SecretStr = Field(default="", description="Sentinelayer API token")
    sentinelayer_managed_llm: bool = Field(
        default=False,
        description=(
            "Use Sentinelayer-managed LLM proxy. If false, managed mode auto-enables "
            "when openai_api_key is empty and sentinelayer_token is provided."
        ),
    )
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
    # Primary model for LLM API fallback path (when Codex CLI is unavailable).
    # Codex CLI model is configured separately via codex_model.
    model: str = Field(default="gpt-4.1")
    model_fallback: str = Field(default="gpt-4.1-mini")
    llm_failure_policy: LLMFailurePolicy = Field(default="block")

    # Rate limiting / cost control
    max_daily_scans: conint(ge=0) = Field(default=20)
    min_scan_interval_minutes: conint(ge=0) = Field(default=2)
    rate_limit_fail_mode: RateLimitFailMode = Field(
        default="closed",
        description="On GitHub API errors during rate limit enforcement: open or closed",
    )
    max_input_tokens: conint(ge=0) = Field(default=100000)
    require_cost_confirmation: confloat(ge=0) = Field(default=5.00)
    approval_mode: ApprovalMode = Field(default="pr_label")
    approval_label: str = Field(default="sentinelayer:approved")

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
        "rate_limit_fail_mode",
        "llm_provider",
        mode="before",
    )
    @classmethod
    def _normalize_lowercase(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _validate_provider_keys(self) -> "OmarGateConfig":
        """
        Cross-field validation for provider keys.

        We validate non-OpenAI providers strictly (they are always explicit).
        OpenAI is allowed to be empty so deterministic-only runs and fork handling
        can still execute without failing config parsing.
        """
        # Note: use_codex=true without openai_api_key is allowed at config time.
        # CodexRunner fails gracefully and the orchestrator falls back to LLM API.

        provider = self.llm_provider
        if provider == "anthropic" and not self.anthropic_api_key.get_secret_value():
            raise ValueError("anthropic_api_key is required when llm_provider=anthropic")
        if provider == "google" and not self.google_api_key.get_secret_value():
            raise ValueError("google_api_key is required when llm_provider=google")
        if provider == "xai" and not self.xai_api_key.get_secret_value():
            raise ValueError("xai_api_key is required when llm_provider=xai")

        if self.sentinelayer_managed_llm:
            if provider != "openai":
                raise ValueError("sentinelayer_managed_llm currently supports only llm_provider=openai")
            if not self.sentinelayer_token.get_secret_value():
                raise ValueError(
                    "sentinelayer_token is required when sentinelayer_managed_llm=true"
                )

        return self

    def use_managed_llm_proxy(self) -> bool:
        """
        Whether to use Sentinelayer-managed OpenAI proxy for LLM analysis.

        Explicit enable takes priority.
        Implicit enable supports 48-hour trial UX when BYO key is absent.
        """
        if self.llm_provider != "openai":
            return False

        if self.sentinelayer_managed_llm:
            return bool(self.sentinelayer_token.get_secret_value())

        has_openai = bool(self.openai_api_key.get_secret_value())
        has_sentinelayer = bool(self.sentinelayer_token.get_secret_value())
        return (not has_openai) and has_sentinelayer
