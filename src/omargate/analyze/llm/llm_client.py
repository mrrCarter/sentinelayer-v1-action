from __future__ import annotations

import asyncio
from dataclasses import dataclass
import time
from typing import Mapping, Optional

from ...redaction import sanitize_public_error
from .providers import (
    AnthropicProvider,
    GeminiProvider,
    LLMProvider,
    OpenAIProvider,
    XAIProvider,
    detect_provider_from_model,
)


@dataclass(frozen=True)
class LLMUsage:
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: int
    provider: str = "openai"
    route: str = "byo"


@dataclass(frozen=True)
class LLMResponse:
    content: str
    usage: LLMUsage
    success: bool
    error: Optional[str] = None


class LLMClient:
    """BYO-provider analysis client with bounded retry and model fallback.

    Managed SentinelLayer execution deliberately does not live in this client.
    Managed results cross the action boundary only through the separately verified
    receipt contract, so this module cannot accidentally trust proxy response text.
    """

    def __init__(
        self,
        api_key: str,
        primary_model: str = "gpt-5.3-codex",
        fallback_model: str = "gpt-5.2-codex",
        llm_provider: str = "openai",
        anthropic_api_key: str = "",
        google_api_key: str = "",
        xai_api_key: str = "",
        timeout_seconds: int = 120,
        max_retries: int = 2,
        *,
        provider_overrides: Optional[Mapping[str, LLMProvider]] = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_retries <= 0:
            raise ValueError("max_retries must be positive")

        self.api_key = api_key
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.llm_provider = llm_provider
        self.anthropic_api_key = anthropic_api_key
        self.google_api_key = google_api_key
        self.xai_api_key = xai_api_key
        self.timeout = timeout_seconds
        self.max_retries = max_retries
        self._client = None
        self._providers: dict[str, LLMProvider] = dict(provider_overrides or {})

    @property
    def client(self):
        """Lazily initialize the OpenAI SDK only when OpenAI is selected."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError as exc:  # pragma: no cover - depends on runner image
                raise RuntimeError(
                    "Install `openai` package to use OpenAI provider"
                ) from exc
            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    def _get_provider(self, provider_name: str) -> LLMProvider:
        existing = self._providers.get(provider_name)
        if existing is not None:
            return existing

        if provider_name == "openai":
            provider: LLMProvider = OpenAIProvider(
                api_key=self.api_key,
                client_getter=lambda: self.client,
            )
        elif provider_name == "anthropic":
            provider = AnthropicProvider(api_key=self.anthropic_api_key)
        elif provider_name == "google":
            provider = GeminiProvider(api_key=self.google_api_key)
        elif provider_name == "xai":
            provider = XAIProvider(api_key=self.xai_api_key)
        else:
            raise ValueError(f"Unknown LLM provider: {provider_name}")

        self._providers[provider_name] = provider
        return provider

    async def analyze(
        self,
        system_prompt: str,
        user_content: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Try the primary model, then the configured fallback model."""
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        primary = await self._call_with_retry(
            self.primary_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if primary.success:
            return primary

        fallback = await self._call_with_retry(
            self.fallback_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if fallback.success:
            return fallback

        primary_error = sanitize_public_error(primary.error or "unknown error")
        fallback_error = sanitize_public_error(fallback.error or "unknown error")
        return LLMResponse(
            content="",
            usage=fallback.usage,
            success=False,
            error=f"Primary failed: {primary_error}; Fallback failed: {fallback_error}",
        )

    async def _call_with_retry(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
    ) -> LLMResponse:
        provider_name = detect_provider_from_model(
            model,
            default_provider=self.llm_provider,
        )
        try:
            provider = self._get_provider(provider_name)
        except Exception as exc:
            return self._failure(model, provider_name, exc)

        last_error = "provider call failed"
        for attempt in range(self.max_retries):
            started = time.monotonic()
            try:
                response = await provider.call(
                    model=model,
                    system=system,
                    user=user,
                    max_tokens=max_tokens,
                    temperature=0.1,
                    timeout=self.timeout,
                )
                latency_ms = int((time.monotonic() - started) * 1000)
                tokens_in = max(0, int(response.input_tokens or 0))
                tokens_out = max(0, int(response.output_tokens or 0))
                return LLMResponse(
                    content=str(response.content or ""),
                    usage=LLMUsage(
                        model=model,
                        tokens_in=tokens_in,
                        tokens_out=tokens_out,
                        cost_usd=max(
                            0.0,
                            float(provider.estimate_cost(model, tokens_in, tokens_out)),
                        ),
                        latency_ms=latency_ms,
                        provider=provider_name,
                    ),
                    success=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = sanitize_public_error(exc) or "provider call failed"

            if attempt + 1 < self.max_retries:
                await asyncio.sleep(min(2**attempt, 8))

        return self._failure(model, provider_name, last_error)

    @staticmethod
    def _failure(model: str, provider_name: str, error: object) -> LLMResponse:
        return LLMResponse(
            content="",
            usage=LLMUsage(
                model=model,
                tokens_in=0,
                tokens_out=0,
                cost_usd=0.0,
                latency_ms=0,
                provider=provider_name,
            ),
            success=False,
            error=sanitize_public_error(error) or "provider call failed",
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        provider_name = detect_provider_from_model(
            model,
            default_provider=self.llm_provider,
        )
        provider = self._get_provider(provider_name)
        return max(0.0, float(provider.estimate_cost(model, tokens_in, tokens_out)))
