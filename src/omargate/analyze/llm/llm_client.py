from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

from .providers import (
    AnthropicProvider,
    GeminiProvider,
    OpenAIProvider,
    XAIProvider,
    detect_provider_from_model,
)


@dataclass
class LLMUsage:
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: int
    provider: str = "openai"


@dataclass
class LLMResponse:
    content: str
    usage: LLMUsage
    success: bool
    error: Optional[str] = None


class LLMClient:
    """LLM SDK wrapper with retry and fallback across providers."""

    def __init__(
        self,
        api_key: str,
        primary_model: str = "gpt-5.2-codex",  # TODO: bump to gpt-5.3-codex when available
        fallback_model: str = "gpt-4.1",
        llm_provider: str = "openai",
        anthropic_api_key: str = "",
        google_api_key: str = "",
        xai_api_key: str = "",
        timeout_seconds: int = 120,
        max_retries: int = 2,
    ) -> None:
        # Back-compat: api_key is the OpenAI key used for OpenAI calls and fallback.
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
        self._providers: dict[str, object] = {}

    @property
    def client(self):
        """Lazy initialize OpenAI client."""
        if self._client is None:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    def _get_provider(self, provider_name: str):
        if provider_name in self._providers:
            return self._providers[provider_name]

        if provider_name == "openai":
            provider = OpenAIProvider(
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
        """
        Run analysis with automatic retry and fallback.

        Flow:
        1. Try primary_model (up to max_retries)
        2. On failure, try fallback_model (up to max_retries)
        3. Return error response if both fail
        """
        primary_response = await self._call_with_retry(
            self.primary_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if primary_response.success:
            return primary_response

        fallback_response = await self._call_with_retry(
            self.fallback_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if fallback_response.success:
            return fallback_response

        primary_error = primary_response.error or "unknown error"
        fallback_error = fallback_response.error or "unknown error"
        combined_error = f"Primary failed: {primary_error}; Fallback failed: {fallback_error}"
        return LLMResponse(
            content="",
            usage=fallback_response.usage,
            success=False,
            error=combined_error,
        )

    async def _call_with_retry(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Call provider API with retry on transient failures."""
        last_error: Optional[str] = None

        provider_name = detect_provider_from_model(model, default_provider=self.llm_provider)
        provider = self._get_provider(provider_name)

        for attempt in range(self.max_retries):
            try:
                start = time.time()
                response = await provider.call(
                    model=model,
                    system=system,
                    user=user,
                    max_tokens=max_tokens,
                    temperature=0.1,
                    timeout=self.timeout,
                )
                latency_ms = int((time.time() - start) * 1000)
                input_tokens = int(getattr(response, "input_tokens", 0) or 0)
                output_tokens = int(getattr(response, "output_tokens", 0) or 0)
                usage = LLMUsage(
                    model=model,
                    tokens_in=input_tokens,
                    tokens_out=output_tokens,
                    cost_usd=provider.estimate_cost(model, input_tokens, output_tokens),
                    latency_ms=latency_ms,
                    provider=provider_name,
                )
                content = getattr(response, "content", "") or ""
                return LLMResponse(
                    content=content,
                    usage=usage,
                    success=True,
                )
            except asyncio.TimeoutError:
                last_error = f"Timeout after {self.timeout}s"
            except Exception as exc:
                last_error = str(exc)

            if attempt < self.max_retries - 1:
                await asyncio.sleep(2**attempt)

        return LLMResponse(
            content="",
            usage=LLMUsage(model, 0, 0, 0.0, 0, provider=provider_name),
            success=False,
            error=last_error,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """Estimate cost in USD based on model pricing."""
        provider_name = detect_provider_from_model(model, default_provider=self.llm_provider)
        provider = self._get_provider(provider_name)
        return provider.estimate_cost(model, tokens_in, tokens_out)
