from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMUsage:
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: int


@dataclass
class LLMResponse:
    content: str
    usage: LLMUsage
    success: bool
    error: Optional[str] = None


class LLMClient:
    """OpenAI SDK wrapper with retry and fallback (Responses API)."""

    def __init__(
        self,
        api_key: str,
        primary_model: str = "gpt-5.2-codex",
        fallback_model: str = "gpt-4.1",
        timeout_seconds: int = 120,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.timeout = timeout_seconds
        self.max_retries = max_retries
        self._client = None

    @property
    def client(self):
        """Lazy initialize OpenAI client."""
        if self._client is None:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

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
        """Call OpenAI Responses API with retry on transient failures."""
        last_error: Optional[str] = None

        for attempt in range(self.max_retries):
            try:
                start = time.time()
                response = await asyncio.wait_for(
                    self.client.responses.create(
                        model=model,
                        instructions=system,
                        input=user,
                        max_output_tokens=max_tokens,
                        temperature=0.1,
                    ),
                    timeout=self.timeout,
                )
                latency_ms = int((time.time() - start) * 1000)
                input_tokens = int(getattr(response.usage, "input_tokens", 0) or 0)
                output_tokens = int(getattr(response.usage, "output_tokens", 0) or 0)
                usage = LLMUsage(
                    model=model,
                    tokens_in=input_tokens,
                    tokens_out=output_tokens,
                    cost_usd=self.estimate_cost(model, input_tokens, output_tokens),
                    latency_ms=latency_ms,
                )
                content = getattr(response, "output_text", "") or ""
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
            usage=LLMUsage(model, 0, 0, 0.0, 0),
            success=False,
            error=last_error,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """Estimate cost in USD based on model pricing."""
        pricing = {
            "gpt-5.3-codex": {"input": 0.00175, "output": 0.014},
            "gpt-5.2-codex": {"input": 0.00175, "output": 0.014},
            "gpt-4.1": {"input": 0.002, "output": 0.008},
            "gpt-4.1-mini": {"input": 0.0004, "output": 0.0016},
            "gpt-4.1-nano": {"input": 0.0001, "output": 0.0004},
            "gpt-4o": {"input": 0.005, "output": 0.015},
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        }
        rates = pricing.get(model, {"input": 0.002, "output": 0.008})
        return (tokens_in / 1000 * rates["input"]) + (tokens_out / 1000 * rates["output"])
