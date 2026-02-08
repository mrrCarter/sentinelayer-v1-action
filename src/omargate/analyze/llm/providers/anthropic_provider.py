from __future__ import annotations

import asyncio

from .base import LLMProvider, ProviderResponse


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API provider."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import anthropic
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(
                    "Install `anthropic` package to use Anthropic provider"
                ) from exc
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    async def call(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> ProviderResponse:
        response = await asyncio.wait_for(
            self.client.messages.create(
                model=model,
                system=system,
                messages=[{"role": "user", "content": user}],
                max_tokens=max_tokens,
                temperature=temperature,
            ),
            timeout=timeout,
        )

        # content is a list of blocks; first block is usually text.
        content_blocks = getattr(response, "content", None) or []
        text = ""
        if content_blocks:
            first = content_blocks[0]
            text = getattr(first, "text", "") or ""

        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0) if usage else 0
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0) if usage else 0

        return ProviderResponse(
            content=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        pricing_per_million = {
            "claude-opus-4-6": {"input": 15.0, "output": 75.0},
            "claude-sonnet-4-5-20250929": {"input": 3.0, "output": 15.0},
            "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
        }
        rates = pricing_per_million.get(model, {"input": 3.0, "output": 15.0})
        return (tokens_in / 1_000_000 * rates["input"]) + (tokens_out / 1_000_000 * rates["output"])
