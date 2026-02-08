from __future__ import annotations

import asyncio

from .base import LLMProvider, ProviderResponse


class XAIProvider(LLMProvider):
    """xAI (Grok) provider via OpenAI-compatible Chat Completions API."""

    def __init__(self, api_key: str, *, base_url: str = "https://api.x.ai/v1") -> None:
        self.api_key = api_key
        self.base_url = base_url
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
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
            self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            ),
            timeout=timeout,
        )

        text = ""
        choices = getattr(response, "choices", None) or []
        if choices:
            message = getattr(choices[0], "message", None)
            text = getattr(message, "content", "") if message is not None else ""
            text = text or ""

        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0) if usage else 0
        output_tokens = int(getattr(usage, "completion_tokens", 0) or 0) if usage else 0

        return ProviderResponse(
            content=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        pricing_per_million = {
            "grok-3": {"input": 3.0, "output": 15.0},
            "grok-3-mini": {"input": 3.0, "output": 15.0},
        }
        rates = pricing_per_million.get(model, {"input": 3.0, "output": 15.0})
        return (tokens_in / 1_000_000 * rates["input"]) + (tokens_out / 1_000_000 * rates["output"])

