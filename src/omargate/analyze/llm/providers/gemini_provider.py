from __future__ import annotations

import asyncio

from .base import LLMProvider, ProviderResponse


class GeminiProvider(LLMProvider):
    """Google Gemini provider (google-genai SDK)."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from google import genai
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(
                    "Install `google-genai` package to use Google provider"
                ) from exc
            self._client = genai.Client(api_key=self.api_key)
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
        # The google-genai SDK uses sync methods today in some versions; keep it awaitable.
        def _run():
            return self.client.models.generate_content(
                model=model,
                contents=user,
                config={
                    "system_instruction": system,
                    "temperature": temperature,
                    "max_output_tokens": max_tokens,
                },
            )

        response = await asyncio.wait_for(asyncio.to_thread(_run), timeout=timeout)

        text = getattr(response, "text", "") or ""

        usage = getattr(response, "usage_metadata", None)
        input_tokens = 0
        output_tokens = 0
        if usage is not None:
            input_tokens = int(
                getattr(usage, "prompt_token_count", 0)
                or getattr(usage, "prompt_tokens", 0)
                or 0
            )
            output_tokens = int(
                getattr(usage, "candidates_token_count", 0)
                or getattr(usage, "response_token_count", 0)
                or getattr(usage, "completion_tokens", 0)
                or 0
            )

        return ProviderResponse(
            content=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        pricing_per_million = {
            "gemini-2.5-pro": {"input": 1.25, "output": 10.0},
            "gemini-2.5-flash": {"input": 0.15, "output": 0.60},
        }
        rates = pricing_per_million.get(model, {"input": 1.25, "output": 10.0})
        return (tokens_in / 1_000_000 * rates["input"]) + (tokens_out / 1_000_000 * rates["output"])

