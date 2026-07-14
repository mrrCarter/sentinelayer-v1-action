from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from omargate.analyze.llm.llm_client import LLMClient, LLMResponse, LLMUsage
from omargate.analyze.llm.providers.base import ProviderResponse


class FakeProvider:
    def __init__(self, *outcomes: ProviderResponse | BaseException) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    async def call(self, **_kwargs) -> ProviderResponse:
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def estimate_cost(self, _model: str, tokens_in: int, tokens_out: int) -> float:
        return (tokens_in + tokens_out) / 1_000_000


def provider_response(content: str = "ok") -> ProviderResponse:
    return ProviderResponse(
        content=content,
        input_tokens=12,
        output_tokens=3,
        model="gpt-5.3-codex",
    )


def failed_response(model: str, error: str, provider: str = "openai") -> LLMResponse:
    return LLMResponse(
        content="",
        usage=LLMUsage(
            model=model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider=provider,
        ),
        success=False,
        error=error,
    )


@pytest.mark.anyio
async def test_llm_client_success_records_usage() -> None:
    provider = FakeProvider(provider_response("hello"))
    client = LLMClient(
        api_key="test",
        max_retries=1,
        provider_overrides={"openai": provider},
    )

    result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "hello"
    assert result.usage.tokens_in == 12
    assert result.usage.tokens_out == 3
    assert result.usage.route == "byo"
    assert provider.calls == 1


@pytest.mark.anyio
async def test_llm_client_retries_with_bounded_backoff() -> None:
    provider = FakeProvider(asyncio.TimeoutError(), provider_response())
    client = LLMClient(
        api_key="test",
        max_retries=2,
        provider_overrides={"openai": provider},
    )

    with patch(
        "omargate.analyze.llm.llm_client.asyncio.sleep", new=AsyncMock()
    ) as sleep:
        result = await client.analyze("system", "user")

    assert result.success is True
    assert provider.calls == 2
    sleep.assert_awaited_once_with(1)


@pytest.mark.anyio
async def test_llm_client_falls_back_across_providers() -> None:
    anthropic = FakeProvider(RuntimeError("capacity"))
    openai = FakeProvider(provider_response("fallback"))
    client = LLMClient(
        api_key="openai-key",
        primary_model="claude-sonnet-4-5-20250929",
        fallback_model="gpt-4.1",
        max_retries=1,
        provider_overrides={"anthropic": anthropic, "openai": openai},
    )

    result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "fallback"
    assert result.usage.provider == "openai"
    assert anthropic.calls == 1
    assert openai.calls == 1


@pytest.mark.anyio
async def test_llm_client_redacts_errors_when_both_models_fail() -> None:
    client = LLMClient(api_key="test", max_retries=1)
    primary = failed_response(
        client.primary_model,
        "quota failed sk-testtesttesttest",
    )
    fallback = failed_response(
        client.fallback_model,
        "consumer projects/123456789012 suspended",
        provider="google",
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary, fallback]),
    ):
        result = await client.analyze("system", "user")

    assert result.success is False
    assert "Primary failed" in str(result.error)
    assert "Fallback failed" in str(result.error)
    assert "sk-testtesttesttest" not in str(result.error)
    assert "123456789012" not in str(result.error)


@pytest.mark.anyio
async def test_llm_client_propagates_cancellation() -> None:
    provider = FakeProvider(asyncio.CancelledError())
    client = LLMClient(
        api_key="test",
        provider_overrides={"openai": provider},
    )

    with pytest.raises(asyncio.CancelledError):
        await client.analyze("system", "user")


def test_llm_client_rejects_unbounded_configuration() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        LLMClient(api_key="test", timeout_seconds=0)
    with pytest.raises(ValueError, match="max_retries"):
        LLMClient(api_key="test", max_retries=0)


def test_llm_client_has_no_managed_content_proxy() -> None:
    client = LLMClient(api_key="test")

    assert not hasattr(client, "_call_managed_proxy")
    with pytest.raises(TypeError):
        LLMClient(api_key="test", managed_llm=True)  # type: ignore[call-arg]


def test_cost_estimation_delegates_to_selected_provider() -> None:
    provider = FakeProvider(provider_response())
    client = LLMClient(
        api_key="test",
        provider_overrides={"openai": provider},
    )

    assert client.estimate_cost("gpt-4.1", 10, 5) == 0.000015
