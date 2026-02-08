from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from omargate.analyze.llm.llm_client import LLMClient, LLMResponse, LLMUsage


def _make_response(content: str = "ok", input_tokens: int = 10, output_tokens: int = 5):
    usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    return SimpleNamespace(usage=usage, output_text=content)


@pytest.mark.anyio
async def test_llm_client_success() -> None:
    """Successful API call returns content and usage."""
    client = LLMClient(api_key="test", max_retries=1)
    response = _make_response("hello", 12, 3)

    fake_client = SimpleNamespace(
        responses=SimpleNamespace(create=AsyncMock(return_value=response))
    )
    client._client = fake_client

    result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "hello"
    assert result.usage.tokens_in == 12
    assert result.usage.tokens_out == 3
    assert result.usage.model == client.primary_model


@pytest.mark.anyio
async def test_llm_client_retry_on_timeout() -> None:
    """Client retries on timeout, then succeeds."""
    client = LLMClient(api_key="test", max_retries=2)
    response = _make_response("ok", 5, 2)

    create_mock = AsyncMock(side_effect=[asyncio.TimeoutError(), response])
    fake_client = SimpleNamespace(
        responses=SimpleNamespace(create=create_mock)
    )
    client._client = fake_client

    with patch("omargate.analyze.llm.llm_client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
        result = await client.analyze("system", "user")

    assert result.success is True
    assert create_mock.call_count == 2
    sleep_mock.assert_awaited_once_with(1)


@pytest.mark.anyio
async def test_llm_client_fallback_to_secondary_model() -> None:
    """Falls back to secondary model when primary fails."""
    client = LLMClient(api_key="test")

    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.primary_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="primary failed",
    )
    fallback_success = LLMResponse(
        content="fallback",
        usage=LLMUsage(model=client.fallback_model, tokens_in=1, tokens_out=1, cost_usd=0.0, latency_ms=1),
        success=True,
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary_fail, fallback_success]),
    ) as retry_mock:
        result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "fallback"
    assert retry_mock.call_count == 2
    assert retry_mock.call_args_list[0].args[0] == client.primary_model
    assert retry_mock.call_args_list[1].args[0] == client.fallback_model


@pytest.mark.anyio
async def test_llm_client_returns_error_when_both_fail() -> None:
    """Returns error response when both models fail."""
    client = LLMClient(api_key="test")

    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.primary_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="primary error",
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.fallback_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="fallback error",
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
    ):
        result = await client.analyze("system", "user")

    assert result.success is False
    assert result.error is not None
    assert "Primary failed" in result.error
    assert "Fallback failed" in result.error


def test_cost_estimation() -> None:
    """Cost estimation matches expected pricing."""
    client = LLMClient(api_key="test")
    cost = client.estimate_cost("gpt-4o", tokens_in=10000, tokens_out=1000)
    expected = (10000 / 1000 * 0.005) + (1000 / 1000 * 0.015)
    assert abs(cost - expected) < 0.001
