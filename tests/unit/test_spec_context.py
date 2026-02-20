from __future__ import annotations

import pytest

from omargate.analyze.spec_context import fetch_spec_context


class DummyResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class DummyAsyncClient:
    def __init__(self, response: DummyResponse) -> None:
        self.response = response
        self.requests: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str, headers: dict | None = None):
        self.requests.append({"url": url, "headers": headers or {}})
        return self.response


@pytest.mark.anyio
async def test_fetch_spec_context_success(monkeypatch: pytest.MonkeyPatch) -> None:
    client = DummyAsyncClient(
        DummyResponse(
            200,
            payload={
                "spec_hash": "a" * 64,
                "project_name": "Spec Aware",
            },
        )
    )
    monkeypatch.setattr("omargate.analyze.spec_context.httpx.AsyncClient", lambda *args, **kwargs: client)

    result = await fetch_spec_context("A" * 64, sentinelayer_token="token")
    assert result is not None
    assert result["project_name"] == "Spec Aware"
    assert client.requests[0]["headers"]["Authorization"] == "Bearer token"


@pytest.mark.anyio
async def test_fetch_spec_context_returns_none_without_auth() -> None:
    result = await fetch_spec_context("a" * 64)
    assert result is None


@pytest.mark.anyio
async def test_fetch_spec_context_returns_none_on_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = DummyAsyncClient(DummyResponse(404))
    monkeypatch.setattr("omargate.analyze.spec_context.httpx.AsyncClient", lambda *args, **kwargs: client)

    result = await fetch_spec_context("a" * 64, sentinelayer_token="token")
    assert result is None
