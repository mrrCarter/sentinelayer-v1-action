from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from omargate.telemetry.uploader import fetch_oidc_token, upload_artifacts, upload_telemetry


class DummyResponse:
    def __init__(self, status_code: int = 200, json_data: dict | None = None) -> None:
        self.status_code = status_code
        self._json_data = json_data or {}

    def json(self) -> dict:
        return self._json_data


class DummyAsyncClient:
    def __init__(self, responses=None, exceptions=None) -> None:
        self._responses = list(responses or [])
        self._exceptions = list(exceptions or [])
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None, headers=None):
        self.requests.append({"method": "post", "url": url, "json": json, "headers": headers})
        if self._exceptions:
            raise self._exceptions.pop(0)
        if self._responses:
            return self._responses.pop(0)
        return DummyResponse(status_code=500)

    async def get(self, url, headers=None):
        self.requests.append({"method": "get", "url": url, "headers": headers})
        if self._exceptions:
            raise self._exceptions.pop(0)
        if self._responses:
            return self._responses.pop(0)
        return DummyResponse(status_code=500)

    async def put(self, url, content=None, headers=None):
        self.requests.append({"method": "put", "url": url, "headers": headers})
        if self._exceptions:
            raise self._exceptions.pop(0)
        if self._responses:
            return self._responses.pop(0)
        return DummyResponse(status_code=200)


@pytest.mark.anyio
async def test_upload_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful upload returns True."""
    client = DummyAsyncClient(responses=[DummyResponse(status_code=200)])
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)

    result = await upload_telemetry({"tier": 1, "run": {}})
    assert result is True


@pytest.mark.anyio
async def test_upload_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timeout doesn't crash, returns False."""
    client = DummyAsyncClient(exceptions=[httpx.TimeoutException("timeout")])
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)
    monkeypatch.setattr("omargate.telemetry.uploader.asyncio.sleep", AsyncMock())

    result = await upload_telemetry({"tier": 1, "run": {}})
    assert result is False


@pytest.mark.anyio
async def test_upload_respects_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """429 response stops retries."""
    client = DummyAsyncClient(responses=[DummyResponse(status_code=429)])
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)

    result = await upload_telemetry({"tier": 1, "run": {}})
    assert result is False
    assert len(client.requests) == 1


@pytest.mark.anyio
async def test_upload_uses_oidc_over_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """OIDC token takes priority over sentinelayer_token."""
    client = DummyAsyncClient(responses=[DummyResponse(status_code=200)])
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)

    await upload_telemetry(
        {"tier": 1},
        sentinelayer_token="sentinelayer-token",
        oidc_token="oidc-token",
    )

    request = client.requests[0]
    assert request["headers"]["Authorization"] == "Bearer oidc-token"


@pytest.mark.anyio
async def test_upload_retries_with_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-200 responses retry with backoff."""
    client = DummyAsyncClient(
        responses=[DummyResponse(status_code=500), DummyResponse(status_code=200)]
    )
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)
    sleep_mock = AsyncMock()
    monkeypatch.setattr("omargate.telemetry.uploader.asyncio.sleep", sleep_mock)

    result = await upload_telemetry({"tier": 1, "run": {}})
    assert result is True
    sleep_mock.assert_awaited_once_with(1)


@pytest.mark.anyio
async def test_upload_artifacts_requires_token() -> None:
    """Artifacts upload requires token."""
    manifest = {"run_id": "run-1", "objects": []}
    result = await upload_artifacts(Path("."), manifest, sentinelayer_token="")
    assert result is False


@pytest.mark.anyio
async def test_fetch_oidc_token_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fetches OIDC token when env is present."""
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/oidc")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")

    client = DummyAsyncClient(responses=[DummyResponse(status_code=200, json_data={"value": "oidc-token"})])
    monkeypatch.setattr("omargate.telemetry.uploader.httpx.AsyncClient", lambda *args, **kwargs: client)

    token = await fetch_oidc_token()
    assert token == "oidc-token"


@pytest.mark.anyio
async def test_fetch_oidc_token_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when env vars are missing."""
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)

    token = await fetch_oidc_token()
    assert token is None
