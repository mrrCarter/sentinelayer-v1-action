from __future__ import annotations

import json
from urllib.error import HTTPError

import pytest

from omargate.analyze import spec_context


class DummyResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> bool:
        return False

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


@pytest.mark.anyio
async def test_fetch_spec_context_uses_normalized_hash_and_bearer_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []
    payload = json.dumps({"project_name": "Spec Aware"}).encode()

    def fake_urlopen(request, *, timeout: int):
        requests.append(request)
        assert timeout == 10
        return DummyResponse(payload)

    monkeypatch.setattr(spec_context, "urlopen", fake_urlopen)

    result = await spec_context.fetch_spec_context(
        "A" * 64,
        sentinelayer_token="token",
    )

    assert result == {"project_name": "Spec Aware"}
    request = requests[0]
    assert request.full_url.endswith("/" + "a" * 64)
    assert request.get_header("Authorization") == "Bearer token"


@pytest.mark.anyio
async def test_fetch_spec_context_rejects_invalid_hash_or_missing_auth() -> None:
    assert await spec_context.fetch_spec_context("not-a-hash", "token") is None
    assert await spec_context.fetch_spec_context("a" * 64) is None


def test_fetch_spec_context_treats_not_found_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def not_found(*_args, **_kwargs):
        raise HTTPError("https://example.test", 404, "missing", {}, None)

    monkeypatch.setattr(spec_context, "urlopen", not_found)

    assert spec_context._fetch_spec_context_sync("a" * 64, "token") is None


def test_fetch_spec_context_rejects_oversized_or_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        spec_context,
        "urlopen",
        lambda *_args, **_kwargs: DummyResponse(
            b"x" * (spec_context.MAX_CONTEXT_BYTES + 1)
        ),
    )
    assert spec_context._fetch_spec_context_sync("a" * 64, "token") is None

    monkeypatch.setattr(
        spec_context,
        "urlopen",
        lambda *_args, **_kwargs: DummyResponse(b"[]"),
    )
    assert spec_context._fetch_spec_context_sync("a" * 64, "token") is None
