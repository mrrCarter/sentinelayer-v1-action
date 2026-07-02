from __future__ import annotations

from omargate.main import _llm_fallback_used


def test_llm_fallback_used_detects_configured_fallback_model() -> None:
    assert _llm_fallback_used(
        {"model": "gemini-2.5-flash"},
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_detects_managed_capacity_route() -> None:
    assert _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "managed_after_byo_capacity",
        },
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_ignores_primary_byo_route() -> None:
    assert not _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "byo",
        },
        model_fallback="gemini-2.5-flash",
    )
