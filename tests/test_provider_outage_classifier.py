from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "classify_omar_provider_outage.py"
)
_SPEC = importlib.util.spec_from_file_location("classify_omar_provider_outage", _SCRIPT_PATH)
assert _SPEC is not None
classifier = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules[_SPEC.name] = classifier
_SPEC.loader.exec_module(classifier)


def test_classifies_backend_shape_system_provider_outage() -> None:
    result = classifier.classify_provider_outage(
        [
            {
                "severity": "P0",
                "category": "LLM Failure",
                "provenance": "system",
                "scope": {"path": "<system>"},
                "impact": (
                    "LLM analysis failed: primary failed and fallback failed; "
                    "blocking merge per fail-closed policy. Provider outage detail: "
                    "Google managed Omar call failed: HTTP 403 - CONSUMER_SUSPENDED"
                ),
            }
        ]
    )

    assert result.provider_outage_break_glass is True
    assert result.reason == "single_system_llm_provider_outage"


def test_classifies_legacy_flat_system_provider_outage() -> None:
    result = classifier.classify_provider_outage(
        [
            {
                "severity": "P0",
                "category": "LLM Failure",
                "source": "system",
                "file_path": "<system>",
                "message": (
                    "LLM analysis failed: primary failed and fallback failed; "
                    "blocking merge per fail-closed policy. OpenAI 429 quota exhausted."
                ),
            }
        ]
    )

    assert result.provider_outage_break_glass is True
    assert result.p0_count == 1


def test_refuses_provider_outage_break_glass_when_real_findings_exist() -> None:
    result = classifier.classify_provider_outage(
        [
            {
                "severity": "P0",
                "category": "LLM Failure",
                "provenance": "system",
                "scope": {"path": "<system>"},
                "impact": (
                    "LLM analysis failed: primary failed and fallback failed; "
                    "blocking merge per fail-closed policy. quota exhausted."
                ),
            },
            {
                "severity": "P1",
                "category": "security",
                "source": "deterministic",
                "file_path": "src/app.py",
                "message": "Hard-coded credential.",
            },
        ]
    )

    assert result.provider_outage_break_glass is False
    assert result.reason == "blocking_non_p0_findings_present"


def test_refuses_provider_outage_break_glass_for_non_system_p0() -> None:
    result = classifier.classify_provider_outage(
        [
            {
                "severity": "P0",
                "category": "security",
                "source": "deterministic",
                "file_path": "src/app.py",
                "message": "Remote code execution.",
            }
        ]
    )

    assert result.provider_outage_break_glass is False
    assert result.reason == "p0_is_not_system_llm_failure"
