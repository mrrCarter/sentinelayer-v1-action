from __future__ import annotations

import pytest
from pydantic import ValidationError

from omargate.config import OmarGateConfig


def test_config_loads_defaults_and_masks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    cfg = OmarGateConfig()

    assert cfg.scan_mode == "pr-diff"
    assert cfg.severity_gate == "P1"
    assert "sk_test_dummy" not in repr(cfg)


def test_config_parses_booleans(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_RUN_DETERMINISTIC_FIX", "true")
    monkeypatch.setenv("INPUT_TRAINING_OPT_IN", "true")
    monkeypatch.setenv("INPUT_TELEMETRY", "false")
    monkeypatch.setenv("INPUT_SHARE_METADATA", "true")
    monkeypatch.setenv("INPUT_SHARE_ARTIFACTS", "true")
    cfg = OmarGateConfig()

    assert cfg.run_deterministic_fix is True
    assert cfg.training_opt_in is True
    assert cfg.telemetry is False
    assert cfg.share_metadata is True
    assert cfg.share_artifacts is True


def test_invalid_severity_gate_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_SEVERITY_GATE", "P9")

    with pytest.raises(ValidationError):
        OmarGateConfig()


def test_config_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    cfg = OmarGateConfig()

    # Pydantic 2.x raises ValidationError for frozen models
    with pytest.raises((TypeError, ValidationError)):
        cfg.scan_mode = "deep"
