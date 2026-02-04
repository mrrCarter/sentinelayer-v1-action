from __future__ import annotations

import time

from omargate.telemetry import TelemetryCollector


def test_collector_computes_repo_hash() -> None:
    """Repo hash is deterministic but not reversible."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/app")
    assert len(collector.repo_hash) == 16
    assert (
        collector.repo_hash
        == TelemetryCollector(run_id="other", repo_full_name="acme/app").repo_hash
    )


def test_collector_stage_timing() -> None:
    """Stage timing records duration."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/app")
    collector.stage_start("ingest")
    time.sleep(0.02)
    collector.stage_end("ingest")

    durations = collector.stage_durations()
    assert "ingest" in durations
    assert durations["ingest"] >= 10


def test_collector_handles_missing_stage() -> None:
    """Ending a stage that wasn't started doesn't crash."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/app")
    collector.stage_end("nonexistent")


def test_collector_llm_usage_accumulates() -> None:
    """Multiple LLM calls accumulate tokens."""
    collector = TelemetryCollector(run_id="test", repo_full_name="acme/app")
    collector.record_llm_usage("gpt-4o", 100, 50, 0.01, 500)
    collector.record_llm_usage("gpt-4o", 200, 100, 0.02, 600)

    assert collector.tokens_in == 300
    assert collector.tokens_out == 150
    assert abs(collector.estimated_cost_usd - 0.03) < 1e-6
