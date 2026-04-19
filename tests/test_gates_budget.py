"""Tests for src/omargate/gates/budget.py — token budget state machine."""

from __future__ import annotations

import unittest

from omargate.gates.budget import (
    QuotaState,
    RateLimitHeaders,
    TokenBudgetTracker,
    parse_rate_limit_headers,
)


# ---------- parse_rate_limit_headers ----------


class ParseRateLimitHeadersTests(unittest.TestCase):
    def test_none_returns_empty_struct(self) -> None:
        parsed = parse_rate_limit_headers(None)
        self.assertIsNone(parsed.status)
        self.assertIsNone(parsed.util_5h)

    def test_empty_dict_returns_empty_struct(self) -> None:
        parsed = parse_rate_limit_headers({})
        self.assertIsNone(parsed.status)

    def test_case_insensitive_header_lookup(self) -> None:
        parsed = parse_rate_limit_headers({
            "ANTHROPIC-RATELIMIT-UNIFIED-STATUS": "allowed",
            "Anthropic-Ratelimit-Unified-5h-Utilization": "0.5",
        })
        self.assertEqual(parsed.status, "allowed")
        self.assertEqual(parsed.util_5h, 0.5)

    def test_parses_numeric_values(self) -> None:
        parsed = parse_rate_limit_headers({
            "anthropic-ratelimit-unified-5h-utilization": "0.92",
            "anthropic-ratelimit-unified-7d-utilization": "0.33",
            "anthropic-ratelimit-unified-reset": "1735689600",
            "retry-after": "30",
        })
        self.assertEqual(parsed.util_5h, 0.92)
        self.assertEqual(parsed.util_7d, 0.33)
        self.assertEqual(parsed.resets_at, 1735689600)
        self.assertEqual(parsed.retry_after_s, 30)

    def test_malformed_numeric_values_become_none(self) -> None:
        parsed = parse_rate_limit_headers({
            "anthropic-ratelimit-unified-5h-utilization": "not-a-number",
        })
        self.assertIsNone(parsed.util_5h)


# ---------- TokenBudgetTracker — state transitions ----------


class TrackerInitialStateTests(unittest.TestCase):
    def test_starts_in_normal(self) -> None:
        t = TokenBudgetTracker()
        self.assertEqual(t.state, QuotaState.NORMAL)
        self.assertFalse(t.using_overage)


class TrackerResponseHeadersTests(unittest.TestCase):
    def _clock(self, t: float):
        return lambda: t

    def test_allowed_status_returns_to_normal(self) -> None:
        t = TokenBudgetTracker(clock=self._clock(1000.0))
        t._state = QuotaState.WARNING  # type: ignore[attr-defined]
        t.on_response_headers({"anthropic-ratelimit-unified-status": "allowed"})
        self.assertEqual(t.state, QuotaState.NORMAL)

    def test_rejected_status_throttles(self) -> None:
        t = TokenBudgetTracker(clock=self._clock(1000.0))
        t.on_response_headers({"anthropic-ratelimit-unified-status": "rejected"})
        self.assertEqual(t.state, QuotaState.THROTTLED)

    def test_five_hour_util_crosses_warning(self) -> None:
        # Utilization 0.92 at ~60% through 5h window (time_progress < 0.72) → warn
        now = 1_000_000.0
        resets_at = int(now + 2 * 3600)  # window ends in 2h → elapsed = 3h → tp = 0.6
        t = TokenBudgetTracker(clock=self._clock(now))
        t.on_response_headers({
            "anthropic-ratelimit-unified-5h-utilization": "0.92",
            "anthropic-ratelimit-unified-reset": str(resets_at),
        })
        self.assertEqual(t.state, QuotaState.WARNING)
        self.assertIn("early_warning[5h]", t.last_reason)

    def test_seven_day_util_deeply_over_multiple_thresholds(self) -> None:
        # util 0.80 very early in 7d window → hits 0.75 threshold
        now = 1_000_000.0
        resets_at = int(now + 6.5 * 86_400)  # window ends in 6.5d → elapsed 0.5d → tp 0.071
        t = TokenBudgetTracker(clock=self._clock(now))
        t.on_response_headers({
            "anthropic-ratelimit-unified-7d-utilization": "0.80",
            "anthropic-ratelimit-unified-reset": str(resets_at),
        })
        self.assertEqual(t.state, QuotaState.WARNING)

    def test_util_high_but_late_in_window_does_not_warn(self) -> None:
        # util 0.92 at ~90% through 5h window (time_progress > 0.72) → NORMAL
        now = 1_000_000.0
        resets_at = int(now + 0.3 * 3600)  # 0.3h left → elapsed 4.7h → tp 0.94
        t = TokenBudgetTracker(clock=self._clock(now))
        t.on_response_headers({
            "anthropic-ratelimit-unified-5h-utilization": "0.92",
            "anthropic-ratelimit-unified-reset": str(resets_at),
        })
        self.assertEqual(t.state, QuotaState.NORMAL)


class TrackerRateLimitErrorTests(unittest.TestCase):
    def test_429_with_retry_after_moves_to_throttled(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({"retry-after": "15"})
        self.assertEqual(t.state, QuotaState.THROTTLED)

    def test_429_without_retry_after_moves_to_exhausted(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({})
        self.assertEqual(t.state, QuotaState.EXHAUSTED)

    def test_429_with_overage_allowed_moves_to_using_overage(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({
            "retry-after": "15",
            "anthropic-ratelimit-overage-status": "allowed",
        })
        self.assertEqual(t.state, QuotaState.USING_OVERAGE)
        self.assertTrue(t.using_overage)

    def test_explicit_retry_after_s_param_wins(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({}, retry_after_s=45)
        self.assertEqual(t.state, QuotaState.THROTTLED)
        self.assertIn("retry_after=45s", t.last_reason)


# ---------- should_allow_call ----------


class ShouldAllowCallTests(unittest.TestCase):
    def test_normal_state_always_allows(self) -> None:
        t = TokenBudgetTracker()
        d = t.should_allow_call(100_000)
        self.assertTrue(d.allow)
        self.assertFalse(d.warn)

    def test_exhausted_blocks_all(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({})  # → EXHAUSTED
        d = t.should_allow_call(100)
        self.assertFalse(d.allow)
        self.assertIn("exhausted", d.reason)

    def test_throttled_allows_under_cap_with_warn(self) -> None:
        t = TokenBudgetTracker(throttle_budget_tokens=5_000)
        t.on_rate_limit_error({"retry-after": "10"})  # → THROTTLED
        under = t.should_allow_call(2_000)
        over = t.should_allow_call(10_000)
        self.assertTrue(under.allow)
        self.assertTrue(under.warn)
        self.assertFalse(over.allow)
        self.assertIn("throttled", over.reason)

    def test_warning_allows_with_warn_flag(self) -> None:
        t = TokenBudgetTracker(clock=lambda: 1_000_000.0, warning_budget_tokens=8_000)
        t.on_response_headers({
            "anthropic-ratelimit-unified-5h-utilization": "0.92",
            "anthropic-ratelimit-unified-reset": str(int(1_000_000.0 + 2 * 3600)),
        })
        self.assertEqual(t.state, QuotaState.WARNING)
        under = t.should_allow_call(5_000)
        over = t.should_allow_call(12_000)
        self.assertTrue(under.allow)
        self.assertTrue(under.warn)
        self.assertTrue(over.allow)  # warnings still allow, just emit warn flag
        self.assertTrue(over.warn)

    def test_using_overage_allows_with_warn(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({"anthropic-ratelimit-overage-status": "allowed"})
        d = t.should_allow_call(100)
        self.assertTrue(d.allow)
        self.assertTrue(d.warn)
        self.assertIn("overage", d.reason)


class ResetTests(unittest.TestCase):
    def test_reset_restores_normal(self) -> None:
        t = TokenBudgetTracker()
        t.on_rate_limit_error({})
        self.assertEqual(t.state, QuotaState.EXHAUSTED)
        t.reset()
        self.assertEqual(t.state, QuotaState.NORMAL)
        self.assertFalse(t.using_overage)


if __name__ == "__main__":
    unittest.main()
