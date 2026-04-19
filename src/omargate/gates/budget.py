"""Token budget + rate-limit state machine for Omar Gate 2.0.

Per CODEX_OMARGATE_COMBINE_SPEC.md §5.2: replace the per-call cost
estimation heuristics with a deterministic state machine that ingests
provider rate-limit headers and transitions between states.

Callers check `should_allow_call(estimate)` before each LLM invocation.
On API responses, call `on_response_headers(headers)`. On 429 errors,
call `on_rate_limit_error(headers, retry_after_s)`.

State transitions:

    NORMAL ─(warning threshold)─> WARNING
       │                              │
       │                              ▼
       └────(429 / rejected)─────> THROTTLED ──(retry-after expires)──> NORMAL
                                      │
                                      ▼
                                  EXHAUSTED (quota window elapsed, no overage)
                                      │
                                      ▼
                                 USING_OVERAGE (if overage header present)

Thresholds and windows follow the pattern in the §5.2 pseudocode with
client-side fallback when provider headers are absent. We deliberately
keep this state local to each runner — cross-runner quota accounting is
the API's responsibility.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

__all__ = [
    "QuotaState",
    "TokenBudgetTracker",
    "BudgetDecision",
    "RateLimitHeaders",
    "parse_rate_limit_headers",
]


class QuotaState(str, Enum):
    NORMAL = "normal"
    WARNING = "warning"
    THROTTLED = "throttled"
    EXHAUSTED = "exhausted"
    USING_OVERAGE = "using_overage"


@dataclass(frozen=True)
class RateLimitHeaders:
    """Normalized view of provider rate-limit headers.

    Providers emit these under slightly different names; this dataclass
    is the canonical form used internally. `None` fields indicate the
    header was not present in the response.
    """

    status: str | None = None            # "allowed" | "rejected"
    util_5h: float | None = None         # 0.0 - 1.0
    util_7d: float | None = None         # 0.0 - 1.0
    resets_at: int | None = None         # unix seconds
    overage_status: str | None = None    # "allowed" | "disabled"
    retry_after_s: int | None = None


# Anthropic / OpenAI header names we look for. The parser is tolerant
# of either casing and of missing headers.
_HEADER_NAMES = {
    "status": ("anthropic-ratelimit-unified-status",),
    "util_5h": (
        "anthropic-ratelimit-unified-5h-utilization",
        "x-ratelimit-unified-5h-utilization",
    ),
    "util_7d": (
        "anthropic-ratelimit-unified-7d-utilization",
        "x-ratelimit-unified-7d-utilization",
    ),
    "resets_at": (
        "anthropic-ratelimit-unified-reset",
        "x-ratelimit-reset",
    ),
    "overage_status": (
        "anthropic-ratelimit-overage-status",
    ),
    "retry_after_s": (
        "retry-after",
    ),
}


def _case_insensitive_get(headers: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    lower = {k.lower(): v for k, v in headers.items()}
    for name in candidates:
        v = lower.get(name.lower())
        if v is not None and str(v).strip() != "":
            return str(v)
    return None


def _to_float(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _to_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return None


def parse_rate_limit_headers(headers: dict[str, str] | None) -> RateLimitHeaders:
    """Normalize a provider's response headers into a RateLimitHeaders struct."""
    if not isinstance(headers, dict):
        return RateLimitHeaders()
    return RateLimitHeaders(
        status=_case_insensitive_get(headers, _HEADER_NAMES["status"]),
        util_5h=_to_float(_case_insensitive_get(headers, _HEADER_NAMES["util_5h"])),
        util_7d=_to_float(_case_insensitive_get(headers, _HEADER_NAMES["util_7d"])),
        resets_at=_to_int(_case_insensitive_get(headers, _HEADER_NAMES["resets_at"])),
        overage_status=_case_insensitive_get(headers, _HEADER_NAMES["overage_status"]),
        retry_after_s=_to_int(_case_insensitive_get(headers, _HEADER_NAMES["retry_after_s"])),
    )


@dataclass
class BudgetDecision:
    """Returned by `should_allow_call`. Callers may ignore `warn` but not `allow=False`."""

    allow: bool
    warn: bool = False
    reason: str = ""
    state: QuotaState = QuotaState.NORMAL


# Warning thresholds per window. Each entry is (utilization_threshold,
# time_progress_threshold). We warn when utilization >= X AND time
# progress through the window is <= Y (i.e. we're high-util but still
# early in the window).
_EARLY_WARNING_CONFIGS = {
    "five_hour": {
        "window_seconds": 5 * 3600,
        "thresholds": ((0.90, 0.72),),
    },
    "seven_day": {
        "window_seconds": 7 * 86_400,
        "thresholds": (
            (0.75, 0.60),
            (0.50, 0.35),
            (0.25, 0.15),
        ),
    },
}

_DEFAULT_THROTTLE_TOKEN_CAP = 4_000
_DEFAULT_WARNING_TOKEN_CAP = 16_000


class TokenBudgetTracker:
    """Stateful tracker. Not thread-safe; callers wrap in a lock if needed."""

    def __init__(
        self,
        *,
        throttle_budget_tokens: int = _DEFAULT_THROTTLE_TOKEN_CAP,
        warning_budget_tokens: int = _DEFAULT_WARNING_TOKEN_CAP,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._state = QuotaState.NORMAL
        self._throttle_cap = int(throttle_budget_tokens)
        self._warn_cap = int(warning_budget_tokens)
        self._clock = clock
        self._resets_at: int | None = None
        self._last_reason: str = ""
        self._overage: bool = False

    @property
    def state(self) -> QuotaState:
        return self._state

    @property
    def resets_at(self) -> int | None:
        return self._resets_at

    @property
    def last_reason(self) -> str:
        return self._last_reason

    @property
    def using_overage(self) -> bool:
        return self._overage

    def on_response_headers(self, headers: dict[str, str] | None) -> QuotaState:
        """Ingest a 200 response's rate-limit headers and update state."""
        parsed = parse_rate_limit_headers(headers)
        now = self._clock()

        # Record reset time (tolerate future or past values; tracker uses
        # them advisorily, not as a hard gate).
        if parsed.resets_at is not None:
            self._resets_at = parsed.resets_at

        # Explicit server-side rejection flag → throttle state.
        if parsed.status and parsed.status.lower() == "rejected":
            self._transition(QuotaState.THROTTLED, "status=rejected")
            return self._state

        # Check each window's thresholds. First match wins.
        warning_reason = self._check_thresholds(parsed, now)
        if warning_reason is not None:
            self._transition(QuotaState.WARNING, warning_reason)
            return self._state

        # Otherwise → NORMAL (re-entry from WARNING/THROTTLED allowed
        # once a response came back without threshold trip).
        self._transition(QuotaState.NORMAL, "status=allowed")
        return self._state

    def on_rate_limit_error(
        self,
        headers: dict[str, str] | None,
        *,
        retry_after_s: int | None = None,
    ) -> QuotaState:
        """Ingest a 429 response and update state."""
        parsed = parse_rate_limit_headers(headers)
        effective_retry_after = retry_after_s if retry_after_s is not None else parsed.retry_after_s

        if parsed.overage_status and parsed.overage_status.lower() == "allowed":
            self._overage = True
            self._transition(QuotaState.USING_OVERAGE, "429 but overage allowed")
            return self._state

        if parsed.resets_at is not None:
            self._resets_at = parsed.resets_at

        reason = (
            f"429 received; retry_after={effective_retry_after}s"
            if effective_retry_after
            else "429 received"
        )
        # Distinguish between "transient throttle" (retry-after provided)
        # and "quota exhausted for this window" (no retry-after).
        if effective_retry_after is not None and effective_retry_after > 0:
            self._transition(QuotaState.THROTTLED, reason)
        else:
            self._transition(QuotaState.EXHAUSTED, reason)
        return self._state

    def should_allow_call(self, estimated_tokens: int) -> BudgetDecision:
        """Check whether a call with `estimated_tokens` is allowed under current state."""
        if self._state == QuotaState.EXHAUSTED:
            return BudgetDecision(
                allow=False, reason="quota exhausted", state=self._state,
            )
        if self._state == QuotaState.THROTTLED:
            if estimated_tokens > self._throttle_cap:
                return BudgetDecision(
                    allow=False,
                    reason=f"throttled: estimate {estimated_tokens} > cap {self._throttle_cap}",
                    state=self._state,
                )
            return BudgetDecision(
                allow=True,
                warn=True,
                reason="throttled: call allowed under throttle cap",
                state=self._state,
            )
        if self._state == QuotaState.WARNING:
            if estimated_tokens > self._warn_cap:
                return BudgetDecision(
                    allow=True,
                    warn=True,
                    reason=(
                        f"warning: estimate {estimated_tokens} > cap {self._warn_cap}; "
                        "caller may defer"
                    ),
                    state=self._state,
                )
            return BudgetDecision(
                allow=True, warn=True, reason="warning: call allowed",
                state=self._state,
            )
        if self._state == QuotaState.USING_OVERAGE:
            return BudgetDecision(
                allow=True, warn=True, reason="using overage credits", state=self._state,
            )
        return BudgetDecision(allow=True, reason="normal", state=self._state)

    def reset(self) -> None:
        """Force state back to NORMAL (used by tests or admin override)."""
        self._transition(QuotaState.NORMAL, "manual reset")
        self._overage = False

    # ---------- internal ----------

    def _transition(self, new_state: QuotaState, reason: str) -> None:
        self._state = new_state
        self._last_reason = reason

    def _check_thresholds(self, parsed: RateLimitHeaders, now: float) -> str | None:
        """Return the first matching warning reason, or None."""
        # 5-hour window
        if parsed.util_5h is not None and parsed.resets_at is not None:
            reason = _match_threshold("5h", parsed.util_5h, parsed.resets_at, now, _EARLY_WARNING_CONFIGS["five_hour"])
            if reason:
                return reason
        # 7-day window
        if parsed.util_7d is not None and parsed.resets_at is not None:
            reason = _match_threshold("7d", parsed.util_7d, parsed.resets_at, now, _EARLY_WARNING_CONFIGS["seven_day"])
            if reason:
                return reason
        return None


def _match_threshold(
    window_label: str,
    utilization: float,
    resets_at: int,
    now: float,
    cfg: dict[str, Any],
) -> str | None:
    """If utilization + time-progress cross any threshold, return a reason string."""
    window_s = cfg["window_seconds"]
    elapsed = now - (resets_at - window_s)
    if window_s <= 0:
        return None
    time_progress = max(0.0, min(1.0, elapsed / window_s))
    for util_t, time_t in cfg["thresholds"]:
        if utilization >= util_t and time_progress <= time_t:
            return (
                f"early_warning[{window_label}]: util={utilization:.2f} "
                f">= {util_t}, time_progress={time_progress:.2f} <= {time_t}"
            )
    return None
