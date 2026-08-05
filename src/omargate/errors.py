from __future__ import annotations

from .constants import ExitCode


class OmarGateError(Exception):
    """Base exception for all Omar Gate errors."""

    exit_code: ExitCode = ExitCode.ERROR


class ConfigError(OmarGateError):
    """Configuration validation failed."""

    exit_code = ExitCode.ERROR


class PreflightError(OmarGateError):
    """Preflight check failed (not an error, expected skip)."""

    exit_code = ExitCode.SKIPPED


class DedupeSkip(PreflightError):
    """Run skipped due to dedupe."""


class RateLimitSkip(PreflightError):
    """Run skipped due to rate limit."""


class ForkBlockedSkip(PreflightError):
    """Run blocked due to fork policy."""


class GateBlockedError(OmarGateError):
    """Gate blocked merge (this is success, not error)."""

    exit_code = ExitCode.BLOCKED


class EvidenceIntegrityError(OmarGateError):
    """Evidence bundle corrupted — fail closed."""

    exit_code = ExitCode.BLOCKED


class DeterministicAnalysisBudgetExceeded(EvidenceIntegrityError):
    """A deterministic scanner exhausted a non-configurable safety budget."""

    def __init__(
        self,
        *,
        path: str,
        budget_kind: str,
        limit: int,
        observed_at_least: int,
    ) -> None:
        self.path = path
        self.budget_kind = budget_kind
        self.limit = limit
        self.observed_at_least = observed_at_least
        super().__init__(
            "Deterministic analysis budget exceeded "
            f"for {path}: {budget_kind} limit {limit}, "
            f"observed at least {observed_at_least}"
        )
