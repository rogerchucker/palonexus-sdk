# SPDX-License-Identifier: MIT
"""Bounded retry policy for authorization transport operations only."""

from __future__ import annotations

import asyncio
import math
import operator
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any, Self, cast

from ._generated import protocol as _protocol


class RetryPolicyError(ValueError):
    """A stable, secret-free invalid retry policy error."""

    code = "invalid_retry_policy"

    def __str__(self) -> str:
        return "invalid retry policy"

    def __repr__(self) -> str:
        return "RetryPolicyError(code='invalid_retry_policy')"


_NORMALIZATION_FAILED = object()


def _raise_retry_policy_error() -> None:
    raise RetryPolicyError() from None


def _normalize_index(raw_value: object) -> Any:
    failed = False
    try:
        if isinstance(raw_value, bool):
            raise ValueError
        normalized = operator.index(raw_value)  # type: ignore[arg-type]
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        raise
    except BaseException:
        del raw_value
        failed = True
    if failed:
        return _NORMALIZATION_FAILED
    return normalized


def _normalize_float(raw_value: object) -> Any:
    failed = False
    try:
        if isinstance(raw_value, bool):
            raise ValueError
        normalized = float(raw_value)  # type: ignore[arg-type]
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        raise
    except BaseException:
        del raw_value
        failed = True
    if failed:
        return _NORMALIZATION_FAILED
    return normalized


def _random_value(random_source: Callable[[], float]) -> Any:
    failed = False
    try:
        raw_value = random_source()
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        raise
    except BaseException:
        failed = True
    if failed:
        return _NORMALIZATION_FAILED
    normalized = _normalize_float(raw_value)
    del raw_value
    return normalized


class RetryFailure(StrEnum):
    """Safe failure classifications accepted by ``RetryPolicy``."""

    CONNECTION = "connection"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    DENIED = "denied"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    PERMANENT = "permanent"


class CompletionState(StrEnum):
    """Whether work outside authorization might already have executed."""

    NOT_EXECUTED = "not_executed"
    AUTHORIZATION_AMBIGUOUS = "authorization_ambiguous"
    APPLICATION_AMBIGUOUS = "application_ambiguous"


class RetryReason(StrEnum):
    """Stable, secret-free reason for a retry decision."""

    RETRY_SCHEDULED = "retry_scheduled"
    NON_RETRYABLE = "non_retryable"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    ELAPSED_EXHAUSTED = "elapsed_exhausted"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CANCELLED = "cancelled"
    IDEMPOTENCY_REQUIRED = "idempotency_required"
    APPLICATION_AMBIGUOUS = "application_ambiguous"
    INVALID_INPUT = "invalid_input"
    INVALID_RANDOMNESS = "invalid_randomness"


@dataclass(frozen=True, slots=True)
class RetryDecision:
    """Immutable authorization retry instruction."""

    should_retry: bool
    delay: float | None
    reason: RetryReason

    def __post_init__(self) -> None:
        valid_retry = (
            self.should_retry
            and self.reason is RetryReason.RETRY_SCHEDULED
            and isinstance(self.delay, float)
            and math.isfinite(self.delay)
            and self.delay >= 0
        )
        valid_stop = (
            not self.should_retry
            and self.delay is None
            and self.reason is not RetryReason.RETRY_SCHEDULED
        )
        if not (valid_retry or valid_stop):
            raise ValueError("invalid retry decision")


_RETRYABLE_FAILURES = frozenset(
    {
        RetryFailure.CONNECTION,
        RetryFailure.TIMEOUT,
        RetryFailure.UNAVAILABLE,
        RetryFailure.RATE_LIMITED,
    }
)
_SIDE_EFFECTS = frozenset({"read_only", "write", "destructive", "external"})


def _stop(reason: RetryReason) -> RetryDecision:
    return RetryDecision(should_retry=False, delay=None, reason=reason)


class RetryPolicy:
    """Compute bounded retries for decision-service transport calls.

    This policy never runs application work.  An ambiguous authorization
    response can be retried with the same request identity; any ambiguity after
    application execution is a terminal fail-closed result.
    """

    __slots__ = (
        "_initial_delay",
        "_jitter_fraction",
        "_max_attempts",
        "_max_delay",
        "_max_elapsed",
        "_max_retry_after",
        "_multiplier",
        "_random_source",
    )

    _max_attempts: int
    _max_elapsed: float
    _initial_delay: float
    _max_delay: float
    _multiplier: float
    _jitter_fraction: float
    _max_retry_after: float
    _random_source: Callable[[], float]

    def __init__(
        self,
        *,
        max_attempts: int = 3,
        max_elapsed: float = 10.0,
        initial_delay: float = 0.1,
        max_delay: float = 2.0,
        multiplier: float = 2.0,
        jitter_fraction: float = 0.2,
        max_retry_after: float = 5.0,
    ) -> None:
        initialized = self._initialize(
            max_attempts=max_attempts,
            max_elapsed=max_elapsed,
            initial_delay=initial_delay,
            max_delay=max_delay,
            multiplier=multiplier,
            jitter_fraction=jitter_fraction,
            max_retry_after=max_retry_after,
            random_source=secrets.SystemRandom().random,
        )
        if not initialized:
            del (
                max_attempts,
                max_elapsed,
                initial_delay,
                max_delay,
                multiplier,
                jitter_fraction,
                max_retry_after,
            )
            _raise_retry_policy_error()

    def _initialize(
        self,
        *,
        max_attempts: int,
        max_elapsed: float,
        initial_delay: float,
        max_delay: float,
        multiplier: float,
        jitter_fraction: float,
        max_retry_after: float,
        random_source: Callable[[], float],
    ) -> bool:
        normalized_attempts = _normalize_index(max_attempts)
        normalized_elapsed = _normalize_float(max_elapsed)
        normalized_initial = _normalize_float(initial_delay)
        normalized_max_delay = _normalize_float(max_delay)
        normalized_multiplier = _normalize_float(multiplier)
        normalized_jitter = _normalize_float(jitter_fraction)
        normalized_retry_after = _normalize_float(max_retry_after)
        normalized_numeric = (
            normalized_elapsed,
            normalized_initial,
            normalized_max_delay,
            normalized_multiplier,
            normalized_jitter,
            normalized_retry_after,
        )
        failed = normalized_attempts is _NORMALIZATION_FAILED or any(
            value is _NORMALIZATION_FAILED for value in normalized_numeric
        )
        if not failed:
            failed = (
                not all(math.isfinite(value) for value in normalized_numeric)
                or normalized_attempts < 1
                or normalized_attempts > 100
                or normalized_elapsed <= 0
                or normalized_initial < 0
                or normalized_max_delay <= 0
                or normalized_initial > normalized_max_delay
                or normalized_multiplier < 1
                or not 0 <= normalized_jitter <= 1
                or normalized_retry_after < 0
                or not callable(random_source)
            )
        if failed:
            del (
                max_attempts,
                max_elapsed,
                initial_delay,
                max_delay,
                multiplier,
                jitter_fraction,
                max_retry_after,
                random_source,
            )
            return False

        object.__setattr__(self, "_max_attempts", normalized_attempts)
        object.__setattr__(self, "_max_elapsed", normalized_elapsed)
        object.__setattr__(self, "_initial_delay", normalized_initial)
        object.__setattr__(self, "_max_delay", normalized_max_delay)
        object.__setattr__(self, "_multiplier", normalized_multiplier)
        object.__setattr__(self, "_jitter_fraction", normalized_jitter)
        object.__setattr__(self, "_max_retry_after", normalized_retry_after)
        object.__setattr__(self, "_random_source", random_source)
        return True

    @classmethod
    def _for_testing(
        cls,
        *,
        random_source: Callable[[], float],
        max_attempts: int = 3,
        max_elapsed: float = 10.0,
        initial_delay: float = 0.1,
        max_delay: float = 2.0,
        multiplier: float = 2.0,
        jitter_fraction: float = 0.2,
        max_retry_after: float = 5.0,
    ) -> Self:
        """Construct with deterministic randomness for private tests only."""

        instance = cls.__new__(cls)
        initialized = instance._initialize(
            max_attempts=max_attempts,
            max_elapsed=max_elapsed,
            initial_delay=initial_delay,
            max_delay=max_delay,
            multiplier=multiplier,
            jitter_fraction=jitter_fraction,
            max_retry_after=max_retry_after,
            random_source=random_source,
        )
        if not initialized:
            del (
                random_source,
                max_attempts,
                max_elapsed,
                initial_delay,
                max_delay,
                multiplier,
                jitter_fraction,
                max_retry_after,
            )
            _raise_retry_policy_error()
        return instance

    def _backoff(self, attempt: int) -> float | None:
        try:
            exponent = min(attempt - 1, 1024)
            base = min(
                self._max_delay,
                self._initial_delay * (self._multiplier**exponent),
            )
            random_value = _random_value(self._random_source)
            if random_value is _NORMALIZATION_FAILED:
                return None
            random_value = cast(float, random_value)
            if not math.isfinite(random_value) or not 0 <= random_value <= 1:
                return None
            factor = 1 + ((2 * random_value - 1) * self._jitter_fraction)
            return max(0.0, min(self._max_delay, base * factor))
        except Exception:
            return None

    def _retry_after(
        self,
        value: str | None,
        *,
        now: datetime | None,
    ) -> float | None:
        if value is None or type(value) is not str:
            return None
        if (
            not value
            or len(value) > 128
            or value != value.strip()
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
        ):
            return None
        if value.isascii() and value.isdecimal():
            # Avoid converting an attacker-controlled giant integer.
            if len(value) > 12:
                return self._max_retry_after
            try:
                return min(float(int(value, 10)), self._max_retry_after)
            except (OverflowError, ValueError):
                return None

        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                return None
            current = datetime.now(UTC) if now is None else now
            if type(current) is not datetime or current.tzinfo is None:
                return None
            seconds = (parsed.astimezone(UTC) - current.astimezone(UTC)).total_seconds()
            if not math.isfinite(seconds):
                return None
            return min(max(0.0, seconds), self._max_retry_after)
        except Exception:
            return None

    def authorization_retry(
        self,
        *,
        attempt: int,
        elapsed: float,
        side_effect: str,
        failure: RetryFailure,
        completion: CompletionState | None = None,
        authorization_idempotency_key: str | None = None,
        retry_after: str | None = None,
        now: datetime | None = None,
        cancelled: bool = False,
        deadline_remaining: float | None = None,
    ) -> RetryDecision:
        """Return whether the *authorization transport* may retry.

        ``attempt`` is the one-based attempt that just failed.  This method
        never schedules or invokes the proposed application action.
        """

        normalized_attempt = _normalize_index(attempt)
        normalized_elapsed = _normalize_float(elapsed)
        normalized_deadline = (
            None if deadline_remaining is None else _normalize_float(deadline_remaining)
        )
        normalization_failed = (
            normalized_attempt is _NORMALIZATION_FAILED
            or normalized_elapsed is _NORMALIZATION_FAILED
            or normalized_deadline is _NORMALIZATION_FAILED
        )
        if normalization_failed:
            del (
                attempt,
                elapsed,
                side_effect,
                failure,
                completion,
                authorization_idempotency_key,
                retry_after,
                now,
                cancelled,
                deadline_remaining,
            )
            _raise_retry_policy_error()
        valid_input = (
            normalized_attempt >= 1
            and math.isfinite(normalized_elapsed)
            and normalized_elapsed >= 0
            and type(side_effect) is str
            and side_effect in _SIDE_EFFECTS
            and isinstance(failure, RetryFailure)
            and (completion is None or isinstance(completion, CompletionState))
            and isinstance(cancelled, bool)
        )
        if normalized_deadline is not None:
            valid_input = (
                valid_input
                and not isinstance(deadline_remaining, bool)
                and math.isfinite(normalized_deadline)
            )
        if not valid_input:
            return _stop(RetryReason.INVALID_INPUT)

        if cancelled:
            return _stop(RetryReason.CANCELLED)
        if completion is None:
            if side_effect != "read_only":
                return _stop(RetryReason.APPLICATION_AMBIGUOUS)
            completion = CompletionState.NOT_EXECUTED
        if completion is CompletionState.APPLICATION_AMBIGUOUS:
            return _stop(RetryReason.APPLICATION_AMBIGUOUS)
        if failure not in _RETRYABLE_FAILURES:
            return _stop(RetryReason.NON_RETRYABLE)
        if normalized_attempt >= self._max_attempts:
            return _stop(RetryReason.ATTEMPTS_EXHAUSTED)

        if side_effect != "read_only":
            valid_key = False
            if type(authorization_idempotency_key) is str:
                try:
                    _protocol.AuthorizationIdempotencyKey(authorization_idempotency_key)
                    valid_key = True
                except Exception:
                    pass
            if not valid_key:
                return _stop(RetryReason.IDEMPOTENCY_REQUIRED)

        delay = self._retry_after(retry_after, now=now)
        if delay is None:
            delay = self._backoff(normalized_attempt)
            if delay is None:
                return _stop(RetryReason.INVALID_RANDOMNESS)

        try:
            remaining_elapsed = self._max_elapsed - normalized_elapsed
            valid_delay = math.isfinite(delay) and delay >= 0
        except Exception:
            return _stop(RetryReason.INVALID_INPUT)
        if not valid_delay:
            return _stop(RetryReason.INVALID_RANDOMNESS)
        if remaining_elapsed <= 0 or delay >= remaining_elapsed:
            return _stop(RetryReason.ELAPSED_EXHAUSTED)
        if normalized_deadline is not None:
            if normalized_deadline <= 0 or delay >= normalized_deadline:
                return _stop(RetryReason.DEADLINE_EXCEEDED)

        return RetryDecision(
            should_retry=True,
            delay=float(delay),
            reason=RetryReason.RETRY_SCHEDULED,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("RetryPolicy is immutable.")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("RetryPolicy is immutable.")

    def __repr__(self) -> str:
        return (
            "RetryPolicy("
            f"max_attempts={self._max_attempts}, "
            f"max_elapsed={self._max_elapsed}, "
            f"initial_delay={self._initial_delay}, "
            f"max_delay={self._max_delay})"
        )


__all__ = [
    "CompletionState",
    "RetryDecision",
    "RetryFailure",
    "RetryPolicy",
    "RetryPolicyError",
    "RetryReason",
]
