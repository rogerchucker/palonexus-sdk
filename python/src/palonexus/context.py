# SPDX-License-Identifier: MIT
"""Task-local context and cryptographically seeded protocol identifiers."""

from __future__ import annotations

import contextvars
import os
import secrets
import threading
import time
from types import TracebackType
from typing import Final, Literal

from .errors import ModelValidationError
from .models import TaskContext

_CROCKFORD32: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_TIMESTAMP: Final = (1 << 48) - 1
_MAX_RANDOMNESS: Final = (1 << 80) - 1
_PREFIXES: Final = {
    "action": "act_",
    "request": "req_",
    "correlation": "corr_",
    "idempotency": "authz_",
    "task": "task_",
    "session": "session_",
    "causation": "cause_",
}


def _encode_ulid(value: int) -> str:
    encoded = ["0"] * 26
    for index in range(25, -1, -1):
        encoded[index] = _CROCKFORD32[value & 31]
        value >>= 5
    return "".join(encoded)


class _MonotonicIdentifierGenerator:
    """PID-aware monotonic ULIDs with a fresh CSPRNG seed after fork."""

    __slots__ = (
        "_last_randomness",
        "_last_timestamp",
        "_lock",
        "_pid",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pid = os.getpid()
        self._last_timestamp = -1
        self._last_randomness = -1
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork_child)

    def _after_fork_child(self) -> None:
        # A lock may have been held by a vanished thread at fork.
        self._lock = threading.Lock()
        self._pid = os.getpid()
        self._last_timestamp = -1
        self._last_randomness = -1

    def _reset_if_forked(self) -> None:
        if os.getpid() != self._pid:
            self._after_fork_child()

    def new(self, kind: str) -> str:
        try:
            prefix = _PREFIXES[kind]
        except KeyError as exc:
            raise ValueError("unsupported identifier kind") from exc

        self._reset_if_forked()
        with self._lock:
            timestamp = time.time_ns() // 1_000_000
            if (
                not isinstance(timestamp, int)
                or isinstance(timestamp, bool)
                or timestamp < 0
                or timestamp > _MAX_TIMESTAMP
            ):
                raise RuntimeError("identifier clock is outside the ULID range")

            if timestamp > self._last_timestamp:
                try:
                    random_bytes = secrets.token_bytes(10)
                except Exception:
                    raise RuntimeError("identifier entropy is unavailable") from None
                if not isinstance(random_bytes, bytes) or len(random_bytes) != 10:
                    raise RuntimeError(
                        "identifier entropy source returned invalid bytes"
                    )
                randomness = int.from_bytes(random_bytes, "big")
            else:
                timestamp = self._last_timestamp
                randomness = self._last_randomness + 1
                if randomness > _MAX_RANDOMNESS:
                    if timestamp == _MAX_TIMESTAMP:
                        raise RuntimeError("identifier space exhausted")
                    timestamp += 1
                    randomness = 0

            self._last_timestamp = timestamp
            self._last_randomness = randomness
            return f"{prefix}{_encode_ulid((timestamp << 80) | randomness)}"


_IDENTIFIERS: Final = _MonotonicIdentifierGenerator()
_CURRENT_TASK: contextvars.ContextVar[TaskContext | None] = contextvars.ContextVar(
    "palonexus_task_context",
    default=None,
)


def _new_identifier(
    kind: str,
) -> str:
    return _IDENTIFIERS.new(kind)


def current_task() -> TaskContext | None:
    """Return the task bound to the current execution context, if any."""

    return _CURRENT_TASK.get()


def _context_value(
    context: TaskContext | None,
    *,
    task_id: str | None,
    session_id: str | None,
) -> TaskContext:
    if context is not None:
        if task_id is not None or session_id is not None:
            raise ModelValidationError()
        checked = TaskContext.model_validate(
            {
                "task_id": context.task_id,
                "session_id": context.session_id,
            }
        )
        if checked != context:
            raise ModelValidationError()
        return context
    return TaskContext(
        task_id=(task_id if task_id is not None else _new_identifier("task")),
        session_id=(
            session_id if session_id is not None else _new_identifier("session")
        ),
    )


class _TaskScope:
    __slots__ = ("_active", "_context", "_entered", "_token")

    def __init__(self, context: TaskContext) -> None:
        self._context = context
        self._token: contextvars.Token[TaskContext | None] | None = None
        self._entered = False
        self._active = False

    def __enter__(self) -> TaskContext:
        if self._entered:
            raise RuntimeError("task scope cannot be re-entered")
        self._entered = True
        self._token = _CURRENT_TASK.set(self._context)
        self._active = True
        return self._context

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if not self._active or self._token is None:
            raise RuntimeError("task scope is not active")
        # Reset first. A cross-context ValueError leaves this scope active so
        # its owner can still close it and restore the binding.
        _CURRENT_TASK.reset(self._token)
        self._active = False
        return False


class _AsyncTaskScope:
    __slots__ = ("_scope",)

    def __init__(self, context: TaskContext) -> None:
        self._scope = _TaskScope(context)

    async def __aenter__(self) -> TaskContext:
        return self._scope.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        return self._scope.__exit__(exc_type, exc_value, traceback)


def task(
    context: TaskContext | None = None,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
) -> _TaskScope:
    """Return a synchronous task-local binding scope.

    A scope must be entered and exited in the same ``contextvars.Context`` and
    must not span a generator ``yield``. Python retains context-variable
    bindings while a generator is suspended; use an explicit ``task_context``
    when building from generator-driven code.
    """

    return _TaskScope(_context_value(context, task_id=task_id, session_id=session_id))


def atask(
    context: TaskContext | None = None,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
) -> _AsyncTaskScope:
    """Return an asynchronous task-local binding scope."""

    return _AsyncTaskScope(
        _context_value(context, task_id=task_id, session_id=session_id)
    )


__all__ = ["TaskContext", "atask", "current_task", "task"]
