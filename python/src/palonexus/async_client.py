# SPDX-License-Identifier: MIT
"""Asynchronous PaloNexus authorization client."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextvars import ContextVar
from typing import Literal, Self

from .client import (
    AuthorizationDecision,
    _attempt_parts,
    _AuthorizationAttempt,
    _public_decision,
    _require_allow,
    _safe_request_identifiers,
)
from .errors import AuthorizationUnavailable, InvalidRequest
from .transports import AsyncAuthorizationTransport

_ACTIVE_CLIENTS: ContextVar[frozenset[int]] = ContextVar(
    "palonexus_active_async_clients",
    default=frozenset(),
)


def _consume_close_task_exception(task: asyncio.Task[None]) -> None:
    """Retrieve background failure while preserving it for future awaiters."""

    try:
        task.exception()
    except BaseException:
        pass


class AsyncAuthorizationClient:
    """Async client with behavior equivalent to :class:`AuthorizationClient`.

    Close runs in one shielded task. Caller cancellation does not cancel shared
    cleanup, and an ambiguous transport-close failure is safely remembered
    rather than retried.
    """

    __slots__ = (
        "_active",
        "_close_failure",
        "_close_task",
        "_condition",
        "_owns_transport",
        "_state",
        "_transport",
    )

    def __init__(
        self,
        transport: AsyncAuthorizationTransport,
        *,
        owns_transport: bool = False,
    ) -> None:
        if not isinstance(transport, AsyncAuthorizationTransport):
            raise InvalidRequest() from None
        if type(owns_transport) is not bool:
            raise InvalidRequest() from None
        self._transport = transport
        self._owns_transport = owns_transport
        self._state = "OPEN"
        self._active = 0
        self._close_failure: AuthorizationUnavailable | None = None
        self._condition = asyncio.Condition()
        self._close_task: asyncio.Task[None] | None = None

    async def _ensure_open(self, request: object | None = None) -> None:
        async with self._condition:
            if self._state == "OPEN":
                return
        request_id, correlation_id = _safe_request_identifiers(request)
        raise AuthorizationUnavailable(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None

    async def _begin_operation(self, request: object) -> None:
        async with self._condition:
            if self._state != "OPEN":
                request_id, correlation_id = _safe_request_identifiers(request)
                raise AuthorizationUnavailable(
                    request_id=request_id,
                    correlation_id=correlation_id,
                ) from None
            self._active += 1

    async def _end_operation(self) -> None:
        async with self._condition:
            self._active -= 1
            if self._active == 0:
                self._condition.notify_all()

    async def decide(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Obtain a decision without executing the proposed application work."""

        request, scope_hash = _attempt_parts(attempt)
        await self._begin_operation(request)
        token = _ACTIVE_CLIENTS.set(_ACTIVE_CLIENTS.get() | {id(self)})
        try:
            value = await self._transport.decide(
                request,
                client_scope_hash=scope_hash,
                deadline=deadline,
                cancelled=cancelled,
            )
            return _public_decision(
                value,
                request=request,
                client_scope_hash=scope_hash,
            )
        finally:
            _ACTIVE_CLIENTS.reset(token)
            await self._end_operation()

    async def authorize(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Return only an allow; deny and approval outcomes raise typed errors."""

        return _require_allow(
            await self.decide(
                attempt,
                deadline=deadline,
                cancelled=cancelled,
            )
        )

    async def _finish_close(self) -> None:
        async with self._condition:
            while self._active:
                await self._condition.wait()
        failure: AuthorizationUnavailable | None = None
        if self._owns_transport:
            try:
                await self._transport.aclose()
            except BaseException:
                failure = AuthorizationUnavailable()
        async with self._condition:
            self._close_failure = failure
            self._state = "CLOSED"
            self._condition.notify_all()
        if failure is not None:
            raise failure from None

    async def aclose(self) -> None:
        """Wait for active calls, then close an owned transport exactly once."""

        if id(self) in _ACTIVE_CLIENTS.get():
            raise AuthorizationUnavailable() from None
        async with self._condition:
            if self._state == "OPEN":
                self._state = "CLOSING"
                self._close_task = asyncio.create_task(self._finish_close())
                self._close_task.add_done_callback(_consume_close_task_exception)
            task = self._close_task
            if task is None:
                if self._close_failure is not None:
                    raise self._close_failure from None
                return
            if task is asyncio.current_task():
                return
        await asyncio.shield(task)

    async def __aenter__(self) -> Self:
        await self._ensure_open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> Literal[False]:
        await self.aclose()
        return False


__all__ = ["AsyncAuthorizationClient"]
