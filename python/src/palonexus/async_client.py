# SPDX-License-Identifier: MIT
"""Asynchronous PaloNexus authorization client."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from contextvars import ContextVar
from typing import Literal, Self

from .approvals import (
    ApprovalRecord,
    ApprovalStatus,
    AsyncApprovalTransport,
)
from .client import (
    AuthorizationDecision,
    _attempt_parts,
    _AuthorizationAttempt,
    _bind_approval,
    _poll_parameters,
    _public_decision,
    _require_allow,
    _require_resumable,
    _safe_request_identifiers,
)
from .errors import AuthorizationUnavailable, InvalidDecision, InvalidRequest
from .models import ActionRequest, DecisionOutcome
from .protocol import ActionRequestBuilder, _PreparedAction
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
        "_approval_transport",
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
        approval_transport: AsyncApprovalTransport | None = None,
        owns_transport: bool = False,
    ) -> None:
        if not isinstance(transport, AsyncAuthorizationTransport):
            raise InvalidRequest() from None
        if type(owns_transport) is not bool:
            raise InvalidRequest() from None
        if approval_transport is not None and not isinstance(
            approval_transport, AsyncApprovalTransport
        ):
            raise InvalidRequest() from None
        self._transport = transport
        self._approval_transport = approval_transport
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

    def _approvals(self) -> AsyncApprovalTransport:
        if self._approval_transport is None:
            raise AuthorizationUnavailable() from None
        return self._approval_transport

    async def request_approval(
        self,
        attempt: _AuthorizationAttempt,
        decision: AuthorizationDecision,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ApprovalRecord:
        """Create or return the approval bound to one immutable attempt."""

        request, scope_hash = _attempt_parts(attempt)
        if (
            type(decision) is not AuthorizationDecision
            or decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED
            or decision.approval_id is None
            or decision.request_id != str(request.request_id)
            or decision.correlation_id != str(request.correlation_id)
            or decision.client_scope_hash != scope_hash
        ):
            from .errors import ApprovalScopeMismatch

            raise ApprovalScopeMismatch(
                request_id=request.request_id,
                decision_id=getattr(decision, "decision_id", None),
                correlation_id=request.correlation_id,
            ) from None
        await self._begin_operation(request)
        token = _ACTIVE_CLIENTS.set(_ACTIVE_CLIENTS.get() | {id(self)})
        try:
            record = ApprovalRecord._from_protocol(
                await self._approvals().request_approval(
                    request,
                    decision_id=decision.decision_id,
                    authoritative_scope_hash=decision.authoritative_scope_hash,
                    approval_id=decision.approval_id,
                    deadline=deadline,
                    cancelled=cancelled,
                )
            )
            _bind_approval(record, request=request, decision=decision)
            return record
        finally:
            _ACTIVE_CLIENTS.reset(token)
            await self._end_operation()

    async def get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ApprovalRecord:
        """Read one validated approval record."""

        from ._generated import protocol as _wire

        try:
            checked_id = str(_wire.ApprovalID(approval_id))
        except (TypeError, ValueError):
            raise InvalidRequest() from None
        await self._begin_operation(None)
        token = _ACTIVE_CLIENTS.set(_ACTIVE_CLIENTS.get() | {id(self)})
        try:
            record = ApprovalRecord._from_protocol(
                await self._approvals().get_approval(
                    checked_id,
                    deadline=deadline,
                    cancelled=cancelled,
                )
            )
            if record.approval_id != checked_id:
                raise InvalidDecision() from None
            return record
        finally:
            _ACTIVE_CLIENTS.reset(token)
            await self._end_operation()

    async def wait_for_approval(
        self,
        approval_id: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool] | None = None,
        poll_interval: float = 0.25,
    ) -> ApprovalRecord:
        """Poll without busy-looping until a terminal approval or deadline."""

        checked_deadline, checked_interval = _poll_parameters(deadline, poll_interval)
        while True:
            if cancelled is not None and cancelled():
                raise asyncio.CancelledError
            now = time.monotonic()
            if now >= checked_deadline:
                raise AuthorizationUnavailable() from None
            record = await self.get_approval(
                approval_id,
                deadline=checked_deadline,
                cancelled=cancelled,
            )
            if record.status is not ApprovalStatus.PENDING:
                return record
            remaining = checked_deadline - time.monotonic()
            if remaining <= 0:
                raise AuthorizationUnavailable() from None
            await asyncio.sleep(min(checked_interval, remaining))

    async def resume(
        self,
        builder: ActionRequestBuilder,
        original: _PreparedAction,
        current: ActionRequest,
        prior_decision: AuthorizationDecision,
        approval: ApprovalRecord,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _PreparedAction:
        """Reauthorize a sealed resume candidate, then transfer execution."""

        _require_resumable(original, prior_decision, approval)
        candidate: _PreparedAction | None = None
        committed = False
        try:
            candidate = builder._prepare_resume(  # noqa: SLF001
                original,
                current,
                prior_decision_id=prior_decision.decision_id,
                approval_id=approval.approval_id,
            )
            fresh_decision = await self.authorize(
                candidate,
                deadline=deadline,
                cancelled=cancelled,
            )
            if (
                fresh_decision.authoritative_scope_hash
                != approval.authoritative_scope_hash
            ):
                from .errors import ApprovalScopeMismatch

                raise ApprovalScopeMismatch(
                    request_id=fresh_decision.request_id,
                    decision_id=fresh_decision.decision_id,
                    correlation_id=fresh_decision.correlation_id,
                ) from None
            builder._commit_resume(original, candidate)  # noqa: SLF001
            committed = True
            return candidate
        finally:
            if candidate is not None and not committed:
                try:
                    candidate.close()
                except BaseException:
                    pass

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
