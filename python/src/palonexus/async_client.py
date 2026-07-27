# SPDX-License-Identifier: MIT
"""Asynchronous PaloNexus authorization client."""

from __future__ import annotations

import threading
from collections.abc import Callable
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


class AsyncAuthorizationClient:
    """Async client with behavior equivalent to :class:`AuthorizationClient`."""

    __slots__ = ("_closed", "_lock", "_owns_transport", "_transport")

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
        self._closed = False
        self._lock = threading.RLock()

    def _ensure_open(self, request: object | None = None) -> None:
        with self._lock:
            if not self._closed:
                return
        request_id, correlation_id = _safe_request_identifiers(request)
        raise AuthorizationUnavailable(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None

    async def decide(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Obtain a decision without executing the proposed application work."""

        request, scope_hash = _attempt_parts(attempt)
        self._ensure_open(request)
        value = await self._transport.decide(
            request,
            client_scope_hash=scope_hash,
            deadline=deadline,
            cancelled=cancelled,
        )
        return _public_decision(value, request=request)

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

    async def aclose(self) -> None:
        """Close this client and, when owned, its transport exactly once."""

        should_close = False
        with self._lock:
            if not self._closed:
                self._closed = True
                should_close = self._owns_transport
        if should_close:
            await self._transport.aclose()

    async def __aenter__(self) -> Self:
        self._ensure_open()
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
