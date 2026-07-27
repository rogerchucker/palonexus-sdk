# SPDX-License-Identifier: MIT
"""Stable transport boundaries for PaloNexus authorization attempts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from .._generated import protocol as _protocol


@runtime_checkable
class AuthorizationTransport(Protocol):
    """Synchronous transport for one authorization attempt.

    A transport sends protocol data and returns protocol data. It never invokes
    the proposed application action.
    """

    def decide(
        self,
        request: _protocol.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _protocol.AuthorizationDecision:
        """Obtain a decision bound to ``request`` and its canonical scope."""

    def close(self) -> None:
        """Release transport resources. Repeated calls are harmless."""


@runtime_checkable
class AsyncAuthorizationTransport(Protocol):
    """Asynchronous transport equivalent of ``AuthorizationTransport``."""

    async def decide(
        self,
        request: _protocol.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _protocol.AuthorizationDecision:
        """Obtain a decision bound to ``request`` and its canonical scope."""

    async def aclose(self) -> None:
        """Release transport resources. Repeated calls are harmless."""


__all__ = ["AsyncAuthorizationTransport", "AuthorizationTransport"]
