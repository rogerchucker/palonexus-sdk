# SPDX-License-Identifier: MIT
"""Optional framework integrations.

Framework dependencies are imported only when their integration is requested,
so the base ``palonexus`` package remains usable without optional extras.
"""

from __future__ import annotations

from typing import Any

from ..errors import InvalidRequest


class MissingIntegrationDependency(InvalidRequest):
    """The selected optional framework integration is not installed."""

    canonical_message = (
        "The LangChain integration requires the 'palonexus[langchain]' extra."
    )


_LANGCHAIN_EXPORTS = frozenset(
    {
        "AsyncAuthorizationClientProtocol",
        "LangChainActionPolicy",
        "LangChainApprovalRequired",
        "LangChainAuthorizationContext",
        "LangChainAuthorizationUnavailable",
        "LangChainInvalidRequest",
        "LangChainPolicyDenied",
        "MissingIntegrationDependency",
        "PaloNexusLangChainMiddleware",
        "SyncAuthorizationClientProtocol",
    }
)


def __getattr__(name: str) -> Any:
    if name not in _LANGCHAIN_EXPORTS:
        raise AttributeError(name)
    if name == "MissingIntegrationDependency":
        return MissingIntegrationDependency
    from . import langchain

    return getattr(langchain, name)


def __dir__() -> list[str]:
    return sorted(_LANGCHAIN_EXPORTS)


__all__ = sorted(_LANGCHAIN_EXPORTS)
