# SPDX-License-Identifier: MIT
"""Regressions from the independent Task 8 security review."""

from __future__ import annotations

import ipaddress
import ssl
from typing import Any

import pytest
from palonexus.identity import OIDCVerificationFailed, OIDCVerifierConfig
from palonexus.identity.oidc import PinnedHTTPSMetadataFetcher


def test_public_address_validation_rejects_mixed_and_mapped_results() -> None:
    for addresses in (
        ("93.184.216.34", "127.0.0.1"),
        ("93.184.216.34", "::ffff:127.0.0.1"),
        ("fc00::1",),
        ("169.254.1.1",),
        ("224.0.0.1",),
        ("0.0.0.0",),
    ):
        with pytest.raises(OIDCVerificationFailed):
            PinnedHTTPSMetadataFetcher.validate_resolved_addresses(addresses)

    approved = PinnedHTTPSMetadataFetcher.validate_resolved_addresses(
        ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
    )
    assert all(ipaddress.ip_address(item).is_global for item in approved)


def test_peer_must_be_one_of_the_pinned_addresses() -> None:
    with pytest.raises(OIDCVerificationFailed):
        PinnedHTTPSMetadataFetcher.validate_connected_peer(
            "127.0.0.1",
            ("93.184.216.34",),
        )


def test_config_has_explicit_client_typ_kid_and_refresh_policies() -> None:
    config = OIDCVerifierConfig(
        issuer="https://issuer.example",
        audiences=("resource-api",),
        client_id="oidc-client",
        algorithms=("RS256",),
        require_typ=False,
        allowed_types=("JWT", "at+jwt"),
        allow_missing_kid=True,
        refresh_cooldown_seconds=30,
        failure_backoff_seconds=5,
    )
    assert config.client_id == "oidc-client"
    assert config.require_typ is False
    assert config.allow_missing_kid is True


def test_dns_is_resolved_for_each_fetch_and_rebinding_fails_closed() -> None:
    answers = iter(("93.184.216.34", "127.0.0.1"))

    def resolver(*_: object) -> list[tuple[object, ...]]:
        address = next(answers)
        return [(2, 1, 6, "canonical.example", (address, 443))]

    class Response:
        status = 200

        def __init__(self) -> None:
            self._body = b"{}"

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Content-Type", "application/json"), ("Content-Length", "2")]

        def getheader(self, name: str, default: str | None = None) -> str | None:
            values = dict(self.getheaders())
            return values.get(name, default)

        def read(self, amount: int) -> bytes:
            result, self._body = self._body[:amount], self._body[amount:]
            return result

    class Connection:
        def request(self, *_: object, **__: object) -> None:
            return None

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            return None

    def connection_factory(*_: object, **__: object) -> Any:
        return Connection()

    context = ssl.create_default_context()
    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=1,
        resolver=resolver,
        ssl_context=context,
        connection_factory=connection_factory,
        testing_only=True,
    )
    assert fetcher.fetch_json("https://issuer.example/discovery", 1024) == {}
    with pytest.raises(OIDCVerificationFailed):
        fetcher.fetch_json("https://issuer.example/discovery", 1024)
    fetcher.close()
