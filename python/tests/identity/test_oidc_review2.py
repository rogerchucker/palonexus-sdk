# SPDX-License-Identifier: MIT
"""Second independent-review regressions for OIDC."""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from palonexus.identity import OIDCVerificationFailed, OIDCVerifierConfig
from palonexus.identity.oidc import (
    PinnedHTTPSMetadataFetcher,
    _PinnedHTTPSConnection,
)


def _records(*addresses: str) -> list[tuple[object, ...]]:
    return [(2, 1, 6, "canonical.example", (address, 443)) for address in addresses]


class _Response:
    status = 200

    def __init__(self, *, delay: float = 0.0) -> None:
        self._body = b"{}"
        self._delay = delay

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json"), ("Content-Length", "2")]

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return dict(self.getheaders()).get(name, default)

    def read(self, amount: int) -> bytes:
        if self._delay:
            time.sleep(self._delay)
        result, self._body = self._body[:amount], self._body[amount:]
        return result


class _Connection:
    sock = None

    def __init__(
        self,
        *,
        request_error: BaseException | None = None,
        response_delay: float = 0.0,
        body_delay: float = 0.0,
        close_error: BaseException | None = None,
    ) -> None:
        self.timeout = 0.0
        self.request_error = request_error
        self.response_delay = response_delay
        self.body_delay = body_delay
        self.close_error = close_error
        self.closed = False

    def request(self, *_: object, **__: object) -> None:
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> _Response:
        if self.response_delay:
            time.sleep(self.response_delay)
        return _Response(delay=self.body_delay)

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


def test_unknown_rotation_slo_is_explicit_and_bounded() -> None:
    config = OIDCVerifierConfig(
        issuer="https://issuer.example",
        audiences=("resource-api",),
        client_id="oidc-client",
        algorithms=("RS256",),
        cache_ttl_seconds=60,
        max_unknown_rotation_delay_seconds=10,
    )
    assert config.max_unknown_rotation_delay_seconds == 10


def test_slow_resolver_obeys_total_deadline_and_worker_cap() -> None:
    release = threading.Event()

    def stuck(*_: object) -> object:
        release.wait(1)
        return []

    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.05,
        resolver=stuck,
        testing_only=True,
    )
    started = time.monotonic()
    with pytest.raises(OIDCVerificationFailed):
        fetcher.fetch_json("https://issuer.example/discovery", 1024)
    assert time.monotonic() - started < 0.25
    fetcher.close()
    release.set()
    time.sleep(0.05)


@pytest.mark.parametrize(
    ("response_delay", "body_delay"),
    [(0.15, 0.0), (0.0, 0.15)],
)
def test_slow_headers_and_body_obey_total_deadline_and_cleanup(
    response_delay: float,
    body_delay: float,
) -> None:
    connection = _Connection(
        response_delay=response_delay,
        body_delay=body_delay,
    )
    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.05,
        resolver=lambda *_: _records("93.184.216.34"),
        connection_factory=lambda *_args, **_kwargs: connection,  # type: ignore[arg-type]
        testing_only=True,
    )
    started = time.monotonic()
    with pytest.raises(OIDCVerificationFailed):
        fetcher.fetch_json("https://issuer.example/discovery", 1024)
    assert time.monotonic() - started < 0.25
    assert connection.closed
    fetcher.close()
    time.sleep(0.2)


def test_all_approved_addresses_are_tried_within_one_budget() -> None:
    attempted: list[str] = []

    def factory(
        _host: str,
        _port: int,
        pinned: str,
        **_: object,
    ) -> Any:
        attempted.append(pinned)
        return _Connection(
            request_error=OSError("first address unavailable")
            if len(attempted) == 1
            else None
        )

    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.5,
        resolver=lambda *_: _records(
            "2606:2800:220:1:248:1893:25c8:1946",
            "93.184.216.34",
        ),
        connection_factory=factory,
        testing_only=True,
    )
    assert fetcher.fetch_json("https://issuer.example/discovery", 1024) == {}
    assert attempted == (["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"])
    fetcher.close()


def test_stuck_resolver_workers_are_daemonized_and_strictly_capped() -> None:
    release = threading.Event()
    calls = 0
    lock = threading.Lock()

    def stuck(*_: object) -> object:
        nonlocal calls
        with lock:
            calls += 1
        release.wait(1)
        return []

    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.05,
        resolver=stuck,
        testing_only=True,
    )

    def rejected(_: int) -> bool:
        with pytest.raises(OIDCVerificationFailed):
            fetcher.fetch_json("https://issuer.example/discovery", 1024)
        return True

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(rejected, range(4)))
    started = time.monotonic()
    assert rejected(5)
    assert time.monotonic() - started < 0.05
    assert calls == 4
    fetcher.close()
    release.set()
    time.sleep(0.05)


@pytest.mark.parametrize(
    "control_error",
    [asyncio.CancelledError(), KeyboardInterrupt(), SystemExit(), GeneratorExit()],
)
def test_direct_control_flow_survives_close_failure(
    control_error: BaseException,
) -> None:
    connection = _Connection(
        request_error=control_error,
        close_error=RuntimeError("LEAK-close-secret"),
    )
    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.5,
        resolver=lambda *_: _records("93.184.216.34"),
        connection_factory=lambda *_args, **_kwargs: connection,  # type: ignore[arg-type]
        testing_only=True,
    )
    with pytest.raises(type(control_error)) as captured:
        fetcher.fetch_json("https://issuer.example/discovery", 1024)
    assert captured.value is control_error
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    fetcher.close()


def test_close_failure_without_primary_is_opaque() -> None:
    connection = _Connection(close_error=RuntimeError("LEAK-close-secret"))
    fetcher = PinnedHTTPSMetadataFetcher(
        timeout_seconds=0.5,
        resolver=lambda *_: _records("93.184.216.34"),
        connection_factory=lambda *_args, **_kwargs: connection,  # type: ignore[arg-type]
        testing_only=True,
    )
    with pytest.raises(OIDCVerificationFailed) as captured:
        fetcher.fetch_json("https://issuer.example/discovery", 1024)
    assert "LEAK" not in repr(captured.value)
    fetcher.close()


def test_tls_postwrap_peer_failure_closes_secured_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Raw:
        closed = False

        def getpeername(self) -> tuple[str, int]:
            return ("93.184.216.34", 443)

        def close(self) -> None:
            self.closed = True

    class Secured(Raw):
        def getpeername(self) -> tuple[str, int]:
            return ("93.184.216.35", 443)

    raw = Raw()
    secured = Secured()

    class Context:
        def wrap_socket(self, *_: object, **__: object) -> Secured:
            return secured

    monkeypatch.setattr(
        "palonexus.identity.oidc.socket.create_connection",
        lambda *_args, **_kwargs: raw,
    )
    connection = _PinnedHTTPSConnection(
        "issuer.example",
        443,
        "93.184.216.34",
        timeout=0.5,
        context=Context(),  # type: ignore[arg-type]
        approved_addresses=("93.184.216.34",),
    )
    with pytest.raises(OIDCVerificationFailed):
        connection.connect()
    assert secured.closed
    assert not raw.closed
