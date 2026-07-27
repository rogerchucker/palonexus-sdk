# SPDX-License-Identifier: MIT
"""Explicit, bounded, fail-closed OpenID Connect ID-token verification."""

from __future__ import annotations

import asyncio
import base64
import http.client
import ipaddress
import json
import math
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from types import MappingProxyType
from typing import NoReturn, Protocol, Self, cast
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

_SECURE_ALGORITHMS = frozenset({"RS256", "PS256", "ES256", "EdDSA"})
_MAX_TOKEN_BYTES = 65_536
_MAX_SEGMENT_BYTES = 49_152
_MAX_DOCUMENT_BYTES = 1_048_576
_MAX_KEYS = 64
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 1024
_MAX_STRING_BYTES = 16_384
_MAX_HEADERS = 64
_MAX_HEADER_BYTES = 16_384
_MAX_NEGATIVE_CACHE = 128
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class OIDCVerificationFailed(Exception):
    """Opaque OIDC configuration, discovery, or verification failure."""

    code = "oidc_verification_failed"
    _message = "OIDC verification failed."

    def __init__(self) -> None:
        super().__init__(self.code, self._message)

    def __str__(self) -> str:
        return f"{self.code}: {self._message}"

    def __repr__(self) -> str:
        return "OIDCVerificationFailed()"

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __reduce__(self) -> tuple[type[OIDCVerificationFailed], tuple[()]]:
        return (OIDCVerificationFailed, ())

    def __setattr__(self, name: str, value: object) -> None:
        if name not in {
            "__traceback__",
            "__cause__",
            "__context__",
            "__suppress_context__",
        }:
            raise AttributeError("OIDC errors are immutable.")
        Exception.__setattr__(self, name, value)


def _fail() -> NoReturn:
    raise OIDCVerificationFailed() from None


_FAILED = object()


class _ControlFlow:
    __slots__ = ("error",)

    def __init__(self, error: BaseException) -> None:
        self.error = error


def _capture[T](operation: Callable[[], T]) -> T | object:
    try:
        return operation()
    except (
        asyncio.CancelledError,
        GeneratorExit,
        KeyboardInterrupt,
        SystemExit,
    ) as error:
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
        return _ControlFlow(error)
    except BaseException:
        return _FAILED


def _raise_control_flow(error: BaseException) -> NoReturn:
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    raise error from None


def _checked[T](result: T | object) -> T:
    if result is _FAILED:
        _fail()
    if type(result) is _ControlFlow:
        _raise_control_flow(result.error)
    return cast(T, result)


def _url(value: object, *, allowed_origins: frozenset[str] | None = None) -> str:
    if type(value) is not str or len(value) > 2048:
        raise ValueError
    split = urlsplit(value)
    if (
        split.scheme != "https"
        or not split.hostname
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
        or split.hostname.endswith(".")
        or split.path.startswith("//")
    ):
        raise ValueError
    port = split.port
    host = split.hostname.encode("idna").decode("ascii").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError
    authority = host if port in (None, 443) else f"{host}:{port}"
    path = split.path or ""
    canonical = urlunsplit(("https", authority, path, "", ""))
    if canonical != value.rstrip("/") and canonical + "/" != value:
        raise ValueError
    origin = f"https://{authority}"
    if allowed_origins is not None and origin not in allowed_origins:
        raise ValueError
    return canonical


def _origin(value: str) -> str:
    split = urlsplit(value)
    authority = split.hostname or ""
    if split.port not in (None, 443):
        authority += f":{split.port}"
    return f"https://{authority}"


def _public_address(value: object) -> str:
    if type(value) is not str or len(value) > 64:
        raise ValueError
    address = ipaddress.ip_address(value)
    if type(address) is ipaddress.IPv6Address and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError
    return str(address)


class MetadataFetcher(Protocol):
    """Closed metadata transport boundary."""

    def fetch_json(self, url: str, maximum: int) -> dict[str, object]:
        """Fetch one bounded JSON object without redirects or ambient state."""

    def close(self) -> None:
        """Release all owned resources."""


class _PinnedHTTPSConnection(http.client.HTTPConnection):
    """One HTTPS/1.1 connection pinned to a prevalidated address."""

    def __init__(
        self,
        host: str,
        port: int,
        pinned_address: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
        approved_addresses: tuple[str, ...],
    ) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_address = pinned_address
        self._context = context
        self._approved_addresses = approved_addresses

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        try:
            PinnedHTTPSMetadataFetcher.validate_connected_peer(
                cast(tuple[object, ...], raw.getpeername())[0],
                self._approved_addresses,
            )
            secured = self._context.wrap_socket(raw, server_hostname=self.host)
            PinnedHTTPSMetadataFetcher.validate_connected_peer(
                cast(tuple[object, ...], secured.getpeername())[0],
                self._approved_addresses,
            )
        except BaseException:
            raw.close()
            raise
        self.sock = secured


class PinnedHTTPSMetadataFetcher:
    """Production HTTPS fetcher with DNS-set validation and connection pinning."""

    __slots__ = (
        "_closed",
        "_connection_factory",
        "_context",
        "_lock",
        "_resolver",
        "_timeout",
    )

    def __init__(
        self,
        *,
        timeout_seconds: float,
        resolver: Callable[..., object] = socket.getaddrinfo,
        ssl_context: ssl.SSLContext | None = None,
        connection_factory: Callable[..., http.client.HTTPConnection] | None = None,
        testing_only: bool = False,
    ) -> None:
        if resolver is not socket.getaddrinfo and testing_only is not True:
            _fail()
        if ssl_context is not None and testing_only is not True:
            _fail()
        if connection_factory is not None and testing_only is not True:
            _fail()
        self._timeout = timeout_seconds
        self._resolver = resolver
        self._context = ssl_context or ssl.create_default_context()
        self._connection_factory = connection_factory or _PinnedHTTPSConnection
        self._lock = threading.Lock()
        if (
            self._context.verify_mode != ssl.CERT_REQUIRED
            or not self._context.check_hostname
        ):
            _fail()
        self._closed = False

    @staticmethod
    def validate_resolved_addresses(addresses: object) -> tuple[str, ...]:
        result = _capture(partial(_validated_addresses, addresses))
        return _checked(result)

    @staticmethod
    def validate_connected_peer(
        peer: object,
        approved_addresses: object,
    ) -> None:
        operation = partial(_validated_peer, peer, approved_addresses)
        result = _capture(operation)
        _checked(result)

    def fetch_json(self, url: str, maximum: int) -> dict[str, object]:
        operation = partial(self._fetch_json_locked, url, maximum)
        result = _capture(operation)
        del operation, url
        return _checked(result)

    def _fetch_json_locked(self, url: str, maximum: int) -> dict[str, object]:
        with self._lock:
            return self._fetch_json(url, maximum)

    def _fetch_json(self, url: str, maximum: int) -> dict[str, object]:
        if self._closed:
            raise ValueError
        split = urlsplit(_url(url))
        host = cast(str, split.hostname)
        port = split.port or 443
        resolved = self._resolver(
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            socket.AI_CANONNAME,
        )
        if type(resolved) is not list:
            raise ValueError
        records = cast(list[tuple[object, ...]], resolved)
        raw_addresses: list[str] = []
        if not records or len(records) > 32:
            raise ValueError
        for record in records:
            if len(record) < 5:
                raise ValueError
            sockaddr = cast(tuple[object, ...], record[4])
            if not sockaddr or type(sockaddr[0]) is not str:
                raise ValueError
            raw_addresses.append(sockaddr[0])
        approved = _validated_addresses(tuple(raw_addresses))
        pinned = approved[0]
        connection = self._connection_factory(
            host,
            port,
            pinned,
            timeout=self._timeout,
            context=self._context,
            approved_addresses=approved,
        )
        authority = host if port == 443 else f"{host}:{port}"
        target = split.path or "/"
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Host": authority,
                    "Accept": "application/json, application/jwk-set+json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError
            headers = response.getheaders()
            if (
                len(headers) > _MAX_HEADERS
                or sum(len(name) + len(value) for name, value in headers)
                > _MAX_HEADER_BYTES
                or response.getheader("Content-Encoding", "identity").lower()
                not in {"", "identity"}
            ):
                raise ValueError
            content_type = (
                response.getheader("Content-Type", "").split(";", 1)[0].lower()
            )
            if content_type not in {"application/json", "application/jwk-set+json"}:
                raise ValueError
            transfer_encoding = response.getheader("Transfer-Encoding")
            declared = response.getheader("Content-Length")
            if transfer_encoding is not None and (
                transfer_encoding.lower() != "chunked" or declared is not None
            ):
                raise ValueError
            if declared is not None and int(declared) > maximum:
                raise ValueError
            body = response.read(maximum + 1)
            if len(body) > maximum or response.read(1):
                raise ValueError
            return _json_object(body)
        finally:
            connection.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True


def _validated_addresses(addresses: object) -> tuple[str, ...]:
    if type(addresses) not in (tuple, list):
        raise ValueError
    sequence = cast(tuple[object, ...] | list[object], addresses)
    if not sequence or len(sequence) > 32:
        raise ValueError
    result: list[str] = []
    for value in sequence:
        address = _public_address(value)
        if address not in result:
            result.append(address)
    if not result:
        raise ValueError
    return tuple(result)


def _validated_peer(peer: object, approved_addresses: object) -> None:
    approved = _validated_addresses(approved_addresses)
    if _public_address(peer) not in approved:
        raise ValueError


class _HTTPXTestingFetcher:
    __slots__ = ("_client",)

    def __init__(
        self,
        transport: httpx.BaseTransport,
        *,
        timeout_seconds: float,
    ) -> None:
        self._client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout_seconds),
            verify=True,
            trust_env=False,
            follow_redirects=False,
            cookies=None,
            auth=None,
            headers={"accept": "application/json"},
        )

    def fetch_json(self, url: str, maximum: int) -> dict[str, object]:
        return _fetch_json(self._client, url, maximum)

    def close(self) -> None:
        self._client.close()


def _string_tuple(value: object, *, maximum: int = 16) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > maximum:
        raise ValueError
    result: list[str] = []
    for item in value:
        if (
            type(item) is not str
            or not item
            or len(item.encode()) > 256
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in item)
            or item in result
        ):
            raise ValueError
        result.append(item)
    return tuple(result)


@dataclass(frozen=True, slots=True, init=False)
class OIDCVerifierConfig:
    """Immutable verifier policy; all trust anchors are caller supplied."""

    issuer: str
    audiences: tuple[str, ...]
    client_id: str
    algorithms: tuple[str, ...]
    discovery_url: str
    jwks_url: str | None
    allowed_jwks_origins: tuple[str, ...]
    timeout_seconds: float
    max_document_bytes: int
    cache_ttl_seconds: int
    leeway_seconds: int
    require_typ: bool
    allowed_types: tuple[str, ...]
    allow_missing_kid: bool
    refresh_cooldown_seconds: int
    failure_backoff_seconds: int

    def __init__(
        self,
        *,
        issuer: str,
        audiences: tuple[str, ...],
        client_id: str,
        algorithms: tuple[str, ...],
        discovery_url: str | None = None,
        jwks_url: str | None = None,
        allowed_jwks_origins: tuple[str, ...] = (),
        timeout_seconds: float = 5.0,
        max_document_bytes: int = _MAX_DOCUMENT_BYTES,
        cache_ttl_seconds: int = 300,
        leeway_seconds: int = 0,
        require_typ: bool = True,
        allowed_types: tuple[str, ...] = ("JWT",),
        allow_missing_kid: bool = False,
        refresh_cooldown_seconds: int = 30,
        failure_backoff_seconds: int = 5,
    ) -> None:
        operation = partial(
            _validate_config,
            issuer,
            audiences,
            client_id,
            algorithms,
            discovery_url,
            jwks_url,
            allowed_jwks_origins,
            timeout_seconds,
            max_document_bytes,
            cache_ttl_seconds,
            leeway_seconds,
            require_typ,
            allowed_types,
            allow_missing_kid,
            refresh_cooldown_seconds,
            failure_backoff_seconds,
        )
        result = _capture(operation)
        del (
            operation,
            issuer,
            audiences,
            client_id,
            algorithms,
            discovery_url,
            jwks_url,
            allowed_jwks_origins,
        )
        values: tuple[object, ...] = _checked(result)
        for name, value in zip(self.__slots__, values, strict=True):
            object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return "OIDCVerifierConfig([REDACTED])"

    def __reduce__(self) -> str:
        raise TypeError("OIDC verifier configuration cannot be serialized.")


def _validate_config(
    issuer: object,
    audiences: object,
    client_id: object,
    algorithms: object,
    discovery_url: object,
    jwks_url: object,
    allowed_jwks_origins: object,
    timeout_seconds: object,
    max_document_bytes: object,
    cache_ttl_seconds: object,
    leeway_seconds: object,
    require_typ: object,
    allowed_types: object,
    allow_missing_kid: object,
    refresh_cooldown_seconds: object,
    failure_backoff_seconds: object,
) -> tuple[object, ...]:
    normalized_issuer = _url(issuer)
    expected_audiences = _string_tuple(audiences)
    expected_client_id = _string_tuple((client_id,))[0]
    expected_algorithms = _string_tuple(algorithms)
    expected_types = _string_tuple(allowed_types)
    if not set(expected_algorithms) <= _SECURE_ALGORITHMS:
        raise ValueError
    issuer_origin = _origin(normalized_issuer)
    origins = (
        _string_tuple(allowed_jwks_origins, maximum=16) if allowed_jwks_origins else ()
    )
    normalized_origins = tuple(_origin(_url(item)) for item in origins)
    permitted = frozenset((issuer_origin, *normalized_origins))
    derived_discovery = (
        f"{normalized_issuer.rstrip('/')}/.well-known/openid-configuration"
    )
    normalized_discovery = _url(
        discovery_url if discovery_url is not None else derived_discovery,
        allowed_origins=frozenset({issuer_origin}),
    )
    normalized_jwks = (
        _url(jwks_url, allowed_origins=permitted) if jwks_url is not None else None
    )
    if type(timeout_seconds) not in (int, float):
        raise ValueError
    normalized_timeout = float(cast(int | float, timeout_seconds))
    if (
        not math.isfinite(normalized_timeout)
        or not 0.05 <= normalized_timeout <= 30
        or type(max_document_bytes) is not int
        or not 1024 <= max_document_bytes <= _MAX_DOCUMENT_BYTES
        or type(cache_ttl_seconds) is not int
        or not 1 <= cache_ttl_seconds <= 86_400
        or type(leeway_seconds) is not int
        or not 0 <= leeway_seconds <= 300
        or type(require_typ) is not bool
        or type(allow_missing_kid) is not bool
        or type(refresh_cooldown_seconds) is not int
        or not 1 <= refresh_cooldown_seconds <= 3600
        or type(failure_backoff_seconds) is not int
        or not 1 <= failure_backoff_seconds <= 300
    ):
        raise ValueError
    return (
        normalized_issuer,
        expected_audiences,
        expected_client_id,
        expected_algorithms,
        normalized_discovery,
        normalized_jwks,
        normalized_origins,
        normalized_timeout,
        max_document_bytes,
        cache_ttl_seconds,
        leeway_seconds,
        require_typ,
        expected_types,
        allow_missing_kid,
        refresh_cooldown_seconds,
        failure_backoff_seconds,
    )


@dataclass(frozen=True, slots=True)
class _FrozenObject:
    items: tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class _FrozenArray:
    items: tuple[object, ...]


def _freeze_json(value: object) -> object:
    if type(value) is dict:
        return _FrozenObject(
            tuple(
                (name, _freeze_json(item))
                for name, item in sorted(cast(dict[str, object], value).items())
            )
        )
    if type(value) is list:
        return _FrozenArray(
            tuple(_freeze_json(item) for item in cast(list[object], value))
        )
    return value


def _thaw_json(value: object) -> object:
    if type(value) is _FrozenObject:
        return {name: _thaw_json(item) for name, item in value.items}
    if type(value) is _FrozenArray:
        return [_thaw_json(item) for item in value.items]
    return value


@dataclass(frozen=True, slots=True, init=False)
class VerifiedOIDCIdentity:
    """Package-created immutable projection of verified ID-token claims."""

    issuer: str
    subject: str
    audiences: tuple[str, ...]
    authorized_party: str | None
    nonce: str | None
    token_id: str | None
    issued_at: datetime
    expires_at: datetime
    _claims: object

    def __init__(self) -> None:
        raise TypeError("Verified OIDC identities are package-controlled.")

    @property
    def claims(self) -> Mapping[str, object]:
        value = _thaw_json(self._claims)
        if type(value) is not dict:
            _fail()
        return MappingProxyType(cast(dict[str, object], value))

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __repr__(self) -> str:
        return "VerifiedOIDCIdentity([VERIFIED])"

    def __reduce__(self) -> str:
        raise TypeError("Verified OIDC identities cannot be serialized.")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("Verified OIDC identities cannot be subclassed.")


@dataclass(frozen=True, slots=True)
class _Key:
    kid: str | None
    algorithm: str
    value: object


@dataclass(frozen=True, slots=True)
class _Cache:
    keys: tuple[_Key, ...]
    expires_at: datetime
    generation: int


class OIDCVerifier:
    """Thread-safe synchronous OIDC verifier with bounded metadata caching."""

    __slots__ = (
        "_cache",
        "_closed",
        "_config",
        "_lock",
        "_clock",
        "_fetcher",
        "_forced_refresh_until",
        "_negative",
        "_refresh_backoff_until",
    )

    def __init__(
        self,
        config: OIDCVerifierConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        metadata_fetcher: MetadataFetcher | None = None,
        testing_only: bool = False,
        clock: Callable[[], datetime],
    ) -> None:
        if (
            type(config) is not OIDCVerifierConfig
            or not callable(clock)
            or (transport is not None and metadata_fetcher is not None)
            or (
                (transport is not None or metadata_fetcher is not None)
                and testing_only is not True
            )
        ):
            _fail()
        self._config = config
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: _Cache | None = None
        self._negative: dict[tuple[str, str], datetime] = {}
        self._forced_refresh_until: dict[str, datetime] = {}
        self._refresh_backoff_until: datetime | None = None
        self._closed = False
        try:
            self._fetcher = (
                metadata_fetcher
                if metadata_fetcher is not None
                else (
                    _HTTPXTestingFetcher(
                        transport,
                        timeout_seconds=config.timeout_seconds,
                    )
                    if transport is not None
                    else PinnedHTTPSMetadataFetcher(
                        timeout_seconds=config.timeout_seconds
                    )
                )
            )
        except BaseException:
            _fail()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def close(self) -> None:
        result = _capture(self._close)
        _checked(result)

    def _close(self) -> None:
        with self._lock:
            if not self._closed:
                try:
                    self._fetcher.close()
                finally:
                    self._closed = True
                    self._cache = None
                    self._negative.clear()
                    self._forced_refresh_until.clear()

    def verify(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> VerifiedOIDCIdentity:
        operation = partial(self._verify, token, expected_nonce)
        result = _capture(operation)
        del operation, token, expected_nonce
        return _checked(result)

    def _verify(
        self,
        token: object,
        expected_nonce: object,
    ) -> VerifiedOIDCIdentity:
        if self._closed:
            raise ValueError
        header, claims, signed, signature = _parse_token(token)
        algorithm = _required_string(header, "alg")
        if "kid" not in header:
            if not self._config.allow_missing_kid:
                raise ValueError
            kid: str | None = None
        else:
            kid = _required_string(header, "kid")
        typ = header.get("typ")
        if typ is None:
            if self._config.require_typ:
                raise ValueError
        elif type(typ) is not str or typ not in self._config.allowed_types:
            raise ValueError
        closed_headers = {
            "jku",
            "x5u",
            "x5c",
            "x5t",
            "x5t#S256",
            "jwk",
            "crit",
            "b64",
        }
        if algorithm not in self._config.algorithms or any(
            name in header for name in closed_headers
        ):
            raise ValueError
        key = self._key(kid, algorithm=algorithm, force=False)
        if key is None or key.algorithm != algorithm:
            key = self._key(
                kid,
                algorithm=algorithm,
                force=True,
                reason="unknown",
            )
        if key is None or key.algorithm != algorithm:
            raise ValueError
        try:
            _verify_signature(key, signed, signature)
        except InvalidSignature:
            key = self._key(
                kid,
                algorithm=algorithm,
                force=True,
                rejected=key,
                reason="signature",
            )
            if key is None or key.algorithm != algorithm:
                raise
            _verify_signature(key, signed, signature)
        return _validate_claims(
            claims,
            config=self._config,
            now=_trusted_now(self._clock),
            expected_nonce=expected_nonce,
        )

    def _key(
        self,
        kid: str | None,
        *,
        algorithm: str,
        force: bool,
        rejected: _Key | None = None,
        reason: str = "",
    ) -> _Key | None:
        now = _trusted_now(self._clock)
        with self._lock:
            if self._closed:
                raise ValueError
            current = self._cache
            if not force and current is not None and now < current.expires_at:
                return _select_key(current.keys, kid, algorithm)
            selected = (
                _select_key(current.keys, kid, algorithm)
                if current is not None
                else None
            )
            if (
                force
                and current is not None
                and now < current.expires_at
                and selected is not None
                and selected is not rejected
            ):
                return selected
            negative_key = (reason, kid or "[missing]")
            if force:
                retry_at = self._negative.get(negative_key)
                if retry_at is not None and now < retry_at:
                    return selected
                if (
                    reason in self._forced_refresh_until
                    and now < self._forced_refresh_until[reason]
                ):
                    return selected
                if (
                    self._refresh_backoff_until is not None
                    and now < self._refresh_backoff_until
                ):
                    raise ValueError
            elif (
                self._refresh_backoff_until is not None
                and now < self._refresh_backoff_until
            ):
                raise ValueError
            try:
                keys = self._refresh()
            except BaseException:
                delta = __import__("datetime").timedelta
                self._refresh_backoff_until = now + delta(
                    seconds=self._config.failure_backoff_seconds
                )
                if force:
                    self._record_negative(negative_key, now)
                raise
            generation = 1 if current is None else current.generation + 1
            self._cache = _Cache(
                keys=keys,
                expires_at=now
                + __import__("datetime").timedelta(
                    seconds=self._config.cache_ttl_seconds
                ),
                generation=generation,
            )
            selected = _select_key(keys, kid, algorithm)
            if force:
                self._record_negative(negative_key, now)
                self._forced_refresh_until[reason] = now + __import__(
                    "datetime"
                ).timedelta(seconds=self._config.refresh_cooldown_seconds)
            return selected

    def _record_negative(
        self,
        key: tuple[str, str],
        now: datetime,
    ) -> None:
        expired = [name for name, expiry in self._negative.items() if expiry <= now]
        for name in expired:
            del self._negative[name]
        while len(self._negative) >= _MAX_NEGATIVE_CACHE:
            del self._negative[next(iter(self._negative))]
        self._negative[key] = now + __import__("datetime").timedelta(
            seconds=self._config.refresh_cooldown_seconds
        )

    def _refresh(self) -> tuple[_Key, ...]:
        discovery = self._fetcher.fetch_json(
            self._config.discovery_url,
            self._config.max_document_bytes,
        )
        if discovery.get("issuer") != self._config.issuer:
            raise ValueError
        discovered_jwks = _url(
            discovery.get("jwks_uri"),
            allowed_origins=frozenset(
                {_origin(self._config.issuer), *self._config.allowed_jwks_origins}
            ),
        )
        if (
            self._config.jwks_url is not None
            and discovered_jwks != self._config.jwks_url
        ):
            raise ValueError
        document = self._fetcher.fetch_json(
            self._config.jwks_url or discovered_jwks,
            self._config.max_document_bytes,
        )
        return _parse_jwks(document, self._config.algorithms)


def _fetch_json(client: httpx.Client, url: str, maximum: int) -> dict[str, object]:
    client.cookies.clear()
    try:
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                raise ValueError
            content_type = (
                response.headers.get("content-type", "").split(";", 1)[0].lower()
            )
            if content_type not in {"application/json", "application/jwk-set+json"}:
                raise ValueError
            chunks: list[bytes] = []
            length = 0
            for chunk in response.iter_bytes(chunk_size=16_384):
                length += len(chunk)
                if length > maximum:
                    raise ValueError
                chunks.append(chunk)
    finally:
        client.cookies.clear()
    return _json_object(b"".join(chunks))


def _json_object(raw: bytes) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in values:
            if name in result:
                raise ValueError
            result[name] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    _bounded_json(value)
    if type(value) is not dict:
        raise ValueError
    return cast(dict[str, object], value)


def _bounded_json(
    value: object,
    *,
    depth: int = 0,
    count: list[int] | None = None,
) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > _MAX_JSON_DEPTH or count[0] > _MAX_JSON_ITEMS:
        raise ValueError
    if type(value) is str:
        if len(value.encode()) > _MAX_STRING_BYTES:
            raise ValueError
    elif type(value) is list:
        for item in cast(list[object], value):
            _bounded_json(item, depth=depth + 1, count=count)
    elif type(value) is dict:
        for name, item in cast(dict[str, object], value).items():
            _bounded_json(name, depth=depth + 1, count=count)
            _bounded_json(item, depth=depth + 1, count=count)
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError
    elif type(value) is float and not math.isfinite(value):
        raise ValueError


def _decode_segment(value: str) -> bytes:
    if (
        not value
        or len(value) > _MAX_SEGMENT_BYTES
        or any(char not in _B64URL for char in value)
    ):
        raise ValueError
    raw = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError
    return raw


def _parse_token(
    token: object,
) -> tuple[dict[str, object], dict[str, object], bytes, bytes]:
    if type(token) is not str or len(token.encode()) > _MAX_TOKEN_BYTES:
        raise ValueError
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError
    header_raw, claims_raw, signature = map(_decode_segment, parts)
    header = _json_object(header_raw)
    claims = _json_object(claims_raw)
    return header, claims, f"{parts[0]}.{parts[1]}".encode(), signature


def _required_string(value: Mapping[str, object], name: str) -> str:
    result = value.get(name)
    if type(result) is not str or not result or len(result) > 256:
        raise ValueError
    return result


def _parse_jwks(
    document: Mapping[str, object],
    allowed: tuple[str, ...],
) -> tuple[_Key, ...]:
    values = document.get("keys")
    if type(values) is not list or not values or len(values) > _MAX_KEYS:
        raise ValueError
    result: list[_Key] = []
    eligible_kids: set[str] = set()
    for raw in cast(list[object], values):
        if type(raw) is not dict:
            raise ValueError
        jwk = cast(dict[str, object], raw)
        if any(name in jwk for name in ("jku", "x5u", "x5c", "x5t", "x5t#S256")):
            raise ValueError
        use = jwk.get("use")
        if use is not None and use != "sig":
            continue
        algorithm_value = jwk.get("alg")
        if algorithm_value is not None and (
            type(algorithm_value) is not str or algorithm_value not in allowed
        ):
            continue
        kty = jwk.get("kty")
        compatible = tuple(
            candidate
            for candidate in allowed
            if (
                (candidate in {"RS256", "PS256"} and kty == "RSA")
                or (candidate == "ES256" and kty == "EC")
                or (candidate == "EdDSA" and kty == "OKP")
            )
        )
        if algorithm_value is None:
            if not compatible:
                continue
            selected_algorithms = compatible
        else:
            selected_algorithms = (algorithm_value,)
        operations = jwk.get("key_ops")
        if operations is not None and (
            type(operations) is not list
            or not operations
            or len(operations) > 8
            or any(type(item) is not str for item in operations)
            or "verify" not in operations
            or any(
                item in {"sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"}
                for item in operations
            )
        ):
            continue
        raw_kid = jwk.get("kid")
        kid = None if raw_kid is None else _required_string(jwk, "kid")
        if (kid is not None and kid in eligible_kids) or any(
            name in jwk for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
        ):
            raise ValueError
        result.extend(
            _Key(kid, algorithm, _public_key(jwk, algorithm))
            for algorithm in selected_algorithms
        )
        if kid is not None:
            eligible_kids.add(kid)
    if not result:
        raise ValueError
    return tuple(result)


def _select_key(
    keys: tuple[_Key, ...],
    kid: str | None,
    algorithm: str,
) -> _Key | None:
    candidates = tuple(
        key
        for key in keys
        if key.algorithm == algorithm and (kid is None or key.kid == kid)
    )
    return candidates[0] if len(candidates) == 1 else None


def _jwk_bytes(value: object, maximum: int) -> bytes:
    if type(value) is not str:
        raise ValueError
    raw = _decode_segment(value)
    if not raw or len(raw) > maximum:
        raise ValueError
    return raw


def _public_key(jwk: Mapping[str, object], algorithm: str) -> object:
    kty = jwk.get("kty")
    if algorithm in {"RS256", "PS256"} and kty == "RSA":
        n = int.from_bytes(_jwk_bytes(jwk.get("n"), 1024), "big")
        e = int.from_bytes(_jwk_bytes(jwk.get("e"), 8), "big")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        if key.key_size < 2048:
            raise ValueError
        return key
    if algorithm == "ES256" and kty == "EC" and jwk.get("crv") == "P-256":
        x_bytes = _jwk_bytes(jwk.get("x"), 32)
        y_bytes = _jwk_bytes(jwk.get("y"), 32)
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise ValueError
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if algorithm == "EdDSA" and kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_jwk_bytes(jwk.get("x"), 32))
    raise ValueError


def _verify_signature(key: _Key, signed: bytes, signature: bytes) -> None:
    if key.algorithm == "RS256":
        cast(rsa.RSAPublicKey, key.value).verify(
            signature, signed, padding.PKCS1v15(), hashes.SHA256()
        )
    elif key.algorithm == "PS256":
        cast(rsa.RSAPublicKey, key.value).verify(
            signature,
            signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    elif key.algorithm == "ES256":
        if len(signature) != 64:
            raise InvalidSignature
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if not 1 <= r < _P256_ORDER or not 1 <= s <= _P256_ORDER // 2:
            raise InvalidSignature
        cast(ec.EllipticCurvePublicKey, key.value).verify(
            utils.encode_dss_signature(r, s),
            signed,
            ec.ECDSA(hashes.SHA256()),
        )
    elif key.algorithm == "EdDSA":
        cast(ed25519.Ed25519PublicKey, key.value).verify(signature, signed)
    else:
        raise ValueError


def _trusted_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError
    return value.astimezone(UTC)


def _numeric_date(claims: Mapping[str, object], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int or value < 0:
        raise ValueError
    return value


def _validate_claims(
    claims: dict[str, object],
    *,
    config: OIDCVerifierConfig,
    now: datetime,
    expected_nonce: object,
) -> VerifiedOIDCIdentity:
    issuer = _required_string(claims, "iss")
    subject = _required_string(claims, "sub")
    if issuer != config.issuer:
        raise ValueError
    audiences: tuple[str, ...]
    raw_audiences = claims.get("aud")
    if type(raw_audiences) is str:
        audiences = (raw_audiences,)
    elif type(raw_audiences) is list:
        audiences = _string_tuple(tuple(raw_audiences))
    else:
        raise ValueError
    intersection = set(audiences) & set(config.audiences)
    if not intersection:
        raise ValueError
    azp = claims.get("azp")
    if len(audiences) > 1:
        if type(azp) is not str or azp != config.client_id:
            raise ValueError
    elif azp is not None and (type(azp) is not str or azp != config.client_id):
        raise ValueError
    exp = _numeric_date(claims, "exp")
    issued = _numeric_date(claims, "iat")
    nbf = _numeric_date(claims, "nbf")
    current = int(now.timestamp())
    if (
        current >= exp + config.leeway_seconds
        or nbf > current + config.leeway_seconds
        or issued > current + config.leeway_seconds
    ):
        raise ValueError
    nonce = claims.get("nonce")
    if expected_nonce is not None:
        if (
            type(expected_nonce) is not str
            or not expected_nonce
            or len(expected_nonce) > 256
            or nonce != expected_nonce
        ):
            raise ValueError
    elif nonce is not None and type(nonce) is not str:
        raise ValueError
    jti = claims.get("jti")
    if jti is not None and (type(jti) is not str or not jti or len(jti) > 256):
        raise ValueError
    identity = object.__new__(VerifiedOIDCIdentity)
    values = {
        "issuer": issuer,
        "subject": subject,
        "audiences": audiences,
        "authorized_party": azp,
        "nonce": nonce,
        "token_id": jti,
        "issued_at": datetime.fromtimestamp(issued, UTC),
        "expires_at": datetime.fromtimestamp(exp, UTC),
        "_claims": _freeze_json(claims),
    }
    for name, value in values.items():
        object.__setattr__(identity, name, value)
    return identity
