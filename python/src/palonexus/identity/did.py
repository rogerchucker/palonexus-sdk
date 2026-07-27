# SPDX-License-Identifier: MIT
"""Strict Ed25519 ``did:key`` helpers over the package key-store boundary."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..keystore import KeyStore

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_ED25519_MULTICODEC = b"\xed\x01"
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_MAX_MESSAGE_BYTES = 1_048_576
_MAX_DID_BYTES = 256
_FAILED = object()


class IdentityVerificationFailed(Exception):
    """A deliberately opaque identity construction or verification failure."""

    code = "identity_verification_failed"
    _message = "Identity verification failed."

    def __init__(self) -> None:
        super().__init__(self.code, self._message)

    def __str__(self) -> str:
        return f"{self.code}: {self._message}"

    def __repr__(self) -> str:
        return "IdentityVerificationFailed()"

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __reduce__(
        self,
    ) -> tuple[type[IdentityVerificationFailed], tuple[()]]:
        return (IdentityVerificationFailed, ())

    def __setattr__(self, name: str, value: object) -> None:
        if name not in {
            "__traceback__",
            "__cause__",
            "__context__",
            "__suppress_context__",
        }:
            raise AttributeError("Identity errors are immutable.")
        Exception.__setattr__(self, name, value)


def _capture[T](operation: Callable[[], T]) -> T | object:
    """Discard an entire unsafe exception graph and return only a sentinel."""

    try:
        return operation()
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        return _FAILED


def _raise_identity_failure() -> NoReturn:
    """Create the public error in a frame that has never held caller input."""

    raise IdentityVerificationFailed() from None


def _base58btc_encode(value: bytes) -> str:
    leading_zeroes = len(value) - len(value.lstrip(b"\0"))
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    return ("1" * leading_zeroes) + encoded


def _base58btc_decode(value: object) -> bytes:
    try:
        if type(value) is not str or not value or len(value) > _MAX_DID_BYTES:
            raise ValueError
        number = 0
        for character in value:
            number = (number * 58) + _BASE58_INDEX[character]
        body = (
            number.to_bytes(math.ceil(number.bit_length() / 8), "big")
            if number
            else b""
        )
        decoded = (b"\0" * (len(value) - len(value.lstrip("1")))) + body
        if _base58btc_encode(decoded) != value:
            raise ValueError
        return decoded
    except Exception:
        raise IdentityVerificationFailed() from None


def _validate_message(value: object) -> bytes:
    if type(value) is not bytes or len(value) > _MAX_MESSAGE_BYTES:
        raise IdentityVerificationFailed() from None
    return value


def _did_from_public_bytes(value: bytes) -> tuple[str, str]:
    if len(value) != _PUBLIC_KEY_BYTES:
        raise IdentityVerificationFailed() from None
    fingerprint = "z" + _base58btc_encode(_ED25519_MULTICODEC + value)
    did = f"did:key:{fingerprint}"
    return did, f"{did}#{fingerprint}"


@dataclass(frozen=True, slots=True, init=False)
class DidKey:
    """Immutable public Ed25519 DID material; it never owns a private key."""

    did: str
    key_id: str
    public_key: bytes

    def __init__(self, *, did: str, key_id: str, public_key: bytes) -> None:
        operation = partial(_validated_did_key_parts, did, key_id, public_key)
        result = _capture(operation)
        del operation, did, key_id, public_key
        if result is _FAILED:
            _raise_identity_failure()
        resolved_did, resolved_key_id, resolved_public_key = cast(
            tuple[str, str, bytes],
            result,
        )
        object.__setattr__(self, "did", resolved_did)
        object.__setattr__(self, "key_id", resolved_key_id)
        object.__setattr__(self, "public_key", resolved_public_key)

    def sign(
        self,
        message: bytes,
        *,
        key_store: KeyStore,
        tenant_id: str,
        key_id: str,
    ) -> bytes:
        """Sign with the named key-store lease and bind it to this public DID."""

        operation = partial(
            sign_ed25519,
            message,
            key_store=key_store,
            tenant_id=tenant_id,
            key_id=key_id,
            expected_did=self.did,
        )
        result = _capture(operation)
        del operation, message, key_store, tenant_id, key_id
        if result is _FAILED:
            _raise_identity_failure()
        return cast(bytes, result)

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self


def _validated_did_key_parts(
    did: object,
    key_id: object,
    public_key: object,
) -> tuple[str, str, bytes]:
    resolved = _resolve_did_key(did)
    if (
        type(key_id) is not str
        or type(public_key) is not bytes
        or resolved.key_id != key_id
        or resolved.public_key != public_key
    ):
        raise IdentityVerificationFailed() from None
    return resolved.did, resolved.key_id, resolved.public_key


def _resolve_did_key(did: object) -> DidKey:
    """Resolve one canonical, fragment-free Ed25519 ``did:key`` value."""

    try:
        if (
            type(did) is not str
            or not did.startswith("did:key:z")
            or "#" in did
            or len(did.encode("ascii")) > _MAX_DID_BYTES
        ):
            raise ValueError
        fingerprint = did.removeprefix("did:key:")
        decoded = _base58btc_decode(fingerprint[1:])
        if (
            not decoded.startswith(_ED25519_MULTICODEC)
            or len(decoded) != len(_ED25519_MULTICODEC) + _PUBLIC_KEY_BYTES
        ):
            raise ValueError
        public_bytes = decoded[len(_ED25519_MULTICODEC) :]
        Ed25519PublicKey.from_public_bytes(public_bytes)
        canonical_did, canonical_key_id = _did_from_public_bytes(public_bytes)
        if canonical_did != did:
            raise ValueError
        # Bypass the validating constructor to avoid recursion.
        result = object.__new__(DidKey)
        object.__setattr__(result, "did", canonical_did)
        object.__setattr__(result, "key_id", canonical_key_id)
        object.__setattr__(result, "public_key", public_bytes)
        return result
    except IdentityVerificationFailed:
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def resolve_did_key(did: object) -> DidKey:
    """Resolve without retaining caller input on a public failure traceback."""

    operation = partial(_resolve_did_key, did)
    result = _capture(operation)
    del operation, did
    if result is _FAILED:
        _raise_identity_failure()
    return cast(DidKey, result)


def _generate_ed25519_key(
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
) -> DidKey:
    """Generate and transfer a raw Ed25519 seed to an explicit key store."""

    private_buffer: bytearray | None = None
    try:
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        private_buffer = bytearray(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        key_store.store(
            tenant_id=tenant_id,
            key_id=key_id,
            value=private_buffer,
        )
        private_buffer = None  # store owns and erases the transferred buffer
        did, did_key_id = _did_from_public_bytes(public_bytes)
        return DidKey(did=did, key_id=did_key_id, public_key=public_bytes)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None
    finally:
        if private_buffer is not None:
            for index in range(len(private_buffer)):
                private_buffer[index] = 0
        try:
            del private_key
        except UnboundLocalError:
            pass


def generate_ed25519_key(
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
) -> DidKey:
    """Generate without connecting key-store failures to the public error."""

    operation = partial(
        _generate_ed25519_key,
        key_store=key_store,
        tenant_id=tenant_id,
        key_id=key_id,
    )
    result = _capture(operation)
    del operation, key_store, tenant_id, key_id
    if result is _FAILED:
        _raise_identity_failure()
    return cast(DidKey, result)


def _sign_ed25519(
    message: bytes,
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    expected_did: str | None = None,
) -> bytes:
    """Sign a bounded byte string using a short-lived key-store lease."""

    private_bytes: bytes | None = None
    try:
        validated_message = _validate_message(message)
        with key_store.load(tenant_id=tenant_id, key_id=key_id) as lease:
            private_bytes = lease.copy_bytes()
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        if expected_did is not None:
            public_bytes = private_key.public_key().public_bytes_raw()
            actual_did, _ = _did_from_public_bytes(public_bytes)
            if actual_did != expected_did:
                raise ValueError
        return private_key.sign(validated_message)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None
    finally:
        try:
            del private_key
        except UnboundLocalError:
            pass
        del private_bytes


def sign_ed25519(
    message: bytes,
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    expected_did: str | None = None,
) -> bytes:
    """Sign without retaining message, identifiers, lease, or key on failure."""

    operation = partial(
        _sign_ed25519,
        message,
        key_store=key_store,
        tenant_id=tenant_id,
        key_id=key_id,
        expected_did=expected_did,
    )
    result = _capture(operation)
    del operation, message, key_store, tenant_id, key_id, expected_did
    if result is _FAILED:
        _raise_identity_failure()
    return cast(bytes, result)


def verify_ed25519(did: str, message: bytes, signature: bytes) -> bool:
    """Return whether a bounded signature matches a canonical Ed25519 DID."""

    try:
        key = _resolve_did_key(did)
        validated_message = _validate_message(message)
        if type(signature) is not bytes or len(signature) != _SIGNATURE_BYTES:
            return False
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature,
            validated_message,
        )
        return True
    except (InvalidSignature, IdentityVerificationFailed, ValueError):
        return False
    except Exception:
        return False
