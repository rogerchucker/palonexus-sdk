# SPDX-License-Identifier: MIT
"""Reachability, model-forgery, replay, and lifetime hardening tests."""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import pickle
import traceback
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta, tzinfo
from functools import partial
from types import TracebackType
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from palonexus import EphemeralKeyStore
from palonexus.identity import (
    DidKey,
    IdentityVerificationFailed,
    MemoryReplayStore,
    StaticRevocationLookup,
    VerifiedCredential,
    VerifiedDelegation,
    VerifiedPresentation,
    create_delegation,
    create_verifiable_credential,
    create_verifiable_presentation,
    generate_ed25519_key,
    sign_ed25519,
    verify_delegation_chain,
    verify_verifiable_credential,
    verify_verifiable_presentation,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
TENANT = "tenant-hardening"


def _identity_graph_values(error: BaseException) -> list[object]:
    values: list[object] = []
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.extend((current, current.args))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        for frame, _ in traceback.walk_tb(current.__traceback__):
            if "/palonexus/" in frame.f_code.co_filename:
                values.extend(frame.f_locals.values())
    return values


def _assert_secret_unreachable(
    error: BaseException,
    *secret_needles: bytes | str,
) -> None:
    values = _identity_graph_values(error)
    rendered: list[str] = []
    for value in values:
        try:
            rendered.append(repr(value))
        except Exception:
            rendered.append("[UNPRINTABLE]")
        assert not isinstance(value, Ed25519PrivateKey)
        if isinstance(value, bytearray):
            assert not any(value)
        if hasattr(value, "private_bytes_raw"):
            try:
                cast(Any, value).private_bytes_raw()
            except Exception:
                pass
            else:
                pytest.fail("private-key object reachable from public exception")
    text = " ".join(rendered)
    for needle in secret_needles:
        rendered_needle = (
            needle.decode("utf-8", errors="ignore")
            if isinstance(needle, bytes)
            else needle
        )
        assert rendered_needle not in text


class _FailingStore:
    capabilities: Mapping[str, bool | str] = {"testing_only": True}

    def __init__(self) -> None:
        self.transferred: bytearray | None = None

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        del tenant_id, key_id
        self.transferred = value
        raise RuntimeError("LEAK-store-secret")

    def load(self, *, tenant_id: str, key_id: str) -> Any:
        del tenant_id, key_id
        raise RuntimeError("LEAK-load-secret")

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        del tenant_id, key_id


def test_key_generation_failure_erases_seed_and_sanitizes_exception_graph() -> None:
    store = _FailingStore()
    with pytest.raises(IdentityVerificationFailed) as captured:
        generate_ed25519_key(
            key_store=store,
            tenant_id="LEAK-tenant",
            key_id="LEAK-key",
        )
    assert store.transferred == bytearray(32)
    _assert_secret_unreachable(
        captured.value,
        "LEAK-store-secret",
        "LEAK-tenant",
        "LEAK-key",
    )


def test_direct_did_key_validation_does_not_retain_malformed_input() -> None:
    with pytest.raises(IdentityVerificationFailed) as captured:
        DidKey(
            did="LEAK-malformed-did",
            key_id="LEAK-malformed-key-id",
            public_key=b"LEAK-malformed-public-key",
        )
    _assert_secret_unreachable(
        captured.value,
        "LEAK-malformed-did",
        "LEAK-malformed-key-id",
        "LEAK-malformed-public-key",
    )


def test_signing_mismatch_and_load_failure_sanitize_exception_graph() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        first = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="first",
        )
        second = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="second",
        )
        with pytest.raises(IdentityVerificationFailed) as captured:
            sign_ed25519(
                b"LEAK-message",
                key_store=store,
                tenant_id=TENANT,
                key_id="first",
                expected_did=second.did,
            )
    _assert_secret_unreachable(captured.value, "LEAK-message")
    assert first.did != second.did

    with pytest.raises(IdentityVerificationFailed) as unavailable:
        sign_ed25519(
            b"LEAK-message",
            key_store=_FailingStore(),
            tenant_id="LEAK-tenant",
            key_id="LEAK-key",
        )
    _assert_secret_unreachable(
        unavailable.value,
        "LEAK-load-secret",
        "LEAK-message",
        "LEAK-tenant",
        "LEAK-key",
    )


def _issued_token(
    store: EphemeralKeyStore,
    *,
    key_id: str = "issuer",
    credential_id: str = "urn:uuid:credential",
    expires_at: datetime = NOW + timedelta(minutes=5),
    claims: Mapping[str, object] | None = None,
) -> tuple[str, str]:
    key = generate_ed25519_key(
        key_store=store,
        tenant_id=TENANT,
        key_id=key_id,
    )
    return (
        create_verifiable_credential(
            key_store=store,
            tenant_id=TENANT,
            key_id=key_id,
            issuer=key.did,
            subject="did:example:agent",
            audience="control-plane",
            credential_id=credential_id,
            issued_at=NOW,
            expires_at=expires_at,
            claims=claims or {"role": "operator"},
        ),
        key.did,
    )


def test_raw_token_claim_and_callback_secrets_are_absent_from_error_graph() -> None:
    class BrokenRevocation:
        def is_revoked(self, credential_id: str) -> bool:
            raise RuntimeError(f"LEAK-revocation:{credential_id}")

    with EphemeralKeyStore(testing_only=True) as store:
        token, _ = _issued_token(
            store,
            credential_id="LEAK-credential-id",
            claims={"private": "LEAK-claim"},
        )
    with pytest.raises(IdentityVerificationFailed) as captured:
        verify_verifiable_credential(
            token,
            expected_audience="control-plane",
            now=NOW,
            revocation_lookup=BrokenRevocation(),
        )
    _assert_secret_unreachable(
        captured.value,
        token,
        "LEAK-credential-id",
        "LEAK-claim",
        "LEAK-revocation",
    )


def test_replay_callback_error_and_presentation_token_are_sanitized() -> None:
    class BrokenReplay:
        def check_and_record(
            self,
            replay_id: str,
            *,
            expires_at: datetime,
            now: datetime,
        ) -> bool:
            del expires_at, now
            raise RuntimeError(f"LEAK-replay:{replay_id}")

    with EphemeralKeyStore(testing_only=True) as store:
        holder = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="holder-replay",
        )
        credential, _ = _issued_token(
            store,
            key_id="issuer-replay",
            credential_id="urn:uuid:replay-credential",
        )
        presentation = create_verifiable_presentation(
            key_store=store,
            tenant_id=TENANT,
            key_id="holder-replay",
            holder=holder.did,
            credentials=(credential,),
            audience="control-plane",
            challenge="LEAK-challenge",
            presentation_id="LEAK-presentation-id",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(IdentityVerificationFailed) as captured:
        verify_verifiable_presentation(
            presentation,
            expected_audience="control-plane",
            expected_challenge="LEAK-challenge",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
            replay_store=BrokenReplay(),
        )
    _assert_secret_unreachable(
        captured.value,
        presentation,
        "LEAK-replay",
        "LEAK-challenge",
        "LEAK-presentation-id",
    )


def test_custom_claim_json_types_round_trip_without_tuple_ambiguity() -> None:
    claims = {
        "emptyArray": [],
        "emptyObject": {},
        "listOfPairs": [["a", 1], ["b", 2]],
        "nested": {"items": [{"flag": True}, None]},
        "scalar": 7,
    }
    with EphemeralKeyStore(testing_only=True) as store:
        token, _ = _issued_token(store, claims=claims)
    verified = verify_verifiable_credential(
        token,
        expected_audience="control-plane",
        now=NOW,
        revocation_lookup=StaticRevocationLookup(),
    )
    assert verified.claims == claims
    first = verified.claims
    cast(list[object], first["emptyArray"]).append("mutation")
    assert verified.claims == claims


def test_verified_models_cannot_be_forged_replaced_subclassed_or_serialized() -> None:
    for model in (VerifiedCredential, VerifiedPresentation, VerifiedDelegation):
        with pytest.raises(TypeError):
            model()
        with pytest.raises(TypeError):
            type("Forged", (model,), {})

    with EphemeralKeyStore(testing_only=True) as store:
        token, _ = _issued_token(
            store,
            claims={"private": "LEAK-authority"},
        )
    verified = verify_verifiable_credential(
        token,
        expected_audience="control-plane",
        now=NOW,
        revocation_lookup=StaticRevocationLookup(),
    )
    assert copy.copy(verified) is verified
    assert copy.deepcopy(verified) is verified
    assert "LEAK-authority" not in repr(verified)
    with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
        dataclasses.replace(verified, subject="did:example:forged")
    with pytest.raises(TypeError):
        pickle.dumps(verified)


def test_vp_expiration_cannot_outlive_any_embedded_credential() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        holder = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="holder",
        )
        first, _ = _issued_token(
            store,
            key_id="issuer-one",
            credential_id="urn:uuid:first",
            expires_at=NOW + timedelta(minutes=2),
        )
        second, _ = _issued_token(
            store,
            key_id="issuer-two",
            credential_id="urn:uuid:second",
            expires_at=NOW + timedelta(minutes=3),
        )

        def presentation(expires_at: datetime, identifier: str) -> str:
            return create_verifiable_presentation(
                key_store=store,
                tenant_id=TENANT,
                key_id="holder",
                holder=holder.did,
                credentials=(first, second),
                audience="control-plane",
                challenge="challenge-strong",
                presentation_id=identifier,
                issued_at=NOW,
                expires_at=expires_at,
            )

        equal = presentation(NOW + timedelta(minutes=2), "urn:uuid:equal")
        earlier = presentation(NOW + timedelta(minutes=1), "urn:uuid:earlier")
        later = presentation(NOW + timedelta(minutes=2, seconds=1), "urn:uuid:later")

    for token in (equal, earlier):
        verify_verifiable_presentation(
            token,
            expected_audience="control-plane",
            expected_challenge="challenge-strong",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
            replay_store=MemoryReplayStore(testing_only=True),
        )
    with pytest.raises(IdentityVerificationFailed):
        verify_verifiable_presentation(
            later,
            expected_audience="control-plane",
            expected_challenge="challenge-strong",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
            replay_store=MemoryReplayStore(testing_only=True),
        )


def test_memory_replay_store_is_explicit_bounded_and_purges_atomically() -> None:
    with pytest.raises(IdentityVerificationFailed):
        MemoryReplayStore()
    replay = MemoryReplayStore(testing_only=True, max_entries=1)
    assert replay.check_and_record(
        "urn:uuid:first",
        expires_at=NOW + timedelta(seconds=1),
        now=NOW,
    )
    assert not replay.check_and_record(
        "urn:uuid:capacity",
        expires_at=NOW + timedelta(minutes=1),
        now=NOW,
    )
    assert replay.check_and_record(
        "urn:uuid:after-expiry",
        expires_at=NOW + timedelta(minutes=1),
        now=NOW + timedelta(seconds=1),
    )
    for invalid in ("", "x" * 257, "contains whitespace", "control\x01"):
        assert not replay.check_and_record(
            invalid,
            expires_at=NOW + timedelta(minutes=1),
            now=NOW,
        )


class _HostileTimezone(tzinfo):
    def utcoffset(self, value: datetime | None) -> timedelta:
        del value
        raise RuntimeError("LEAK-hostile-utcoffset")

    def dst(self, value: datetime | None) -> timedelta:
        del value
        raise RuntimeError("LEAK-hostile-dst")

    def tzname(self, value: datetime | None) -> str:
        del value
        raise RuntimeError("LEAK-hostile-tzname")

    def fromutc(self, value: datetime) -> datetime:
        del value
        raise RuntimeError("LEAK-hostile-fromutc")


def test_memory_replay_store_guards_hostile_datetime_normalization() -> None:
    replay = MemoryReplayStore(testing_only=True, max_entries=1)
    hostile = datetime(2026, 7, 27, 12, 0, tzinfo=_HostileTimezone())
    assert not replay.check_and_record(
        "urn:uuid:hostile-expiry",
        expires_at=hostile,
        now=NOW,
    )
    assert not replay.check_and_record(
        "urn:uuid:hostile-now",
        expires_at=NOW + timedelta(minutes=1),
        now=hostile,
    )
    assert replay.check_and_record(
        "urn:uuid:valid-after-hostile",
        expires_at=NOW + timedelta(minutes=1),
        now=NOW,
    )


class _CancellationStore:
    capabilities: Mapping[str, bool | str] = {"testing_only": True}

    def __init__(
        self,
        cancellation: BaseException,
        *,
        cancel_on: str,
    ) -> None:
        self.cancellation = cancellation
        self.cancel_on = cancel_on
        self.inner = EphemeralKeyStore(testing_only=True)

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        if self.cancel_on == "store":
            for index in range(len(value)):
                value[index] = 0
            raise self.cancellation
        self.inner.store(tenant_id=tenant_id, key_id=key_id, value=value)

    def load(self, *, tenant_id: str, key_id: str) -> Any:
        if self.cancel_on == "load":
            raise self.cancellation
        lease = self.inner.load(tenant_id=tenant_id, key_id=key_id)
        if self.cancel_on != "lease":
            return lease

        cancellation = self.cancellation

        class CancellingLease:
            def __enter__(self) -> Any:
                entered = lease.__enter__()
                del entered
                raise cancellation

            def __exit__(
                self,
                exc_type: type[BaseException] | None,
                exc_value: BaseException | None,
                traceback_value: TracebackType | None,
            ) -> None:
                lease.__exit__(exc_type, exc_value, traceback_value)

        return CancellingLease()

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        self.inner.delete(tenant_id=tenant_id, key_id=key_id)


def _assert_same_clean_cancellation(
    expected: asyncio.CancelledError,
    operation: Any,
) -> None:
    with pytest.raises(asyncio.CancelledError) as captured:
        operation()
    assert captured.value is expected
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    _assert_secret_unreachable(captured.value, "LEAK-callback-frame")


@pytest.mark.parametrize("cancel_on", ["store", "load", "lease"])
def test_key_store_cancellation_propagates_identity_without_secret_graph(
    cancel_on: str,
) -> None:
    cancellation = asyncio.CancelledError()
    store = _CancellationStore(cancellation, cancel_on=cancel_on)
    operation: Callable[[], object]
    if cancel_on == "store":
        operation = partial(
            generate_ed25519_key,
            key_store=store,
            tenant_id="LEAK-callback-frame",
            key_id="cancelled",
        )
    else:
        if cancel_on == "lease":
            key = generate_ed25519_key(
                key_store=store.inner,
                tenant_id=TENANT,
                key_id="cancelled",
            )
        else:
            key = generate_ed25519_key(
                key_store=store.inner,
                tenant_id=TENANT,
                key_id="cancelled",
            )
        operation = partial(
            sign_ed25519,
            b"LEAK-callback-frame",
            key_store=store,
            tenant_id=TENANT,
            key_id="cancelled",
            expected_did=key.did,
        )
    _assert_same_clean_cancellation(cancellation, operation)


def test_revocation_and_replay_cancellation_propagate_same_clean_object() -> None:
    revocation_cancelled = asyncio.CancelledError()

    class CancellingRevocation:
        def is_revoked(self, credential_id: str) -> bool:
            del credential_id
            raise revocation_cancelled

    with EphemeralKeyStore(testing_only=True) as store:
        credential, _ = _issued_token(store)
    _assert_same_clean_cancellation(
        revocation_cancelled,
        lambda: verify_verifiable_credential(
            credential,
            expected_audience="control-plane",
            now=NOW,
            revocation_lookup=CancellingRevocation(),
        ),
    )

    replay_cancelled = asyncio.CancelledError()

    class CancellingReplay:
        def check_and_record(
            self,
            replay_id: str,
            *,
            expires_at: datetime,
            now: datetime,
        ) -> bool:
            del replay_id, expires_at, now
            raise replay_cancelled

    with EphemeralKeyStore(testing_only=True) as store:
        holder = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="cancel-holder",
        )
        credential, _ = _issued_token(
            store,
            key_id="cancel-issuer",
            expires_at=NOW + timedelta(minutes=2),
        )
        presentation = create_verifiable_presentation(
            key_store=store,
            tenant_id=TENANT,
            key_id="cancel-holder",
            holder=holder.did,
            credentials=(credential,),
            audience="control-plane",
            challenge="cancel-challenge",
            presentation_id="urn:uuid:cancel-presentation",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    _assert_same_clean_cancellation(
        replay_cancelled,
        lambda: verify_verifiable_presentation(
            presentation,
            expected_audience="control-plane",
            expected_challenge="cancel-challenge",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
            replay_store=CancellingReplay(),
        ),
    )


@pytest.mark.parametrize("boundary", ["vc", "vp", "delegation"])
def test_signed_identity_creation_propagates_cancellation(boundary: str) -> None:
    cancellation = asyncio.CancelledError()
    store = _CancellationStore(cancellation, cancel_on="load")
    issuer = generate_ed25519_key(
        key_store=store.inner,
        tenant_id=TENANT,
        key_id="cancel-signing",
    )
    if boundary == "vc":
        operation = partial(
            create_verifiable_credential,
            key_store=store,
            tenant_id=TENANT,
            key_id="cancel-signing",
            issuer=issuer.did,
            subject="did:example:agent",
            audience="control-plane",
            credential_id="urn:uuid:cancel-vc",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            claims={"private": "LEAK-callback-frame"},
        )
    elif boundary == "vp":
        credential, _ = _issued_token(
            store.inner,
            key_id="cancel-vp-issuer",
        )
        operation = partial(
            create_verifiable_presentation,
            key_store=store,
            tenant_id=TENANT,
            key_id="cancel-signing",
            holder=issuer.did,
            credentials=(credential,),
            audience="control-plane",
            challenge="LEAK-callback-frame",
            presentation_id="urn:uuid:cancel-vp",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    else:
        operation = partial(
            create_delegation,
            key_store=store,
            tenant_id=TENANT,
            key_id="cancel-signing",
            issuer=issuer.did,
            subject="did:example:delegate",
            audience="control-plane",
            credential_id="urn:uuid:cancel-delegation",
            actor="did:example:actor",
            agent="did:example:agent",
            capabilities=("tools:read",),
            resources=("runbooks/*",),
            remaining_depth=1,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    _assert_same_clean_cancellation(cancellation, operation)


def test_delegation_revocation_cancellation_propagates() -> None:
    cancellation = asyncio.CancelledError()

    class CancellingRevocation:
        def is_revoked(self, credential_id: str) -> bool:
            del credential_id
            raise cancellation

    with EphemeralKeyStore(testing_only=True) as store:
        issuer = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="delegation-cancel",
        )
        token = create_delegation(
            key_store=store,
            tenant_id=TENANT,
            key_id="delegation-cancel",
            issuer=issuer.did,
            subject="did:example:delegate",
            audience="control-plane",
            credential_id="urn:uuid:delegation-cancel",
            actor="did:example:actor",
            agent="did:example:agent",
            capabilities=("tools:read",),
            resources=("runbooks/*",),
            remaining_depth=1,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    _assert_same_clean_cancellation(
        cancellation,
        lambda: verify_delegation_chain(
            (token,),
            root_issuer=issuer.did,
            expected_subject="did:example:delegate",
            expected_actor="did:example:actor",
            expected_agent="did:example:agent",
            expected_audience="control-plane",
            required_capability="tools:read",
            required_resource="runbooks/*",
            now=NOW,
            revocation_lookup=CancellingRevocation(),
        ),
    )


def test_generator_exit_is_not_converted_to_identity_failure() -> None:
    class GeneratorExitStore(_FailingStore):
        def store(
            self,
            *,
            tenant_id: str,
            key_id: str,
            value: bytearray,
        ) -> None:
            del tenant_id, key_id
            for index in range(len(value)):
                value[index] = 0
            raise GeneratorExit

    with pytest.raises(GeneratorExit):
        generate_ed25519_key(
            key_store=GeneratorExitStore(),
            tenant_id=TENANT,
            key_id="generator-exit",
        )


class _HostileBaseException(BaseException):
    pass


def _assert_sanitized_base_exception(
    operation: Callable[[], object],
    *needles: str,
) -> None:
    with pytest.raises(IdentityVerificationFailed) as captured:
        operation()
    _assert_secret_unreachable(captured.value, *needles)


@pytest.mark.parametrize("fail_on", ["store", "load", "lease"])
def test_custom_base_exception_from_key_store_is_sanitized(fail_on: str) -> None:
    hostile = _HostileBaseException("LEAK-hostile-base")
    store = _CancellationStore(hostile, cancel_on=fail_on)
    operation: Callable[[], object]
    if fail_on == "store":
        operation = partial(
            generate_ed25519_key,
            key_store=store,
            tenant_id="LEAK-hostile-tenant",
            key_id="hostile",
        )
    else:
        key = generate_ed25519_key(
            key_store=store.inner,
            tenant_id=TENANT,
            key_id="hostile",
        )
        operation = partial(
            sign_ed25519,
            b"LEAK-hostile-message",
            key_store=store,
            tenant_id=TENANT,
            key_id="hostile",
            expected_did=key.did,
        )
    _assert_sanitized_base_exception(
        operation,
        "LEAK-hostile-base",
        "LEAK-hostile-tenant",
        "LEAK-hostile-message",
    )


def test_custom_base_exception_from_revocation_and_replay_is_sanitized() -> None:
    class HostileRevocation:
        def is_revoked(self, credential_id: str) -> bool:
            del credential_id
            raise _HostileBaseException("LEAK-hostile-revocation")

    with EphemeralKeyStore(testing_only=True) as store:
        credential, _ = _issued_token(store)
    _assert_sanitized_base_exception(
        partial(
            verify_verifiable_credential,
            credential,
            expected_audience="control-plane",
            now=NOW,
            revocation_lookup=HostileRevocation(),
        ),
        credential,
        "LEAK-hostile-revocation",
    )

    class HostileReplay:
        def check_and_record(
            self,
            replay_id: str,
            *,
            expires_at: datetime,
            now: datetime,
        ) -> bool:
            del replay_id, expires_at, now
            raise _HostileBaseException("LEAK-hostile-replay")

    with EphemeralKeyStore(testing_only=True) as store:
        holder = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="hostile-holder",
        )
        credential, _ = _issued_token(
            store,
            key_id="hostile-issuer",
            expires_at=NOW + timedelta(minutes=2),
        )
        presentation = create_verifiable_presentation(
            key_store=store,
            tenant_id=TENANT,
            key_id="hostile-holder",
            holder=holder.did,
            credentials=(credential,),
            audience="control-plane",
            challenge="hostile-challenge",
            presentation_id="urn:uuid:hostile-presentation",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
    _assert_sanitized_base_exception(
        partial(
            verify_verifiable_presentation,
            presentation,
            expected_audience="control-plane",
            expected_challenge="hostile-challenge",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
            replay_store=HostileReplay(),
        ),
        presentation,
        "LEAK-hostile-replay",
    )


def test_base_exception_group_is_sanitized_as_one_opaque_failure() -> None:
    grouped = BaseExceptionGroup(
        "LEAK-hostile-group",
        [
            asyncio.CancelledError("LEAK-nested-cancellation"),
            _HostileBaseException("LEAK-nested-base"),
        ],
    )
    store = _CancellationStore(grouped, cancel_on="store")
    _assert_sanitized_base_exception(
        partial(
            generate_ed25519_key,
            key_store=store,
            tenant_id="LEAK-group-tenant",
            key_id="grouped",
        ),
        "LEAK-hostile-group",
        "LEAK-nested-cancellation",
        "LEAK-nested-base",
        "LEAK-group-tenant",
    )
