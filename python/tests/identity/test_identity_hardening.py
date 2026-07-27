# SPDX-License-Identifier: MIT
"""Reachability, model-forgery, replay, and lifetime hardening tests."""

from __future__ import annotations

import copy
import dataclasses
import pickle
import traceback
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
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
    create_verifiable_credential,
    create_verifiable_presentation,
    generate_ed25519_key,
    sign_ed25519,
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
