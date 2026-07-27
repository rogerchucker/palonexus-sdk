# SPDX-License-Identifier: MIT
"""Interoperable and adversarial tests for DID, VC, and VP helpers."""

from __future__ import annotations

import copy
import json
import pickle
import threading
from collections.abc import Mapping
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from palonexus import EphemeralKeyStore
from palonexus.identity import (
    IdentityVerificationFailed,
    MemoryReplayStore,
    StaticRevocationLookup,
    create_verifiable_credential,
    create_verifiable_presentation,
    generate_ed25519_key,
    resolve_did_key,
    sign_ed25519,
    verify_ed25519,
    verify_verifiable_credential,
    verify_verifiable_presentation,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
TENANT = "tenant-test"
KEY_ID = "issuer-v1"


def _store() -> EphemeralKeyStore:
    return EphemeralKeyStore(testing_only=True)


def _issue(store: EphemeralKeyStore, **overrides: object) -> str:
    key = generate_ed25519_key(
        key_store=store,
        tenant_id=TENANT,
        key_id=KEY_ID,
    )
    arguments: dict[str, object] = {
        "key_store": store,
        "tenant_id": TENANT,
        "key_id": KEY_ID,
        "issuer": key.did,
        "subject": "did:example:agent-7",
        "audience": "palonexus-control-plane",
        "credential_id": "urn:uuid:credential-7",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
        "claims": {"role": "operator"},
    }
    arguments.update(overrides)
    return create_verifiable_credential(**arguments)  # type: ignore[arg-type]


def test_ed25519_did_key_generation_resolution_and_signing() -> None:
    with _store() as store:
        key = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id=KEY_ID,
        )
        resolved = resolve_did_key(key.did)
        signature = key.sign(
            b"bounded-message",
            key_store=store,
            tenant_id=TENANT,
            key_id=KEY_ID,
        )

    assert key.did.startswith("did:key:z6Mk")
    assert key.key_id == f"{key.did}#{key.did.removeprefix('did:key:')}"
    assert resolved == key
    assert verify_ed25519(key.did, b"bounded-message", signature)
    assert not verify_ed25519(key.did, b"changed", signature)
    Ed25519PublicKey.from_public_bytes(key.public_key).verify(
        signature,
        b"bounded-message",
    )
    assert copy.copy(key) is key
    assert pickle.loads(pickle.dumps(key)) == key


def test_key_generation_transfer_is_erased_and_signing_lease_closes() -> None:
    class TrackingStore:
        def __init__(self) -> None:
            self.inner = EphemeralKeyStore(testing_only=True)
            self.transferred: bytearray | None = None
            self.loaded_lease: Any = None

        @property
        def capabilities(self) -> Mapping[str, bool | str]:
            return self.inner.capabilities

        def store(
            self,
            *,
            tenant_id: str,
            key_id: str,
            value: bytearray,
        ) -> None:
            self.transferred = value
            self.inner.store(tenant_id=tenant_id, key_id=key_id, value=value)

        def load(
            self,
            *,
            tenant_id: str,
            key_id: str,
        ) -> AbstractContextManager[Any]:
            self.loaded_lease = self.inner.load(
                tenant_id=tenant_id,
                key_id=key_id,
            )
            return cast(AbstractContextManager[Any], self.loaded_lease)

        def delete(self, *, tenant_id: str, key_id: str) -> None:
            self.inner.delete(tenant_id=tenant_id, key_id=key_id)

    store = TrackingStore()
    key = generate_ed25519_key(
        key_store=store,
        tenant_id=TENANT,
        key_id=KEY_ID,
    )
    assert store.transferred == bytearray(32)
    key.sign(
        b"lease-closes",
        key_store=store,
        tenant_id=TENANT,
        key_id=KEY_ID,
    )
    assert store.loaded_lease.closed is True
    store.inner.close()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "did:key:",
        "did:key:xnot-base58btc",
        "did:key:z",
        "did:key:zQ3shnon-ed25519",
        "did:key:z6MkmvHjN2a6fH7qT7J3uUC9xCvg4hDfx",
        "did:key:z6MkwQpJtLhmoRieDFX4BGQ6HJDn3qLkG9BfY43pU1dAzu6C#fragment",
    ],
)
def test_did_key_rejects_malformed_noncanonical_or_non_ed25519(value: str) -> None:
    with pytest.raises(IdentityVerificationFailed):
        resolve_did_key(value)


def test_vc_round_trip_binds_all_registered_claims() -> None:
    with _store() as store:
        token = _issue(store)
        _, payload, _ = token.split(".")
        document = json.loads(
            __import__("base64").urlsafe_b64decode(payload + "==").decode()
        )
        credential = verify_verifiable_credential(
            token,
            expected_audience="palonexus-control-plane",
            now=NOW + timedelta(seconds=1),
            revocation_lookup=StaticRevocationLookup(),
        )

    assert credential.issuer.startswith("did:key:")
    assert credential.subject == "did:example:agent-7"
    assert credential.credential_id == "urn:uuid:credential-7"
    assert credential.audience == "palonexus-control-plane"
    assert credential.claims == {"role": "operator"}
    assert document["jti"] == document["vc"]["id"]
    assert document["iss"] == document["vc"]["issuer"]
    assert copy.deepcopy(credential) is credential
    assert pickle.loads(pickle.dumps(credential)) == credential


def test_vc_rejects_tamper_wrong_audience_expiry_and_revocation() -> None:
    with _store() as store:
        token = _issue(store)
    header, payload, signature = token.split(".")
    decoded = json.loads(
        __import__("base64").urlsafe_b64decode(payload + "==").decode()
    )
    decoded["sub"] = "did:example:attacker"
    tampered_payload = (
        __import__("base64")
        .urlsafe_b64encode(
            json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    for candidate, audience, now, revoked in (
        (
            f"{header}.{tampered_payload}.{signature}",
            "palonexus-control-plane",
            NOW,
            (),
        ),
        (token, "other-audience", NOW, ()),
        (token, "palonexus-control-plane", NOW + timedelta(hours=1), ()),
        (token, "palonexus-control-plane", NOW, ("urn:uuid:credential-7",)),
    ):
        with pytest.raises(IdentityVerificationFailed):
            verify_verifiable_credential(
                candidate,
                expected_audience=audience,
                now=now,
                revocation_lookup=StaticRevocationLookup(revoked_ids=revoked),
            )


def test_vc_rejects_revocation_lookup_failure_and_malformed_inputs() -> None:
    class BrokenLookup:
        def is_revoked(self, credential_id: str) -> bool:
            raise RuntimeError(f"secret:{credential_id}")

    with _store() as store:
        token = _issue(store)

    candidates = (
        token + "x",
        "a.b",
        "a.b.c",
        "A" * 65_537,
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.",
    )
    for candidate in candidates:
        with pytest.raises(IdentityVerificationFailed):
            verify_verifiable_credential(
                candidate,
                expected_audience="palonexus-control-plane",
                now=NOW,
                revocation_lookup=StaticRevocationLookup(),
            )
    with pytest.raises(IdentityVerificationFailed) as captured:
        verify_verifiable_credential(
            token,
            expected_audience="palonexus-control-plane",
            now=NOW,
            revocation_lookup=BrokenLookup(),
        )
    assert "secret" not in repr(captured.value)


@pytest.mark.parametrize(
    "variant",
    ["noncanonical-whitespace", "duplicate-key", "wrong-typ"],
)
def test_vc_rejects_noncanonical_duplicate_and_wrong_typ_even_when_resigned(
    variant: str,
) -> None:
    with _store() as store:
        token = _issue(store)
        header, payload, _ = token.split(".")
        header_json = __import__("base64").urlsafe_b64decode(header + "==")
        payload_json = __import__("base64").urlsafe_b64decode(payload + "==")
        if variant == "noncanonical-whitespace":
            candidate_header, candidate_payload = header_json, b" " + payload_json
        elif variant == "duplicate-key":
            candidate_header, candidate_payload = (
                header_json,
                payload_json.replace(
                    b'"sub":',
                    b'"sub":"did:example:duplicate","sub":',
                    1,
                ),
            )
        else:
            candidate_header, candidate_payload = (
                header_json.replace(b'"typ":"JWT"', b'"typ":"vc+jwt"'),
                payload_json,
            )
        encoded_header = (
            __import__("base64")
            .urlsafe_b64encode(candidate_header)
            .rstrip(b"=")
            .decode()
        )
        encoded_payload = (
            __import__("base64")
            .urlsafe_b64encode(candidate_payload)
            .rstrip(b"=")
            .decode()
        )
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature = sign_ed25519(
            signing_input,
            key_store=store,
            tenant_id=TENANT,
            key_id=KEY_ID,
        )
        candidate = (
            signing_input.decode()
            + "."
            + __import__("base64").urlsafe_b64encode(signature).rstrip(b"=").decode()
        )

    with pytest.raises(IdentityVerificationFailed):
        verify_verifiable_credential(
            candidate,
            expected_audience="palonexus-control-plane",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
        )


def test_vc_rejects_reserved_subject_claim_and_non_rfc3339_time() -> None:
    with _store() as store:
        with pytest.raises(IdentityVerificationFailed):
            _issue(store, claims={"id": "did:example:attacker"})
        with pytest.raises(IdentityVerificationFailed):
            _issue(store, issued_at="2026-07-27 12:00:00+00:00")


def test_vp_binds_audience_challenge_and_replay_atomically() -> None:
    with _store() as store:
        key = generate_ed25519_key(
            key_store=store,
            tenant_id=TENANT,
            key_id="holder-v1",
        )
        vc = _issue(store)
        presentation = create_verifiable_presentation(
            key_store=store,
            tenant_id=TENANT,
            key_id="holder-v1",
            holder=key.did,
            credentials=(vc,),
            audience="palonexus-control-plane",
            challenge="challenge-0123456789",
            presentation_id="urn:uuid:presentation-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        )

    replay = MemoryReplayStore()
    verified = verify_verifiable_presentation(
        presentation,
        expected_audience="palonexus-control-plane",
        expected_challenge="challenge-0123456789",
        now=NOW,
        revocation_lookup=StaticRevocationLookup(),
        replay_store=replay,
    )
    assert verified.holder == key.did
    assert verified.credentials[0].credential_id == "urn:uuid:credential-7"
    assert copy.copy(verified) is verified
    assert pickle.loads(pickle.dumps(verified)) == verified

    for audience, challenge in (
        ("other", "challenge-0123456789"),
        ("palonexus-control-plane", "wrong-challenge"),
        ("palonexus-control-plane", "challenge-0123456789"),
    ):
        with pytest.raises(IdentityVerificationFailed):
            verify_verifiable_presentation(
                presentation,
                expected_audience=audience,
                expected_challenge=challenge,
                now=NOW,
                revocation_lookup=StaticRevocationLookup(),
                replay_store=replay,
            )


def test_memory_replay_store_records_once_under_concurrency() -> None:
    replay = MemoryReplayStore()
    barrier = threading.Barrier(16)
    results: list[bool] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        result = replay.check_and_record(
            "urn:uuid:single-use",
            expires_at=NOW + timedelta(minutes=1),
        )
        with lock:
            results.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 15


def test_vc_supports_numeric_and_rfc3339_times_but_rejects_ambiguous_time() -> None:
    with _store() as store:
        numeric = _issue(
            store,
            issued_at=NOW.timestamp(),
            expires_at=(NOW + timedelta(minutes=1)).timestamp(),
            credential_id="urn:uuid:numeric",
        )
        textual = _issue(
            store,
            issued_at=NOW.isoformat().replace("+00:00", "Z"),
            expires_at=(NOW + timedelta(minutes=1)).isoformat(),
            credential_id="urn:uuid:textual",
        )
        for token in (numeric, textual):
            verify_verifiable_credential(
                token,
                expected_audience="palonexus-control-plane",
                now=NOW,
                revocation_lookup=StaticRevocationLookup(),
            )
        with pytest.raises(IdentityVerificationFailed):
            _issue(store, issued_at=True)
