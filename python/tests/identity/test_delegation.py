# SPDX-License-Identifier: MIT
"""Delegation-chain narrowing and accountability tests."""

from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime, timedelta

import pytest
from palonexus import EphemeralKeyStore
from palonexus.identity import (
    DidKey,
    IdentityVerificationFailed,
    StaticRevocationLookup,
    create_delegation,
    generate_ed25519_key,
    verify_delegation_chain,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
TENANT = "tenant-test"


def _key(store: EphemeralKeyStore, key_id: str) -> DidKey:
    return generate_ed25519_key(
        key_store=store,
        tenant_id=TENANT,
        key_id=key_id,
    )


def _delegation(
    store: EphemeralKeyStore,
    *,
    issuer_key_id: str,
    issuer: str,
    subject: str,
    credential_id: str,
    capabilities: tuple[str, ...],
    resources: tuple[str, ...],
    depth: int,
    expires_at: datetime,
    actor: str = "did:example:alice",
    agent: str = "did:example:agent-final",
) -> str:
    return create_delegation(
        key_store=store,
        tenant_id=TENANT,
        key_id=issuer_key_id,
        issuer=issuer,
        subject=subject,
        audience="palonexus-control-plane",
        credential_id=credential_id,
        actor=actor,
        agent=agent,
        capabilities=capabilities,
        resources=resources,
        remaining_depth=depth,
        issued_at=NOW,
        expires_at=expires_at,
    )


def test_delegation_chain_verifies_links_and_monotonic_narrowing() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        root = _key(store, "root")
        intermediate = _key(store, "intermediate")
        leaf = _key(store, "leaf")
        first = _delegation(
            store,
            issuer_key_id="root",
            issuer=root.did,
            subject=intermediate.did,
            credential_id="urn:uuid:delegation-1",
            capabilities=("tools:read", "tools:write"),
            resources=("cluster/*", "runbooks/*"),
            depth=2,
            expires_at=NOW + timedelta(minutes=30),
        )
        second = _delegation(
            store,
            issuer_key_id="intermediate",
            issuer=intermediate.did,
            subject=leaf.did,
            credential_id="urn:uuid:delegation-2",
            capabilities=("tools:read",),
            resources=("runbooks/*",),
            depth=1,
            expires_at=NOW + timedelta(minutes=10),
        )

    result = verify_delegation_chain(
        (first, second),
        root_issuer=root.did,
        expected_subject=leaf.did,
        expected_actor="did:example:alice",
        expected_agent="did:example:agent-final",
        expected_audience="palonexus-control-plane",
        required_capability="tools:read",
        required_resource="runbooks/*",
        now=NOW + timedelta(seconds=1),
        revocation_lookup=StaticRevocationLookup(),
    )
    assert result.subject == leaf.did
    assert result.capabilities == ("tools:read",)
    assert result.resources == ("runbooks/*",)
    assert result.remaining_depth == 1
    assert copy.deepcopy(result) is result
    with pytest.raises(TypeError):
        pickle.dumps(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capabilities", ("tools:read", "admin:*")),
        ("resources", ("runbooks/*", "secrets/*")),
        ("depth", 3),
        ("expires_at", NOW + timedelta(hours=1)),
        ("actor", "did:example:mallory"),
        ("agent", "did:example:other-agent"),
    ],
)
def test_delegation_chain_rejects_widening_or_accountability_change(
    field: str,
    value: object,
) -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        root = _key(store, "root")
        intermediate = _key(store, "intermediate")
        leaf = _key(store, "leaf")
        first = _delegation(
            store,
            issuer_key_id="root",
            issuer=root.did,
            subject=intermediate.did,
            credential_id="urn:uuid:first",
            capabilities=("tools:read",),
            resources=("runbooks/*",),
            depth=2,
            expires_at=NOW + timedelta(minutes=30),
        )
        arguments: dict[str, object] = {
            "issuer_key_id": "intermediate",
            "issuer": intermediate.did,
            "subject": leaf.did,
            "credential_id": "urn:uuid:second",
            "capabilities": ("tools:read",),
            "resources": ("runbooks/*",),
            "depth": 1,
            "expires_at": NOW + timedelta(minutes=10),
        }
        arguments[field] = value
        second = _delegation(store, **arguments)  # type: ignore[arg-type]

    with pytest.raises(IdentityVerificationFailed):
        verify_delegation_chain(
            (first, second),
            root_issuer=root.did,
            expected_subject=leaf.did,
            expected_actor="did:example:alice",
            expected_agent="did:example:agent-final",
            expected_audience="palonexus-control-plane",
            required_capability="tools:read",
            required_resource="runbooks/*",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
        )


def test_delegation_rejects_bad_link_cycle_length_expiry_and_missing_scope() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        root = _key(store, "root")
        leaf = _key(store, "leaf")
        token = _delegation(
            store,
            issuer_key_id="root",
            issuer=root.did,
            subject=leaf.did,
            credential_id="urn:uuid:delegation",
            capabilities=("tools:read",),
            resources=("runbooks/*",),
            depth=1,
            expires_at=NOW + timedelta(minutes=1),
        )

    invalid_chains = (
        (),
        (token, token),
        tuple(token for _ in range(17)),
    )
    for chain in invalid_chains:
        with pytest.raises(IdentityVerificationFailed):
            verify_delegation_chain(
                chain,
                root_issuer=root.did,
                expected_subject=leaf.did,
                expected_actor="did:example:alice",
                expected_agent="did:example:agent-final",
                expected_audience="palonexus-control-plane",
                required_capability="tools:read",
                required_resource="runbooks/*",
                now=NOW,
                revocation_lookup=StaticRevocationLookup(),
            )

    for now, capability, resource in (
        (NOW + timedelta(hours=1), "tools:read", "runbooks/*"),
        (NOW, "tools:write", "runbooks/*"),
        (NOW, "tools:read", "secrets/*"),
    ):
        with pytest.raises(IdentityVerificationFailed):
            verify_delegation_chain(
                (token,),
                root_issuer=root.did,
                expected_subject=leaf.did,
                expected_actor="did:example:alice",
                expected_agent="did:example:agent-final",
                expected_audience="palonexus-control-plane",
                required_capability=capability,
                required_resource=resource,
                now=now,
                revocation_lookup=StaticRevocationLookup(),
            )


def test_delegation_scopes_are_nonempty_exact_opaque_tokens() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        root = _key(store, "root")
        leaf = _key(store, "leaf")
        with pytest.raises(IdentityVerificationFailed):
            _delegation(
                store,
                issuer_key_id="root",
                issuer=root.did,
                subject=leaf.did,
                credential_id="urn:uuid:empty",
                capabilities=(),
                resources=("runbooks/*",),
                depth=1,
                expires_at=NOW + timedelta(minutes=1),
            )
        wildcard = _delegation(
            store,
            issuer_key_id="root",
            issuer=root.did,
            subject=leaf.did,
            credential_id="urn:uuid:wildcard",
            capabilities=("tools:*",),
            resources=("runbooks/*",),
            depth=1,
            expires_at=NOW + timedelta(minutes=1),
        )

    # Version 1 treats scope strings as exact opaque identifiers. A wildcard
    # character has no SDK-side expansion semantics; policy owns that meaning.
    with pytest.raises(IdentityVerificationFailed):
        verify_delegation_chain(
            (wildcard,),
            root_issuer=root.did,
            expected_subject=leaf.did,
            expected_actor="did:example:alice",
            expected_agent="did:example:agent-final",
            expected_audience="palonexus-control-plane",
            required_capability="tools:read",
            required_resource="runbooks/123",
            now=NOW,
            revocation_lookup=StaticRevocationLookup(),
        )
