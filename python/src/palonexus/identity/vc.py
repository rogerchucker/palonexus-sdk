# SPDX-License-Identifier: MIT
"""Bounded compact-JWT VC, VP, and delegation helpers."""

from __future__ import annotations

import base64
import json
import math
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, Self, cast

from .._canonicalize import canonical_json
from ..keystore import KeyStore
from .did import (
    IdentityVerificationFailed,
    resolve_did_key,
    sign_ed25519,
    verify_ed25519,
)

_MAX_TOKEN_BYTES = 65_536
_MAX_SEGMENT_BYTES = 49_152
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 512
_MAX_STRING_BYTES = 8_192
_MAX_CREDENTIALS = 16
_MAX_DELEGATIONS = 16
_MAX_SCOPE_ITEMS = 128
_BASE64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
_VC_TYPE = "VerifiableCredential"
_VP_TYPE = "VerifiablePresentation"
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


class RevocationLookup(Protocol):
    """Explicit fail-closed credential revocation boundary."""

    def is_revoked(self, credential_id: str) -> bool:
        """Return exactly ``True`` when revoked and ``False`` when current."""


class ReplayStore(Protocol):
    """Atomic presentation replay boundary."""

    def check_and_record(self, replay_id: str, *, expires_at: datetime) -> bool:
        """Atomically return true only when a fresh ID was recorded."""


@dataclass(frozen=True, slots=True)
class StaticRevocationLookup:
    """Immutable offline lookup useful for deterministic tests and examples."""

    revoked_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        values = _validated_string_tuple(self.revoked_ids, allow_empty=True)
        object.__setattr__(self, "revoked_ids", values)

    def is_revoked(self, credential_id: str) -> bool:
        return credential_id in self.revoked_ids


class MemoryReplayStore:
    """Thread-safe process-local replay store; never selected implicitly."""

    __slots__ = ("_entries", "_lock")

    def __init__(self) -> None:
        self._entries: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def check_and_record(self, replay_id: str, *, expires_at: datetime) -> bool:
        if (
            type(replay_id) is not str
            or type(expires_at) is not datetime
            or expires_at.tzinfo is None
        ):
            return False
        with self._lock:
            if replay_id in self._entries:
                return False
            self._entries[replay_id] = expires_at.astimezone(UTC)
            return True

    def __repr__(self) -> str:
        return "MemoryReplayStore(entries=[REDACTED])"

    def __copy__(self) -> Self:
        raise TypeError("Replay stores cannot be copied.")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        raise TypeError("Replay stores cannot be copied.")

    def __reduce__(self) -> str:
        raise TypeError("Replay stores cannot be serialized.")


def _freeze_json(value: object) -> object:
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        return tuple((key, _freeze_json(item)) for key, item in sorted(mapping.items()))
    if type(value) is list:
        return tuple(_freeze_json(item) for item in cast(list[object], value))
    return value


def _thaw_json(value: object) -> object:
    if type(value) is tuple:
        if all(
            type(item) is tuple and len(item) == 2 and type(item[0]) is str
            for item in value
        ):
            return {item[0]: _thaw_json(item[1]) for item in value}
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class VerifiedCredential:
    """Immutable verified VC projection with copy-on-read custom claims."""

    issuer: str
    subject: str
    audience: str
    credential_id: str
    issued_at: datetime
    expires_at: datetime
    _claims: object

    @property
    def claims(self) -> dict[str, object]:
        value = _thaw_json(self._claims)
        if type(value) is not dict:  # pragma: no cover - constructor invariant
            raise IdentityVerificationFailed() from None
        return value

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self


@dataclass(frozen=True, slots=True)
class VerifiedPresentation:
    """Immutable verified VP projection."""

    holder: str
    audience: str
    challenge: str
    presentation_id: str
    issued_at: datetime
    expires_at: datetime
    credentials: tuple[VerifiedCredential, ...]

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self


@dataclass(frozen=True, slots=True)
class VerifiedDelegation:
    """Effective authority after verifying an entire delegation chain."""

    issuer: str
    subject: str
    actor: str
    agent: str
    audience: str
    capabilities: tuple[str, ...]
    resources: tuple[str, ...]
    remaining_depth: int
    expires_at: datetime
    credential_ids: tuple[str, ...]

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self


def _valid_string(value: object, *, allow_empty: bool = False) -> str:
    try:
        if (
            type(value) is not str
            or (not value and not allow_empty)
            or len(value.encode("utf-8")) > _MAX_STRING_BYTES
            or "\x00" in value
        ):
            raise ValueError
        return value
    except Exception:
        raise IdentityVerificationFailed() from None


def _validated_string_tuple(
    value: object,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    try:
        if (
            type(value) not in (tuple, list)
            or len(cast(Sequence[object], value)) > _MAX_SCOPE_ITEMS
        ):
            raise ValueError
        sequence = cast(Sequence[object], value)
        result = tuple(_valid_string(item) for item in sequence)
        if (not result and not allow_empty) or len(set(result)) != len(result):
            raise ValueError
        return result
    except IdentityVerificationFailed:
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def _timestamp(value: object) -> int:
    try:
        if type(value) in (int, float):
            number = float(cast(int | float, value))
            if not math.isfinite(number):
                raise ValueError
            normalized = datetime.fromtimestamp(number, UTC)
        elif type(value) is datetime:
            if value.tzinfo is None:
                raise ValueError
            normalized = value.astimezone(UTC)
        elif type(value) is str:
            text = _valid_string(value)
            if _RFC3339.fullmatch(text) is None:
                raise ValueError
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            normalized = datetime.fromisoformat(text)
            if normalized.tzinfo is None:
                raise ValueError
            normalized = normalized.astimezone(UTC)
        else:
            raise ValueError
        timestamp = normalized.timestamp()
        if not math.isfinite(timestamp) or timestamp != math.floor(timestamp):
            raise ValueError
        return int(timestamp)
    except Exception:
        raise IdentityVerificationFailed() from None


def _trusted_now(value: object) -> datetime:
    timestamp = _timestamp(value)
    try:
        return datetime.fromtimestamp(timestamp, UTC)
    except Exception:
        raise IdentityVerificationFailed() from None


def _inspect_json(
    value: object,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
) -> object:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_JSON_ITEMS or depth > _MAX_JSON_DEPTH:
        raise IdentityVerificationFailed() from None
    if value is None or type(value) in (bool, int, str):
        if type(value) is str:
            _valid_string(value, allow_empty=True)
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise IdentityVerificationFailed() from None
        return value
    if type(value) is list:
        return [_inspect_json(item, depth=depth + 1, counter=counter) for item in value]
    if type(value) is dict:
        output: dict[str, object] = {}
        for key, item in value.items():
            validated_key = _valid_string(key)
            output[validated_key] = _inspect_json(
                item,
                depth=depth + 1,
                counter=counter,
            )
        return output
    raise IdentityVerificationFailed() from None


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: object) -> bytes:
    try:
        if (
            type(value) is not str
            or not value
            or len(value) > _MAX_SEGMENT_BYTES
            or "=" in value
            or any(character not in _BASE64URL_ALPHABET for character in value)
        ):
            raise ValueError
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
        if _b64encode(decoded) != value:
            raise ValueError
        return decoded
    except Exception:
        raise IdentityVerificationFailed() from None


def _json_loads(value: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    try:
        loaded = json.loads(
            value.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        inspected = _inspect_json(loaded)
        if type(inspected) is not dict:
            raise ValueError
        return inspected
    except IdentityVerificationFailed:
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def _encode_jwt(
    payload: dict[str, object],
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    issuer: str,
) -> str:
    resolved = resolve_did_key(issuer)
    header = {"alg": "EdDSA", "kid": resolved.key_id, "typ": "JWT"}
    inspected_payload = _inspect_json(payload)
    if type(inspected_payload) is not dict:
        raise IdentityVerificationFailed() from None
    signing_input = (
        _b64encode(canonical_json(header))
        + "."
        + _b64encode(canonical_json(inspected_payload))
    ).encode("ascii")
    signature = sign_ed25519(
        signing_input,
        key_store=key_store,
        tenant_id=tenant_id,
        key_id=key_id,
        expected_did=issuer,
    )
    token = signing_input.decode("ascii") + "." + _b64encode(signature)
    if len(token.encode("ascii")) > _MAX_TOKEN_BYTES:
        raise IdentityVerificationFailed() from None
    return token


def _decode_verified_jwt(token: object) -> dict[str, object]:
    try:
        if type(token) is not str or len(token.encode("ascii")) > _MAX_TOKEN_BYTES:
            raise ValueError
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError
        encoded_header, encoded_payload, encoded_signature = parts
        header = _json_loads(_b64decode(encoded_header))
        payload = _json_loads(_b64decode(encoded_payload))
        if canonical_json(header) != _b64decode(encoded_header) or canonical_json(
            payload
        ) != _b64decode(encoded_payload):
            raise ValueError
        signature = _b64decode(encoded_signature)
        if (
            header.keys() != {"alg", "kid", "typ"}
            or header["alg"] != "EdDSA"
            or header["typ"] != "JWT"
        ):
            raise ValueError
        issuer = _valid_string(payload.get("iss"))
        resolved = resolve_did_key(issuer)
        if header["kid"] != resolved.key_id:
            raise ValueError
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        if not verify_ed25519(issuer, signing_input, signature):
            raise ValueError
        return payload
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def _registered_claims(
    *,
    issuer: object,
    subject: object,
    audience: object,
    credential_id: object,
    issued_at: object,
    expires_at: object,
) -> tuple[dict[str, object], datetime, datetime]:
    validated_issuer = _valid_string(issuer)
    resolve_did_key(validated_issuer)
    validated_subject = _valid_string(subject)
    validated_audience = _valid_string(audience)
    validated_id = _valid_string(credential_id)
    issued = _timestamp(issued_at)
    expires = _timestamp(expires_at)
    if expires <= issued:
        raise IdentityVerificationFailed() from None
    return (
        {
            "aud": validated_audience,
            "exp": expires,
            "iat": issued,
            "iss": validated_issuer,
            "jti": validated_id,
            "nbf": issued,
            "sub": validated_subject,
        },
        datetime.fromtimestamp(issued, UTC),
        datetime.fromtimestamp(expires, UTC),
    )


def create_verifiable_credential(
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    issuer: str,
    subject: str,
    audience: str,
    credential_id: str,
    issued_at: datetime | int | float | str,
    expires_at: datetime | int | float | str,
    claims: Mapping[str, object],
) -> str:
    """Create a canonical compact EdDSA JWT VC."""

    try:
        registered, _, _ = _registered_claims(
            issuer=issuer,
            subject=subject,
            audience=audience,
            credential_id=credential_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        inspected_claims = _inspect_json(dict(claims))
        if type(inspected_claims) is not dict:
            raise ValueError
        if "id" in inspected_claims:
            raise ValueError
        credential_subject = {"id": registered["sub"], **inspected_claims}
        payload = {
            **registered,
            "vc": {
                "@context": [_VC_CONTEXT],
                "credentialSubject": credential_subject,
                "id": registered["jti"],
                "issuer": registered["iss"],
                "type": [_VC_TYPE],
            },
        }
        return _encode_jwt(
            payload,
            key_store=key_store,
            tenant_id=tenant_id,
            key_id=key_id,
            issuer=issuer,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def _verify_times_and_binding(
    payload: dict[str, object],
    *,
    expected_audience: object,
    now: object,
) -> tuple[datetime, datetime]:
    required = {"aud", "exp", "iat", "iss", "jti", "nbf", "sub"}
    if not required.issubset(payload):
        raise IdentityVerificationFailed() from None
    audience = _valid_string(payload["aud"])
    if audience != _valid_string(expected_audience):
        raise IdentityVerificationFailed() from None
    issued_timestamp = _timestamp(payload["iat"])
    not_before = _timestamp(payload["nbf"])
    expires_timestamp = _timestamp(payload["exp"])
    current = _trusted_now(now)
    current_timestamp = int(current.timestamp())
    if (
        not_before != issued_timestamp
        or expires_timestamp <= issued_timestamp
        or current_timestamp < not_before
        or current_timestamp >= expires_timestamp
    ):
        raise IdentityVerificationFailed() from None
    return (
        datetime.fromtimestamp(issued_timestamp, UTC),
        datetime.fromtimestamp(expires_timestamp, UTC),
    )


def _check_revocation(
    credential_id: str,
    lookup: RevocationLookup,
) -> None:
    try:
        revoked = lookup.is_revoked(credential_id)
        if type(revoked) is not bool or revoked:
            raise ValueError
    except Exception:
        raise IdentityVerificationFailed() from None


def verify_verifiable_credential(
    token: str,
    *,
    expected_audience: str,
    now: datetime | int | float | str,
    revocation_lookup: RevocationLookup,
) -> VerifiedCredential:
    """Verify signature, registered claims, VC shape, and revocation."""

    try:
        payload = _decode_verified_jwt(token)
        issued, expires = _verify_times_and_binding(
            payload,
            expected_audience=expected_audience,
            now=now,
        )
        issuer = _valid_string(payload["iss"])
        subject = _valid_string(payload["sub"])
        credential_id = _valid_string(payload["jti"])
        vc = payload.get("vc")
        if (
            type(vc) is not dict
            or vc.get("@context") != [_VC_CONTEXT]
            or vc.get("type") != [_VC_TYPE]
            or vc.get("id") != credential_id
            or vc.get("issuer") != issuer
            or type(vc.get("credentialSubject")) is not dict
        ):
            raise ValueError
        credential_subject = dict(vc["credentialSubject"])
        if credential_subject.pop("id", None) != subject:
            raise ValueError
        _check_revocation(credential_id, revocation_lookup)
        return VerifiedCredential(
            issuer=issuer,
            subject=subject,
            audience=_valid_string(payload["aud"]),
            credential_id=credential_id,
            issued_at=issued,
            expires_at=expires,
            _claims=_freeze_json(credential_subject),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def create_verifiable_presentation(
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    holder: str,
    credentials: Sequence[str],
    audience: str,
    challenge: str,
    presentation_id: str,
    issued_at: datetime | int | float | str,
    expires_at: datetime | int | float | str,
) -> str:
    """Create a holder-signed JWT VP bound to verifier audience and challenge."""

    try:
        if (
            type(credentials) not in (tuple, list)
            or not credentials
            or len(credentials) > _MAX_CREDENTIALS
        ):
            raise ValueError
        values = tuple(_valid_string(item) for item in credentials)
        registered, _, _ = _registered_claims(
            issuer=holder,
            subject=holder,
            audience=audience,
            credential_id=presentation_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        payload = {
            **registered,
            "nonce": _valid_string(challenge),
            "vp": {
                "@context": [_VC_CONTEXT],
                "type": [_VP_TYPE],
                "verifiableCredential": list(values),
            },
        }
        return _encode_jwt(
            payload,
            key_store=key_store,
            tenant_id=tenant_id,
            key_id=key_id,
            issuer=holder,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def verify_verifiable_presentation(
    token: str,
    *,
    expected_audience: str,
    expected_challenge: str,
    now: datetime | int | float | str,
    revocation_lookup: RevocationLookup,
    replay_store: ReplayStore,
) -> VerifiedPresentation:
    """Verify a VP and atomically record its presentation identifier."""

    try:
        payload = _decode_verified_jwt(token)
        issued, expires = _verify_times_and_binding(
            payload,
            expected_audience=expected_audience,
            now=now,
        )
        holder = _valid_string(payload["iss"])
        if payload["sub"] != holder:
            raise ValueError
        challenge = _valid_string(payload.get("nonce"))
        if challenge != _valid_string(expected_challenge):
            raise ValueError
        presentation_id = _valid_string(payload["jti"])
        vp = payload.get("vp")
        if (
            type(vp) is not dict
            or vp.get("@context") != [_VC_CONTEXT]
            or vp.get("type") != [_VP_TYPE]
            or type(vp.get("verifiableCredential")) is not list
            or not vp["verifiableCredential"]
            or len(vp["verifiableCredential"]) > _MAX_CREDENTIALS
        ):
            raise ValueError
        credentials = tuple(
            verify_verifiable_credential(
                _valid_string(item),
                expected_audience=expected_audience,
                now=now,
                revocation_lookup=revocation_lookup,
            )
            for item in vp["verifiableCredential"]
        )
        recorded = replay_store.check_and_record(
            presentation_id,
            expires_at=expires,
        )
        if recorded is not True:
            raise ValueError
        return VerifiedPresentation(
            holder=holder,
            audience=_valid_string(payload["aud"]),
            challenge=challenge,
            presentation_id=presentation_id,
            issued_at=issued,
            expires_at=expires,
            credentials=credentials,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def create_delegation(
    *,
    key_store: KeyStore,
    tenant_id: str,
    key_id: str,
    issuer: str,
    subject: str,
    audience: str,
    credential_id: str,
    actor: str,
    agent: str,
    capabilities: Sequence[str],
    resources: Sequence[str],
    remaining_depth: int,
    issued_at: datetime | int | float | str,
    expires_at: datetime | int | float | str,
) -> str:
    """Create one signed delegation VC."""

    try:
        if type(remaining_depth) is not int or not 0 <= remaining_depth <= 16:
            raise ValueError
        delegation = {
            "actor": _valid_string(actor),
            "agent": _valid_string(agent),
            "capabilities": list(_validated_string_tuple(capabilities)),
            "remainingDepth": remaining_depth,
            "resources": list(_validated_string_tuple(resources)),
        }
        return create_verifiable_credential(
            key_store=key_store,
            tenant_id=tenant_id,
            key_id=key_id,
            issuer=issuer,
            subject=subject,
            audience=audience,
            credential_id=credential_id,
            issued_at=issued_at,
            expires_at=expires_at,
            claims={"delegation": delegation},
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None


def verify_delegation_chain(
    chain: Sequence[str],
    *,
    root_issuer: str,
    expected_subject: str,
    expected_actor: str,
    expected_agent: str,
    expected_audience: str,
    required_capability: str,
    required_resource: str,
    now: datetime | int | float | str,
    revocation_lookup: RevocationLookup,
) -> VerifiedDelegation:
    """Verify every chain link and return its monotonically narrowed authority."""

    try:
        if (
            type(chain) not in (tuple, list)
            or not chain
            or len(chain) > _MAX_DELEGATIONS
        ):
            raise ValueError
        root = _valid_string(root_issuer)
        subject_expected = _valid_string(expected_subject)
        actor_expected = _valid_string(expected_actor)
        agent_expected = _valid_string(expected_agent)
        capability_required = _valid_string(required_capability)
        resource_required = _valid_string(required_resource)
        credentials = tuple(
            verify_verifiable_credential(
                _valid_string(token),
                expected_audience=expected_audience,
                now=now,
                revocation_lookup=revocation_lookup,
            )
            for token in chain
        )
        if credentials[0].issuer != root:
            raise ValueError
        seen = {root}
        previous_capabilities: set[str] | None = None
        previous_resources: set[str] | None = None
        previous_depth: int | None = None
        previous_expiry: datetime | None = None
        credential_ids: list[str] = []
        effective_capabilities: tuple[str, ...] = ()
        effective_resources: tuple[str, ...] = ()
        effective_depth = -1
        for index, credential in enumerate(credentials):
            if index and credential.issuer != credentials[index - 1].subject:
                raise ValueError
            if credential.subject in seen:
                raise ValueError
            seen.add(credential.subject)
            claims = credential.claims
            delegation = claims.get("delegation")
            if type(delegation) is not dict or claims.keys() != {"delegation"}:
                raise ValueError
            actor = _valid_string(delegation.get("actor"))
            agent = _valid_string(delegation.get("agent"))
            capabilities = _validated_string_tuple(delegation.get("capabilities"))
            resources = _validated_string_tuple(delegation.get("resources"))
            depth = delegation.get("remainingDepth")
            if type(depth) is not int or not 0 <= depth <= 16:
                raise ValueError
            if actor != actor_expected or agent != agent_expected:
                raise ValueError
            capability_set = set(capabilities)
            resource_set = set(resources)
            if previous_capabilities is not None and not capability_set.issubset(
                previous_capabilities
            ):
                raise ValueError
            if previous_resources is not None and not resource_set.issubset(
                previous_resources
            ):
                raise ValueError
            if previous_depth is not None and depth >= previous_depth:
                raise ValueError
            if previous_expiry is not None and credential.expires_at > previous_expiry:
                raise ValueError
            previous_capabilities = capability_set
            previous_resources = resource_set
            previous_depth = depth
            previous_expiry = credential.expires_at
            effective_capabilities = capabilities
            effective_resources = resources
            effective_depth = depth
            credential_ids.append(credential.credential_id)
        final = credentials[-1]
        if (
            final.subject != subject_expected
            or capability_required not in effective_capabilities
            or resource_required not in effective_resources
        ):
            raise ValueError
        return VerifiedDelegation(
            issuer=root,
            subject=final.subject,
            actor=actor_expected,
            agent=agent_expected,
            audience=_valid_string(expected_audience),
            capabilities=effective_capabilities,
            resources=effective_resources,
            remaining_depth=effective_depth,
            expires_at=final.expires_at,
            credential_ids=tuple(credential_ids),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IdentityVerificationFailed() from None
