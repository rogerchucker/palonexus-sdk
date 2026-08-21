# SPDX-License-Identifier: MIT
"""Strict reusable developer and exact-action wire contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping, Set
from copy import deepcopy
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal, Never, Self, cast

import rfc8785
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic import ValidationError as _PydanticValidationError
from pydantic.config import ExtraValues

from ..errors import ModelValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@~-]{0,127}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9]*(?:[._:/-][a-z0-9]+)*$")
_DESCRIPTOR_VERSION = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,255}$")
_HARNESS_ADAPTER_CONTRACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_MAX_DEPTH = 64
_MAX_NODES = 100_000
_MAX_PROCESSABLE_BYTES = 1_048_576
_MAX_RULES = 1024
_MAX_CONSTRAINT_PROPERTIES = 1024


def _raise_validation() -> Never:
    raise ModelValidationError() from None


class _DeveloperContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="never",
        validate_default=True,
    )

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except _PydanticValidationError:
            _raise_validation()

    @model_validator(mode="before")
    @classmethod
    def _reject_wire_coercions(cls, value: object) -> object:
        if isinstance(value, Mapping):
            for field in ("issued_at", "not_before", "expires_at"):
                timestamp = value.get(field)
                if timestamp is not None and not isinstance(timestamp, (str, datetime)):
                    raise ValueError(f"{field} must be an RFC 3339 string or datetime")
            stack = list(value.values())
            while stack:
                item = stack.pop()
                if isinstance(item, (bytes, bytearray)):
                    raise ValueError("wire values must not contain bytes")
                if isinstance(item, Mapping):
                    stack.extend(item.values())
                elif isinstance(item, (list, tuple)):
                    stack.extend(item)
        return value

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate(
                obj,
                strict=strict,
                extra=extra,
                from_attributes=from_attributes,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except _PydanticValidationError:
            _raise_validation()

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = item
            return result

        def reject_constant(_value: str) -> None:
            raise ValueError("non-finite JSON number")

        try:
            raw = bytes(json_data) if isinstance(json_data, bytearray) else json_data
            encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
            if len(encoded) > _MAX_PROCESSABLE_BYTES:
                raise ValueError("JSON input exceeds the processable byte bound")
            parsed = json.loads(
                raw,
                object_pairs_hook=unique,
                parse_constant=reject_constant,
            )
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            _raise_validation()
        return cls.model_validate(
            parsed,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @classmethod
    def model_validate_strings(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate_strings(
                obj,
                strict=strict,
                extra=extra,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except (_PydanticValidationError, TypeError, ValueError):
            _raise_validation()

    @classmethod
    def model_construct(
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        _raise_validation()

    @classmethod
    def construct(cls, _fields_set: set[str] | None = None, **values: Any) -> Self:
        _raise_validation()

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        values = cast(dict[str, Any], _thaw(self.model_dump(mode="json")))
        if deep:
            values = deepcopy(values)
        if update is not None:
            try:
                values.update(update)
            except Exception:
                _raise_validation()
        return type(self).model_validate(values)

    def copy(
        self,
        *,
        include: Set[int]
        | Set[str]
        | Mapping[int, Any]
        | Mapping[str, Any]
        | None = None,
        exclude: Set[int]
        | Set[str]
        | Mapping[int, Any]
        | Mapping[str, Any]
        | None = None,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if include is not None or exclude is not None:
            _raise_validation()
        return self.model_copy(update=update, deep=deep)

    def __copy__(self) -> Self:
        return self.model_copy()

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        copied = self.model_copy(deep=True)
        if memo is not None:
            memo[id(self)] = copied
        return copied

    def __setattr__(self, name: str, value: Any) -> Never:
        _raise_validation()

    def __delattr__(self, name: str) -> Never:
        _raise_validation()


def _developer_id(value: str) -> str:
    if not _ID.fullmatch(value):
        raise ValueError("noncanonical ID")
    return value


def _canonical_name(value: str) -> str:
    if len(value) > 256 or not _NAME.fullmatch(value):
        raise ValueError("noncanonical name")
    return value


def _digest(value: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise ValueError("invalid SHA-256 digest")
    return value


def _base64url(value: str, *, size: int) -> str:
    if len(value) > 512 or not _BASE64URL.fullmatch(value):
        raise ValueError("invalid base64url")
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ValueError("invalid base64url") from error
    if len(decoded) != size:
        raise ValueError("invalid decoded size")
    canonical = urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if value != canonical:
        raise ValueError("base64url must use its canonical unpadded encoding")
    return value


def _preflight_json(value: object) -> None:
    stack: list[tuple[bool, object, int]] = [(True, value, 0)]
    active_containers: set[int] = set()
    nodes = 0
    processable_bytes = 0
    while stack:
        entering, item, depth = stack.pop()
        if not entering:
            active_containers.remove(id(item))
            continue
        nodes += 1
        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError("JSON exceeds bounds")
        if isinstance(item, Mapping):
            container_id = id(item)
            if container_id in active_containers:
                raise ValueError("JSON contains a cycle")
            active_containers.add(container_id)
            processable_bytes += 2
            stack.append((False, item, depth))
            children: list[object] = []
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON keys must be strings")
                processable_bytes += len(key.encode("utf-8")) + 3
                children.append(child)
            for child in reversed(children):
                stack.append((True, child, depth + 1))
        elif isinstance(item, (list, tuple)):
            container_id = id(item)
            if container_id in active_containers:
                raise ValueError("JSON contains a cycle")
            active_containers.add(container_id)
            processable_bytes += 2
            stack.append((False, item, depth))
            for child in reversed(item):
                stack.append((True, child, depth + 1))
        elif isinstance(item, str):
            processable_bytes += len(item.encode("utf-8")) + 2
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
            processable_bytes += 32
        elif item is None:
            processable_bytes += 4
        elif isinstance(item, bool):
            processable_bytes += 5
        elif isinstance(item, int):
            decimal_digits = max(1, (abs(item).bit_length() * 30_103) // 100_000 + 1)
            processable_bytes += decimal_digits + (1 if item < 0 else 0)
        else:
            raise ValueError("unsupported JSON value")
        if processable_bytes > _MAX_PROCESSABLE_BYTES:
            raise ValueError("JSON exceeds the maximum processable input bytes")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def developer_canonical_json_bytes(value: object) -> bytes:
    """Serialize a developer-v1 payload as RFC 8785 JCS UTF-8 bytes."""

    _preflight_json(value)
    try:
        return rfc8785.dumps(cast(Any, _thaw(value)))
    except (TypeError, ValueError, rfc8785.CanonicalizationError) as error:
        raise ValueError(
            "value is outside the RFC 8785 interoperable JSON domain"
        ) from error


def developer_payload_sha256(value: object) -> str:
    """Hash the exact RFC 8785 bytes used by developer-v1 payload contracts."""

    return hashlib.sha256(developer_canonical_json_bytes(value)).hexdigest()


def _canonical_json(value: object) -> str:
    return developer_canonical_json_bytes(value).decode("utf-8")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(child) for key, child in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


class Ed25519PublicJWK(_DeveloperContract):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str
    kid: str | None = None
    use: Literal["sig"] | None = None
    alg: Literal["EdDSA"] | None = None

    @field_validator("x")
    @classmethod
    def _x(cls, value: str) -> str:
        return _base64url(value, size=32)

    @field_validator("kid")
    @classmethod
    def _kid(cls, value: str | None) -> str | None:
        return None if value is None else _developer_id(value)


class DetachedProof(_DeveloperContract):
    alg: Literal["EdDSA"]
    key_thumbprint: str
    signature: str

    @field_validator("key_thumbprint")
    @classmethod
    def _thumbprint(cls, value: str) -> str:
        return _digest(value)

    @field_validator("signature")
    @classmethod
    def _signature(cls, value: str) -> str:
        return _base64url(value, size=64)


class DeveloperAgentRegistration(_DeveloperContract):
    schema_version: Literal["palonexus.developer-agent/v1"]
    name: str
    descriptor_digest: str
    public_key_jwk: Ed25519PublicJWK
    descriptor_version: str
    runtime_profile: Mapping[str, JsonValue]
    composition_digest: str
    harness_adapter_contracts: tuple[str, ...]
    not_before: AwareDatetime
    expires_at: AwareDatetime
    proof: DetachedProof

    _name = field_validator("name")(_canonical_name)
    _descriptor_digest = field_validator("descriptor_digest")(_digest)
    _composition_digest = field_validator("composition_digest")(_digest)

    @model_validator(mode="before")
    @classmethod
    def _preflight_runtime_profile(cls, value: object) -> object:
        if isinstance(value, Mapping) and "runtime_profile" in value:
            profile = value["runtime_profile"]
            if not isinstance(profile, Mapping) or not profile:
                raise ValueError("runtime_profile must be a non-empty object")
            _preflight_json(profile)
            _canonical_json(profile)
        return value

    @field_validator("descriptor_version")
    @classmethod
    def _descriptor_version(cls, value: str) -> str:
        if _DESCRIPTOR_VERSION.fullmatch(value) is None:
            raise ValueError("descriptor_version is not canonical")
        return value

    @field_validator("harness_adapter_contracts")
    @classmethod
    def _adapter_contracts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not 1 <= len(value) <= 64:
            raise ValueError("harness_adapter_contracts must contain 1 to 64 values")
        if len(set(value)) != len(value):
            raise ValueError("harness_adapter_contracts must be unique")
        if any(_HARNESS_ADAPTER_CONTRACT.fullmatch(item) is None for item in value):
            raise ValueError("harness_adapter_contracts contains a non-canonical value")
        return value

    @model_validator(mode="after")
    def _freeze_profile(self) -> Self:
        if self.expires_at <= self.not_before:
            raise ValueError("registration profile validity window is invalid")
        object.__setattr__(self, "runtime_profile", _freeze(self.runtime_profile))
        return self

    @field_serializer("runtime_profile")
    def _serialize_runtime_profile(
        self, value: Mapping[str, JsonValue]
    ) -> JsonValue:
        return cast(JsonValue, _thaw(value))


class RequestedCapabilityRule(_DeveloperContract):
    schema_version: Literal["palonexus.requested-capability/v1"]
    canonical_action: str
    resource: str
    constraints: Mapping[str, JsonValue]
    logical_target_id: str

    _canonical_fields = field_validator("canonical_action", "resource")(_canonical_name)
    _target = field_validator("logical_target_id")(_developer_id)

    @model_validator(mode="before")
    @classmethod
    def _preflight(cls, value: object) -> object:
        if isinstance(value, Mapping) and "constraints" in value:
            _preflight_json(value["constraints"])
            _canonical_json(value["constraints"])
            constraints = value["constraints"]
            if (
                isinstance(constraints, Mapping)
                and len(constraints) > _MAX_CONSTRAINT_PROPERTIES
            ):
                raise ValueError("constraints exceed the maximum property count")
        return value

    @model_validator(mode="after")
    def _freeze_constraints(self) -> Self:
        object.__setattr__(self, "constraints", _freeze(self.constraints))
        return self

    @field_serializer("constraints")
    def _serialize_constraints(self, value: Mapping[str, JsonValue]) -> JsonValue:
        return cast(JsonValue, _thaw(value))


class CapabilityCeilingRequest(_DeveloperContract):
    schema_version: Literal["palonexus.ceiling-request/v1"]
    agent_id: str
    agent_generation: int = Field(strict=True, gt=0, le=2_147_483_647)
    descriptor_digest: str
    rules: tuple[RequestedCapabilityRule, ...]

    _agent_id = field_validator("agent_id")(_developer_id)
    _descriptor_digest = field_validator("descriptor_digest")(_digest)

    @field_validator("rules")
    @classmethod
    def _rules(
        cls, value: tuple[RequestedCapabilityRule, ...]
    ) -> tuple[RequestedCapabilityRule, ...]:
        identities = tuple((rule.canonical_action, rule.resource) for rule in value)
        if (
            not value
            or len(value) > _MAX_RULES
            or len(identities) != len(set(identities))
        ):
            raise ValueError("rules must be nonempty and unique")
        return value


class CreateActionRequest(_DeveloperContract):
    schema_version: Literal["palonexus.action-request/v1"]
    agent_id: str
    agent_generation: int = Field(strict=True, gt=0, le=2_147_483_647)
    lease_id: str
    descriptor_digest: str
    input_digest: str
    canonical_action: str
    resource: str
    payload: JsonValue
    payload_digest: str
    idempotency_key: str

    _ids = field_validator("agent_id", "lease_id", "idempotency_key")(_developer_id)
    _digests = field_validator("descriptor_digest", "input_digest", "payload_digest")(
        _digest
    )
    _canonical_fields = field_validator("canonical_action", "resource")(_canonical_name)

    @model_validator(mode="before")
    @classmethod
    def _preflight(cls, value: object) -> object:
        if isinstance(value, Mapping) and "payload" in value:
            _preflight_json(value["payload"])
        return value

    @model_validator(mode="after")
    def _bind_payload(self) -> Self:
        canonical = _canonical_json(self.payload)
        if hashlib.sha256(canonical.encode()).hexdigest() != self.payload_digest:
            raise ValueError("payload is unbounded or does not match its digest")
        object.__setattr__(self, "payload", _freeze(self.payload))
        return self

    @field_serializer("payload")
    def _serialize_payload(self, value: JsonValue) -> JsonValue:
        return cast(JsonValue, _thaw(value))


class DeveloperAction(_DeveloperContract):
    schema_version: Literal["palonexus.action/v1"]
    run_id: str
    root_action_id: str
    action_id: str
    request: CreateActionRequest
    state: Literal[
        "pending",
        "approved",
        "denied",
        "executing",
        "completed",
        "failed",
        "expired",
        "canceled",
    ]

    _ids = field_validator("run_id", "root_action_id", "action_id")(_developer_id)


class TargetRegistrationRef(_DeveloperContract):
    schema_version: Literal["1"]
    registration_id: str
    version: int = Field(strict=True, gt=0, le=2_147_483_647)
    mapping_hash: str
    target: str
    target_kind: Literal[
        "tool",
        "mcp-server",
        "model",
        "agent",
        "filesystem",
        "memory",
        "artifact",
        "sandbox",
        "harness",
    ]
    canonical_action: str
    audience: str
    downstream_scope: str

    @field_validator(
        "registration_id",
        "target",
        "canonical_action",
        "audience",
        "downstream_scope",
    )
    @classmethod
    def _nonblank_fields(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError(
                "target registration fields must be nonblank canonical strings"
            )
        return value

    _mapping_hash = field_validator("mapping_hash")(_digest)


class ExactLeafAuthority(_DeveloperContract):
    schema_version: Literal["1"]
    delegation_id: str
    tenant_id: str
    agent_name: str
    accountable_owner: str
    run_requester: str
    run_sponsor: str
    parent_authority_ref: str
    run_id: str
    task_id: str
    root_action_id: str
    canonical_action: str
    exact_resource: str
    target: TargetRegistrationRef
    ceiling_approver: str
    action_approver: str | None
    approval_ref: str | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @field_validator(
        "delegation_id",
        "tenant_id",
        "agent_name",
        "accountable_owner",
        "run_requester",
        "run_sponsor",
        "parent_authority_ref",
        "run_id",
        "task_id",
        "root_action_id",
        "canonical_action",
        "exact_resource",
        "ceiling_approver",
    )
    @classmethod
    def _nonblank_fields(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError(
                "exact leaf authority fields must be nonblank canonical strings"
            )
        return value

    @field_validator("action_approver", "approval_ref")
    @classmethod
    def _optional_nonblank(cls, value: str | None) -> str | None:
        if value is not None and (not value or value != value.strip()):
            raise ValueError("optional exact leaf fields must be nonblank when present")
        return value

    @model_validator(mode="after")
    def _valid_leaf(self) -> Self:
        if (
            self.target.canonical_action != self.canonical_action
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("invalid exact leaf binding")
        return self


class ExactActionLeafAuthority(ExactLeafAuthority):
    # Exact-action v3 is the only published wire contract.
    schema_version: Literal["palonexus.exact-action/v3"]  # type: ignore[assignment]
    action_id: str
    payload_digest: str
    effect_idempotency_key: str
    agent_generation: int = Field(strict=True, gt=0, le=2_147_483_647)
    authority_profile: Literal["palonexus.exact-action/v3"]
    proxy_proof_key_thumbprint: str

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def _canonical_rfc3339(cls, value: object, info: Any) -> object:
        if not isinstance(value, str) or not _RFC3339.fullmatch(value):
            raise ValueError(
                f"{info.field_name} must use canonical uppercase RFC 3339 syntax"
            )
        return value

    _ids = field_validator("action_id", "effect_idempotency_key")(_developer_id)
    _digests = field_validator("payload_digest", "proxy_proof_key_thumbprint")(_digest)


__all__ = [
    "CapabilityCeilingRequest",
    "CreateActionRequest",
    "DetachedProof",
    "DeveloperAction",
    "DeveloperAgentRegistration",
    "Ed25519PublicJWK",
    "ExactActionLeafAuthority",
    "ExactLeafAuthority",
    "RequestedCapabilityRule",
    "developer_canonical_json_bytes",
    "developer_payload_sha256",
]
