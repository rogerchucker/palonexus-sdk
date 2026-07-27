# SPDX-License-Identifier: MIT
"""Stable, immutable value types for proposed PaloNexus actions."""

from __future__ import annotations

from collections.abc import Mapping, Set
from typing import Any, Literal, Never, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic import ValidationError as _PydanticValidationError
from pydantic.config import ExtraValues

from ._generated import protocol as _protocol
from .errors import ModelValidationError

_PLACEHOLDER_ACTION_ID = f"act_{'0' * 26}"
_PLACEHOLDER_REQUEST_ID = f"req_{'0' * 26}"
_PLACEHOLDER_RESOURCE_HASH = f"sha256:{'0' * 64}"
_PLACEHOLDER_OCCURRED_AT = "2000-01-01T00:00:00Z"

type _ActionName = Literal[
    "shell:exec",
    "file:read",
    "file:write",
    "file:delete",
    "web:fetch",
    "mcp:call",
    "tool:invoke",
]
type _TargetKind = Literal["local-action", "mcp-tool", "tool"]
type _SideEffect = Literal["read_only", "write", "destructive", "external"]


def _raise_model_validation_error() -> Never:
    raise ModelValidationError() from None


class _ProtocolValue(BaseModel):
    """Shared fail-closed configuration for public protocol wrappers."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    def __init__(self, **data: Any) -> None:
        failed = False
        try:
            super().__init__(**data)
        except _PydanticValidationError:
            failed = True
        if failed:
            _raise_model_validation_error()

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
        failed = False
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
            failed = True
        if failed:
            _raise_model_validation_error()
        raise AssertionError("unreachable")

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
        failed = False
        try:
            return super().model_validate_json(
                json_data,
                strict=strict,
                extra=extra,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except _PydanticValidationError:
            failed = True
        if failed:
            _raise_model_validation_error()
        raise AssertionError("unreachable")

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
        failed = False
        try:
            return super().model_validate_strings(
                obj,
                strict=strict,
                extra=extra,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except _PydanticValidationError:
            failed = True
        if failed:
            _raise_model_validation_error()
        raise AssertionError("unreachable")

    @classmethod
    def model_construct(
        cls,
        _fields_set: set[str] | None = None,
        **values: Any,
    ) -> Self:
        """Disable Pydantic's explicitly unchecked construction escape hatch."""

        _raise_model_validation_error()

    @classmethod
    def construct(
        cls,
        _fields_set: set[str] | None = None,
        **values: Any,
    ) -> Self:
        """Disable the deprecated alias for unchecked model construction."""

        _raise_model_validation_error()

    @classmethod
    def parse_obj(cls, obj: Any) -> Self:
        """Route the deprecated object parser through safe validation."""

        return cls.model_validate(obj)

    @classmethod
    def parse_raw(cls, *args: Any, **kwargs: Any) -> Self:
        """Disable deprecated raw parsing in favor of ``model_validate_json``."""

        _raise_model_validation_error()

    @classmethod
    def parse_file(cls, *args: Any, **kwargs: Any) -> Self:
        """Disable deprecated file parsing and implicit file access."""

        _raise_model_validation_error()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a fully revalidated copy; updates are never trusted."""

        values = {name: getattr(self, name) for name in type(self).model_fields}
        failed = False
        if update is not None:
            try:
                values.update(update)
            except Exception:
                failed = True
        if failed:
            _raise_model_validation_error()
        return type(self).model_validate(values)

    def copy(
        self,
        *,
        include: (
            Set[int] | Set[str] | Mapping[int, Any] | Mapping[str, Any] | None
        ) = None,
        exclude: (
            Set[int] | Set[str] | Mapping[int, Any] | Mapping[str, Any] | None
        ) = None,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Route the deprecated copy API through complete revalidation."""

        if include is not None or exclude is not None:
            _raise_model_validation_error()
        return self.model_copy(update=update, deep=deep)

    def __copy__(self) -> Self:
        return self.model_copy()

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.model_copy(deep=True)

    def __setattr__(self, name: str, value: Any) -> Never:
        _raise_model_validation_error()

    def __delattr__(self, name: str) -> Never:
        _raise_model_validation_error()

    def _safe_repr_items(self) -> tuple[tuple[str, object], ...]:
        return ()

    def __repr__(self) -> str:
        rendered = ", ".join(
            f"{name}={value!r}" for name, value in self._safe_repr_items()
        )
        return f"{type(self).__name__}({rendered})"

    def __str__(self) -> str:
        return repr(self)


class ActionTarget(_ProtocolValue):
    """Client-visible destination of a proposed action.

    The canonical builder computes ``resourceHash`` from ``resource``. Keeping
    that derived field out of this value prevents callers from supplying a hash
    that disagrees with the resource they are authorizing.
    """

    kind: _TargetKind
    service: str = Field(repr=False)
    resource: str = Field(repr=False)

    def _safe_repr_items(self) -> tuple[tuple[str, object], ...]:
        return (("kind", self.kind),)

    @model_validator(mode="after")
    def _validate_protocol_fragment(self) -> Self:
        target = _protocol.ActionTarget(
            kind=_protocol.TargetKind(self.kind),
            service=self.service,
            resource=_protocol.SafeText(self.resource),
            resource_hash=_protocol.SHA256Digest(_PLACEHOLDER_RESOURCE_HASH),
        )
        target.validate_structural()
        return self

    @classmethod
    def from_protocol(cls, value: _protocol.ActionTarget) -> Self:
        """Create a public target after revalidating a generated wire value."""

        failed = False
        try:
            value.validate_structural()
            kind = _protocol.TargetKind(str(value.kind)).value
            service = value.service
            resource = str(value.resource)
        except (AttributeError, TypeError, ValueError):
            failed = True
        if failed:
            _raise_model_validation_error()
        return cls(
            kind=cast(_TargetKind, kind),
            service=service,
            resource=resource,
        )


class TaskContext(_ProtocolValue):
    """Immutable task and session identifiers carried by an action."""

    task_id: str
    session_id: str

    def _safe_repr_items(self) -> tuple[tuple[str, object], ...]:
        return (
            ("task_id", self.task_id),
            ("session_id", self.session_id),
        )

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str) -> str:
        return str(_protocol.TaskID(value))

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, value: str) -> str:
        return str(_protocol.SessionID(value))

    @classmethod
    def from_protocol(cls, value: _protocol.TaskBinding) -> Self:
        """Create a public task context from a generated wire value."""

        failed = False
        try:
            value.validate_structural()
            task_id = str(value.task_id)
            session_id = str(value.session_id)
        except (AttributeError, TypeError, ValueError):
            failed = True
        if failed:
            _raise_model_validation_error()
        return cls(task_id=task_id, session_id=session_id)


class ActionRequest(_ProtocolValue):
    """Client-visible immutable action intent.

    ``action_id`` and ``request_id`` may be absent only before the canonical
    request builder assigns them. All caller-supplied identifiers are validated
    against the generated protocol definitions.
    """

    action: _ActionName
    target: ActionTarget = Field(repr=False)
    task: TaskContext
    side_effect: _SideEffect
    correlation_id: str
    idempotency_key: str
    action_id: str | None = None
    request_id: str | None = None
    causation_id: str | None = None
    resume_from_approval_id: str | None = None

    def _safe_repr_items(self) -> tuple[tuple[str, object], ...]:
        return (
            ("action", self.action),
            ("side_effect", self.side_effect),
            ("action_id", self.action_id),
            ("request_id", self.request_id),
            ("correlation_id", self.correlation_id),
        )

    @field_validator("action_id")
    @classmethod
    def _validate_action_id(cls, value: str | None) -> str | None:
        return None if value is None else str(_protocol.ActionID(value))

    @field_validator("request_id")
    @classmethod
    def _validate_request_id(cls, value: str | None) -> str | None:
        return None if value is None else str(_protocol.RequestID(value))

    @field_validator("correlation_id")
    @classmethod
    def _validate_correlation_id(cls, value: str) -> str:
        return str(_protocol.CorrelationID(value))

    @field_validator("idempotency_key")
    @classmethod
    def _validate_idempotency_key(cls, value: str) -> str:
        return str(_protocol.AuthorizationIdempotencyKey(value))

    @field_validator("causation_id")
    @classmethod
    def _validate_causation_id(cls, value: str | None) -> str | None:
        return None if value is None else str(_protocol.CausationID(value))

    @field_validator("resume_from_approval_id")
    @classmethod
    def _validate_resume_approval_id(cls, value: str | None) -> str | None:
        return None if value is None else str(_protocol.ApprovalID(value))

    @model_validator(mode="after")
    def _validate_protocol_document_shape(self) -> Self:
        wire_request = _protocol.ActionRequest(
            schema_version=_protocol.SchemaVersion("1"),
            action_id=_protocol.ActionID(self.action_id or _PLACEHOLDER_ACTION_ID),
            request_id=_protocol.RequestID(self.request_id or _PLACEHOLDER_REQUEST_ID),
            correlation_id=_protocol.CorrelationID(self.correlation_id),
            idempotency_key=_protocol.AuthorizationIdempotencyKey(self.idempotency_key),
            adapter=_protocol.Adapter(
                id="python-sdk",
                version=_protocol.SemanticVersion("0.0.0"),
                host_version=_protocol.SemanticVersion("3.12.0"),
            ),
            task=_protocol.TaskBinding(
                task_id=_protocol.TaskID(self.task.task_id),
                session_id=_protocol.SessionID(self.task.session_id),
            ),
            action=_protocol.ActionName(self.action),
            target=_protocol.ActionTarget(
                kind=_protocol.TargetKind(self.target.kind),
                service=self.target.service,
                resource=_protocol.SafeText(self.target.resource),
                resource_hash=_protocol.SHA256Digest(_PLACEHOLDER_RESOURCE_HASH),
            ),
            side_effect=_protocol.SideEffect(self.side_effect),
            occurred_at=_protocol.RFC3339Timestamp(_PLACEHOLDER_OCCURRED_AT),
            context=_protocol.ActionContext(),
            causation_id=(
                None
                if self.causation_id is None
                else _protocol.CausationID(self.causation_id)
            ),
            resume_from_approval_id=(
                None
                if self.resume_from_approval_id is None
                else _protocol.ApprovalID(self.resume_from_approval_id)
            ),
        )
        wire_request.validate_structural()
        return self

    @classmethod
    def from_protocol(cls, value: _protocol.ActionRequest) -> Self:
        """Create a public action after revalidating a generated wire value."""

        failed = False
        try:
            value.validate_structural()
            action = _protocol.ActionName(str(value.action)).value
            side_effect = _protocol.SideEffect(str(value.side_effect)).value
        except (AttributeError, TypeError, ValueError):
            failed = True
        if failed:
            _raise_model_validation_error()
        return cls(
            action_id=str(value.action_id),
            request_id=str(value.request_id),
            correlation_id=str(value.correlation_id),
            idempotency_key=str(value.idempotency_key),
            action=cast(_ActionName, action),
            target=ActionTarget.from_protocol(value.target),
            task=TaskContext.from_protocol(value.task),
            side_effect=cast(_SideEffect, side_effect),
            causation_id=(
                None if value.causation_id is None else str(value.causation_id)
            ),
            resume_from_approval_id=(
                None
                if value.resume_from_approval_id is None
                else str(value.resume_from_approval_id)
            ),
        )


DecisionOutcome = _protocol.DecisionOutcome

__all__ = [
    "ActionRequest",
    "ActionTarget",
    "DecisionOutcome",
    "TaskContext",
]
