# SPDX-License-Identifier: MIT
"""Canonical construction of protocol-v1 authorization attempts."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import weakref
from datetime import UTC, datetime
from typing import Any, Literal, Never, Self, cast

from . import _canonicalize as _canonical
from ._generated import protocol as _wire
from .context import (
    _new_identifier,
)
from .errors import ApprovalScopeMismatch, ModelValidationError
from .models import ActionRequest, ActionTarget, TaskContext

type ActionName = Literal[
    "shell:exec",
    "file:read",
    "file:write",
    "file:delete",
    "web:fetch",
    "mcp:call",
    "tool:invoke",
]
type SideEffect = Literal["read_only", "write", "destructive", "external"]

_CAPABILITY = object()
_STATE_LOCK = threading.RLock()


def _invalid() -> ModelValidationError:
    return ModelValidationError()


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
    buffer.clear()


def _execution_hash(kind: str, buffer: bytearray) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"palonexus.execution.v1\0")
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    digest.update(buffer)
    return digest.digest()


def _seal(
    key: bytes,
    *,
    domain: bytes,
    nonce: bytes,
    metadata: bytes,
    execution_digest: bytes,
) -> bytes:
    return hmac.digest(
        key,
        domain + b"\0" + nonce + b"\0" + metadata + b"\0" + execution_digest,
        "sha256",
    )


def _encode_execution(value: object) -> tuple[str, bytearray]:
    if value is None:
        return "none", bytearray()
    if isinstance(value, str):
        return "text", bytearray(value.encode("utf-8"))
    # Canonical serialization severs every mutable caller alias.
    return "json", bytearray(_canonical.canonical_json(value))


def _decode_execution(kind: str, buffer: bytearray) -> object:
    if kind == "none":
        return None
    if kind == "text":
        return bytes(buffer).decode("utf-8")
    if kind == "json":
        return _canonical.parse_json(bytes(buffer))
    raise _invalid()


class _ExecutionState:
    __slots__ = (
        "buffer",
        "closed",
        "execution_digest",
        "finalizer",
        "key",
        "kind",
        "lock",
        "metadata",
        "nonce",
        "seal",
    )

    def __init__(
        self,
        *,
        owner: object,
        key: bytes,
        kind: str,
        buffer: bytearray,
        nonce: bytes,
        metadata: bytes,
        domain: bytes,
    ) -> None:
        self.key = key
        self.kind = kind
        self.buffer = buffer
        self.nonce = nonce
        self.metadata = metadata
        self.execution_digest = _execution_hash(kind, buffer)
        self.seal = _seal(
            key,
            domain=domain,
            nonce=nonce,
            metadata=metadata,
            execution_digest=self.execution_digest,
        )
        self.closed = False
        self.lock = threading.RLock()
        self.finalizer = weakref.finalize(owner, _wipe, buffer)

    def verify(
        self,
        *,
        key: bytes,
        domain: bytes,
        metadata: bytes,
        require_open: bool = True,
    ) -> None:
        if not hmac.compare_digest(key, self.key):
            raise _invalid()
        expected = _seal(
            key,
            domain=domain,
            nonce=self.nonce,
            metadata=metadata,
            execution_digest=self.execution_digest,
        )
        if not hmac.compare_digest(metadata, self.metadata):
            raise _invalid()
        if not hmac.compare_digest(expected, self.seal):
            raise _invalid()
        if require_open:
            if self.closed:
                raise _invalid()
            current_digest = _execution_hash(self.kind, self.buffer)
            if not hmac.compare_digest(current_digest, self.execution_digest):
                raise _invalid()

    def close(self) -> None:
        with self.lock:
            if not self.closed:
                _wipe(self.buffer)
                self.closed = True
                self.finalizer.detach()

_TARGET_STATES: weakref.WeakKeyDictionary[_PreparedTarget, _ExecutionState]
_ACTION_STATES: weakref.WeakKeyDictionary[_PreparedAction, _ExecutionState]


class _OpaqueExecution:
    __slots__ = ("__weakref__",)
    _DOMAIN: bytes

    def __repr__(self) -> str:
        return f"{type(self).__name__}(opaque=True)"

    __str__ = __repr__

    def __copy__(self) -> Never:
        raise TypeError("prepared execution objects cannot be copied")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Never:
        raise TypeError("prepared execution objects cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("prepared execution objects cannot be serialized")

    def __reduce_ex__(self, protocol: object) -> Never:
        raise TypeError("prepared execution objects cannot be serialized")

    def __enter__(self) -> Self:
        state = self._state()
        self._verify_for(state.key)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> Literal[False]:
        self.close()
        return False

    def _state(self) -> _ExecutionState:
        raise NotImplementedError

    def consume(self) -> object:
        state = self._state()
        with state.lock:
            self._verify_for(state.key)
            value = _decode_execution(state.kind, state.buffer)
            state.close()
            return value

    def _verify_for(
        self,
        key: bytes,
        *,
        require_open: bool = True,
    ) -> _ExecutionState:
        raise NotImplementedError

    def close(self) -> None:
        self._state().close()


class _PreparedTarget(_OpaqueExecution):
    __slots__ = ("_resource_hash", "_target", "_target_nonce")
    _DOMAIN = b"palonexus.prepared-target.v1"
    _resource_hash: str
    _target: ActionTarget
    _target_nonce: bytes

    def __new__(
        cls,
        capability: object,
        *,
        key: bytes,
        target: ActionTarget,
        resource_hash: str,
        execution: object,
    ) -> Self:
        if capability is not _CAPABILITY:
            raise _invalid()
        instance = super().__new__(cls)
        object.__setattr__(instance, "_target", target)
        object.__setattr__(instance, "_resource_hash", resource_hash)
        nonce = secrets.token_bytes(16)
        object.__setattr__(instance, "_target_nonce", nonce)
        kind, buffer = _encode_execution(execution)
        metadata = _canonical.canonical_json(
            {
                "kind": target.kind,
                "service": target.service,
                "resource": target.resource,
                "resourceHash": resource_hash,
            }
        )
        state = _ExecutionState(
            owner=instance,
            key=key,
            kind=kind,
            buffer=buffer,
            nonce=nonce,
            metadata=metadata,
            domain=cls._DOMAIN,
        )
        with _STATE_LOCK:
            _TARGET_STATES[instance] = state
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("prepared targets are immutable")

    @property
    def target(self) -> ActionTarget:
        self._verify_for(self._state().key, require_open=False)
        return self._target

    @property
    def resource_hash(self) -> str:
        self._verify_for(self._state().key, require_open=False)
        return self._resource_hash

    def _state(self) -> _ExecutionState:
        try:
            with _STATE_LOCK:
                return _TARGET_STATES[self]
        except (KeyError, TypeError):
            raise _invalid() from None

    def _metadata(self) -> bytes:
        return _canonical.canonical_json(
            {
                "kind": self._target.kind,
                "service": self._target.service,
                "resource": self._target.resource,
                "resourceHash": self._resource_hash,
            }
        )

    def _verify_for(
        self,
        key: bytes,
        *,
        require_open: bool = True,
    ) -> _ExecutionState:
        state = self._state()
        with state.lock:
            state.verify(
                key=key,
                domain=self._DOMAIN,
                metadata=self._metadata(),
                require_open=require_open,
            )
        return state


class _PreparedAction(_OpaqueExecution):
    __slots__ = (
        "_client_scope_hash",
        "_request",
        "_target_nonce",
    )
    _DOMAIN = b"palonexus.prepared-action.v1"
    _client_scope_hash: str
    _request: _wire.ActionRequest
    _target_nonce: bytes

    def __new__(
        cls,
        capability: object,
        *,
        key: bytes,
        request: _wire.ActionRequest,
        client_scope_hash: str,
        target_nonce: bytes,
        kind: str,
        buffer: bytearray,
    ) -> Self:
        if capability is not _CAPABILITY:
            raise _invalid()
        instance = super().__new__(cls)
        object.__setattr__(instance, "_request", request)
        object.__setattr__(instance, "_client_scope_hash", client_scope_hash)
        object.__setattr__(instance, "_target_nonce", target_nonce)
        nonce = secrets.token_bytes(16)
        metadata = _canonical.canonical_json(
            {
                "request": request.to_dict(),
                "clientScopeHash": client_scope_hash,
                "targetNonce": target_nonce.hex(),
            }
        )
        state = _ExecutionState(
            owner=instance,
            key=key,
            kind=kind,
            buffer=buffer,
            nonce=nonce,
            metadata=metadata,
            domain=cls._DOMAIN,
        )
        with _STATE_LOCK:
            _ACTION_STATES[instance] = state
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("prepared actions are immutable")

    @property
    def request(self) -> _wire.ActionRequest:
        self._verify_for(self._state().key, require_open=False)
        return self._request

    @property
    def client_scope_hash(self) -> str:
        self._verify_for(self._state().key, require_open=False)
        return self._client_scope_hash

    def _state(self) -> _ExecutionState:
        try:
            with _STATE_LOCK:
                return _ACTION_STATES[self]
        except (KeyError, TypeError):
            raise _invalid() from None

    def _metadata(self) -> bytes:
        return _canonical.canonical_json(
            {
                "request": self._request.to_dict(),
                "clientScopeHash": self._client_scope_hash,
                "targetNonce": self._target_nonce.hex(),
            }
        )

    def _verify_for(
        self,
        key: bytes,
        *,
        require_open: bool = True,
    ) -> _ExecutionState:
        state = self._state()
        with state.lock:
            state.verify(
                key=key,
                domain=self._DOMAIN,
                metadata=self._metadata(),
                require_open=require_open,
            )
        return state


_TARGET_STATES = weakref.WeakKeyDictionary()
_ACTION_STATES = weakref.WeakKeyDictionary()


def _timestamp(clock: Any) -> _wire.RFC3339Timestamp:
    try:
        value = clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TypeError
        utc_value = value.astimezone(UTC)
        timespec = "microseconds" if utc_value.microsecond else "seconds"
        rendered = utc_value.isoformat(timespec=timespec)
        return _wire.RFC3339Timestamp(rendered.replace("+00:00", "Z"))
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise _invalid() from None


def _safe_text(value: str | None) -> _wire.SafeText | None:
    if value is None:
        return None
    try:
        return _wire.SafeText(value)
    except (TypeError, ValueError):
        raise _invalid() from None


class ActionRequestBuilder:
    """Build canonical protocol requests from sealed prepared resources."""

    __slots__ = ("_adapter", "_seal_key")

    def __init__(
        self,
        *,
        adapter_id: str,
        adapter_version: str,
        host_version: str,
    ) -> None:
        try:
            adapter = _wire.Adapter(
                id=adapter_id,
                version=_wire.SemanticVersion(adapter_version),
                host_version=_wire.SemanticVersion(host_version),
            )
            adapter.validate_structural()
        except (AttributeError, TypeError, ValueError):
            raise _invalid() from None
        self._adapter = adapter
        try:
            self._seal_key = secrets.token_bytes(32)
        except Exception:
            raise RuntimeError("preparation entropy is unavailable") from None

    def _new_id(self, kind: str) -> str:
        try:
            value = _new_identifier(kind)
            if not isinstance(value, str):
                raise TypeError
            return value
        except ModelValidationError:
            raise
        except Exception:
            raise _invalid() from None

    def prepare_path_target(
        self,
        *,
        service: str,
        path: str,
        cwd: str,
    ) -> _PreparedTarget:
        return self._prepared_target(
            kind="local-action",
            service=service,
            prepared=_canonical.prepare_path_resource(path, cwd=cwd),
        )

    def prepare_url_target(
        self,
        *,
        service: str,
        value: str,
        sensitive_query_keys: frozenset[str] = frozenset(),
    ) -> _PreparedTarget:
        return self._prepared_target(
            kind="local-action",
            service=service,
            prepared=_canonical.prepare_url_resource(
                value,
                sensitive_query_keys=sensitive_query_keys,
            ),
        )

    def prepare_shell_target(
        self,
        *,
        service: str,
        command: str,
        additional_sensitive_names: frozenset[str] = frozenset(),
    ) -> _PreparedTarget:
        return self._prepared_target(
            kind="local-action",
            service=service,
            prepared=_canonical.prepare_shell_resource(
                command,
                additional_sensitive_names=additional_sensitive_names,
            ),
        )

    def prepare_mcp_target(
        self,
        *,
        server: str,
        tool: str,
        tool_input: object,
    ) -> _PreparedTarget:
        return self._prepared_target(
            kind="mcp-tool",
            service=server,
            prepared=_canonical.prepare_mcp_resource(server, tool, tool_input),
        )

    def prepare_generic_target(self, target: ActionTarget) -> _PreparedTarget:
        try:
            checked = ActionTarget.model_validate(
                {
                    "kind": target.kind,
                    "service": target.service,
                    "resource": target.resource,
                }
            )
            resource = _canonical.PreparedResource(
                resource=_canonical._nfc(  # noqa: SLF001
                    checked.resource,
                    code="invalid_target_resource",
                ),
                execution=None,
            )
            return self._prepared_target(
                kind=checked.kind,
                service=checked.service,
                prepared=resource,
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
            _canonical.CanonicalizationError,
        ):
            raise _invalid() from None

    def _prepared_target(
        self,
        *,
        kind: str,
        service: str,
        prepared: _canonical.PreparedResource,
    ) -> _PreparedTarget:
        try:
            target_document = _canonical.build_target(
                kind=kind,
                service=service,
                prepared=prepared,
            )
            canonical = _canonical.validated_target(target_document)
            target = ActionTarget(
                kind=cast(Any, canonical["kind"]),
                service=canonical["service"],
                resource=canonical["resource"],
            )
            return _PreparedTarget(
                _CAPABILITY,
                key=self._seal_key,
                target=target,
                resource_hash=canonical["resourceHash"],
                execution=prepared.execution,
            )
        except (TypeError, ValueError, _canonical.CanonicalizationError):
            raise _invalid() from None

    def _checked_target(self, target: object) -> _PreparedTarget:
        if not isinstance(target, _PreparedTarget):
            raise _invalid()
        target._verify_for(self._seal_key)
        return target

    def new(
        self,
        *,
        action: ActionName,
        target: _PreparedTarget,
        side_effect: SideEffect,
        task_context: TaskContext | None = None,
        action_id: str | None = None,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> ActionRequest:
        checked_target = self._checked_target(target)
        if task_context is None:
            raise _invalid()
        bound = task_context
        try:
            checked_task = TaskContext.model_validate(
                {
                    "task_id": bound.task_id,
                    "session_id": bound.session_id,
                }
            )
            supplied = {
                "action": action_id,
                "correlation": correlation_id,
            }
            values = {
                kind: value if value is not None else self._new_id(kind)
                for kind, value in supplied.items()
            }
            values["request"] = self._new_id("request")
            values["idempotency"] = self._new_id("idempotency")
            # Namespaces differ, but a broken source that reuses the same ULID
            # payload across required fields still fails closed.
            suffixes = [
                values[kind].split("_", 1)[-1]
                for kind, value in {
                    **supplied,
                    "request": None,
                    "idempotency": None,
                }.items()
                if value is None
            ]
            if len(suffixes) != len(set(suffixes)):
                raise _invalid()
            return ActionRequest(
                action_id=values["action"],
                request_id=values["request"],
                correlation_id=values["correlation"],
                idempotency_key=values["idempotency"],
                action=action,
                target=checked_target.target,
                task=checked_task,
                side_effect=side_effect,
                causation_id=causation_id,
            )
        except ModelValidationError:
            raise
        except (AttributeError, TypeError, ValueError):
            raise _invalid() from None

    def build(
        self,
        intent: ActionRequest,
        *,
        prepared_target: _PreparedTarget | None = None,
        cwd: str | None = None,
        repository: str | None = None,
        tool_name: str | None = None,
        safe_display: str | None = None,
    ) -> _PreparedAction:
        try:
            checked = ActionRequest.model_validate(
                {
                    name: getattr(intent, name)
                    for name in type(intent).model_fields
                }
            )
            if checked.action_id is None or checked.request_id is None:
                raise _invalid()
            target = (
                self.prepare_generic_target(checked.target)
                if prepared_target is None
                else self._checked_target(prepared_target)
            )
            if target.target != checked.target:
                raise _invalid()
            target_document = {
                "kind": target.target.kind,
                "service": target.target.service,
                "resource": target.target.resource,
                "resourceHash": target.resource_hash,
            }
            canonical_target = _canonical.validated_target(target_document)
            context = _wire.ActionContext(
                cwd=_safe_text(cwd),
                repository=_safe_text(repository),
                tool_name=_safe_text(tool_name),
                safe_display=_safe_text(safe_display),
            )
            request = _wire.ActionRequest(
                schema_version=_wire.SchemaVersion("1"),
                action_id=_wire.ActionID(checked.action_id),
                request_id=_wire.RequestID(checked.request_id),
                correlation_id=_wire.CorrelationID(checked.correlation_id),
                idempotency_key=_wire.AuthorizationIdempotencyKey(
                    checked.idempotency_key
                ),
                adapter=self._adapter,
                task=_wire.TaskBinding(
                    task_id=_wire.TaskID(checked.task.task_id),
                    session_id=_wire.SessionID(checked.task.session_id),
                ),
                action=_wire.ActionName(checked.action),
                target=_wire.ActionTarget(
                    kind=_wire.TargetKind(canonical_target["kind"]),
                    service=canonical_target["service"],
                    resource=_wire.SafeText(canonical_target["resource"]),
                    resource_hash=_wire.SHA256Digest(
                        canonical_target["resourceHash"]
                    ),
                ),
                side_effect=_wire.SideEffect(checked.side_effect),
                occurred_at=_timestamp(lambda: datetime.now(UTC)),
                context=context,
                causation_id=(
                    None
                    if checked.causation_id is None
                    else _wire.CausationID(checked.causation_id)
                ),
                resume_from_approval_id=(
                    None
                    if checked.resume_from_approval_id is None
                    else _wire.ApprovalID(checked.resume_from_approval_id)
                ),
            )
            request.validate_structural()
            scope_hash = _canonical.client_scope_hash(request.to_dict())
            state = target._verify_for(self._seal_key)
            with state.lock:
                state.verify(
                    key=self._seal_key,
                    domain=target._DOMAIN,
                    metadata=target._metadata(),
                )
                buffer = bytearray(state.buffer)
                kind = state.kind
                state.close()
            return _PreparedAction(
                _CAPABILITY,
                key=self._seal_key,
                request=request,
                client_scope_hash=scope_hash,
                target_nonce=target._target_nonce,
                kind=kind,
                buffer=buffer,
            )
        except ModelValidationError:
            raise
        except (
            AttributeError,
            TypeError,
            ValueError,
            _canonical.CanonicalizationError,
        ):
            raise _invalid() from None

    def resume(
        self,
        original: _PreparedAction,
        current: _PreparedAction,
        *,
        prior_decision_id: str,
        approval_id: str,
    ) -> _PreparedAction:
        """Create one resumed attempt and atomically retire ``original``.

        Validation failure leaves the original envelope open and closes every
        temporary envelope. Success transfers execution ownership: the
        original is closed before the resumed envelope is returned.
        """
        resumed = self._prepare_resume(
            original,
            current,
            prior_decision_id=prior_decision_id,
            approval_id=approval_id,
        )
        try:
            self._commit_resume(original, current, resumed)
        except BaseException:
            resumed.close()
            raise
        return resumed

    def _restore_original_for_resume(
        self,
        request_document: object,
        *,
        client_scope_hash: str,
    ) -> _PreparedAction:
        """Restore only the authorization half of a checkpointed action.

        Framework adapters checkpoint protocol data, never an execution
        envelope. This validator recreates the sealed original required by the
        approval binding while deliberately restoring no executable value.
        """

        try:
            if not isinstance(request_document, dict):
                raise TypeError
            request = _wire.parse_action(request_document)
            request.validate_structural()
            if (
                request.adapter != self._adapter
                or request.resume_from_approval_id is not None
                or type(client_scope_hash) is not str
                or _canonical.client_scope_hash(request.to_dict())
                != client_scope_hash
            ):
                raise ValueError
            target_document = request.target.to_dict()
            canonical_target = _canonical.validated_target(target_document)
            if canonical_target["resourceHash"] != str(request.target.resource_hash):
                raise ValueError
            return _PreparedAction(
                _CAPABILITY,
                key=self._seal_key,
                request=request,
                client_scope_hash=client_scope_hash,
                target_nonce=secrets.token_bytes(16),
                kind=str(request.target.kind),
                buffer=bytearray(),
            )
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            _canonical.CanonicalizationError,
        ):
            raise _invalid() from None

    def _prepare_resume(
        self,
        original: _PreparedAction,
        current: _PreparedAction,
        *,
        prior_decision_id: str,
        approval_id: str,
    ) -> _PreparedAction:
        """Build a sealed resume candidate without retiring ``original``.

        This package-private phase exists so clients can obtain a fresh policy
        decision before committing execution ownership. The public ``resume``
        method above retains its original atomic-transfer contract.
        """
        if not isinstance(original, _PreparedAction) or not isinstance(
            current, _PreparedAction
        ) or current is original:
            raise _invalid()
        original._verify_for(self._seal_key)
        current._verify_for(self._seal_key)
        try:
            _wire.DecisionID(prior_decision_id)
            _wire.ApprovalID(approval_id)
            prior = original.request
            checked = current.request
            if (
                checked.action_id != prior.action_id
                or checked.correlation_id != prior.correlation_id
                or checked.task != prior.task
                or checked.adapter != prior.adapter
                or checked.action != prior.action
                or checked.target != prior.target
                or checked.side_effect != prior.side_effect
                or current.client_scope_hash != original.client_scope_hash
                or checked.request_id == prior.request_id
                or checked.idempotency_key == prior.idempotency_key
            ):
                raise ApprovalScopeMismatch(
                    request_id=prior.request_id,
                    decision_id=prior_decision_id,
                    correlation_id=prior.correlation_id,
                )
            resumed_request = _wire.ActionRequest(
                schema_version=checked.schema_version,
                action_id=checked.action_id,
                request_id=_wire.RequestID(self._new_id("request")),
                correlation_id=checked.correlation_id,
                idempotency_key=_wire.AuthorizationIdempotencyKey(
                    self._new_id("idempotency")
                ),
                adapter=checked.adapter,
                task=checked.task,
                action=checked.action,
                target=checked.target,
                side_effect=checked.side_effect,
                occurred_at=_timestamp(lambda: datetime.now(UTC)),
                context=checked.context,
                causation_id=_wire.CausationID(prior_decision_id),
                resume_from_approval_id=_wire.ApprovalID(approval_id),
            )
            resumed_request.validate_structural()
            if (
                resumed_request.request_id
                in {prior.request_id, checked.request_id}
                or resumed_request.idempotency_key
                in {prior.idempotency_key, checked.idempotency_key}
            ):
                raise _invalid()
            resumed_scope_hash = _canonical.client_scope_hash(
                resumed_request.to_dict()
            )
            if resumed_scope_hash != original.client_scope_hash:
                raise ApprovalScopeMismatch(
                    request_id=resumed_request.request_id,
                    decision_id=prior_decision_id,
                    correlation_id=resumed_request.correlation_id,
                )
            current_state = current._verify_for(self._seal_key)
            with current_state.lock:
                current._verify_for(self._seal_key)
                execution = bytearray(current_state.buffer)
                try:
                    resumed = _PreparedAction(
                        _CAPABILITY,
                        key=self._seal_key,
                        request=resumed_request,
                        client_scope_hash=resumed_scope_hash,
                        target_nonce=current._target_nonce,
                        kind=current_state.kind,
                        buffer=execution,
                    )
                except Exception:
                    _wipe(execution)
                    raise _invalid() from None
                return resumed
        except (ApprovalScopeMismatch, ModelValidationError):
            raise
        except (
            AttributeError,
            TypeError,
            ValueError,
            _canonical.CanonicalizationError,
        ):
            raise _invalid() from None

    def _commit_resume(
        self,
        original: _PreparedAction,
        current: _PreparedAction,
        resumed: _PreparedAction,
    ) -> None:
        """Atomically retire an original after its candidate is allowed."""

        if (
            not isinstance(original, _PreparedAction)
            or not isinstance(current, _PreparedAction)
            or not isinstance(resumed, _PreparedAction)
        ):
            raise _invalid()
        original_state = original._verify_for(self._seal_key)
        current_state = current._verify_for(self._seal_key)
        resumed._verify_for(self._seal_key)
        try:
            if (
                resumed.request.action_id != original.request.action_id
                or resumed.request.correlation_id != original.request.correlation_id
                or resumed.request.task != original.request.task
                or resumed.client_scope_hash != original.client_scope_hash
                or current.client_scope_hash != original.client_scope_hash
            ):
                raise _invalid()
            locks = sorted(
                (original_state, current_state),
                key=id,
            )
            with locks[0].lock, locks[1].lock:
                original._verify_for(self._seal_key)
                current._verify_for(self._seal_key)
                resumed._verify_for(self._seal_key)
                original_state.close()
                current_state.close()
        except ModelValidationError:
            raise
        except (AttributeError, TypeError, ValueError):
            raise _invalid() from None


__all__ = ["ActionRequestBuilder"]
