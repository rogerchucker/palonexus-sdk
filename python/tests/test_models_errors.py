# SPDX-License-Identifier: MIT
"""Contract tests for the first stable Python SDK value types."""

from __future__ import annotations

import copy
import json
import pickle
import traceback
from collections.abc import Callable
from typing import Any, Final, cast

import palonexus
import pytest
from palonexus import (
    ActionRequest,
    ActionTarget,
    ApprovalExpired,
    ApprovalRequired,
    ApprovalScopeMismatch,
    AuthenticationFailed,
    AuthorizationUnavailable,
    CredentialRevoked,
    DecisionOutcome,
    IdempotencyConflict,
    InvalidDecision,
    InvalidRequest,
    MissingIdentity,
    ModelValidationError,
    PaloNexusError,
    PolicyDenied,
    TaskContext,
    UnsupportedProtocol,
)
from palonexus._generated import protocol as generated

_ULID: Final = "0" * 26
ACTION_ID: Final = f"act_{_ULID}"
REQUEST_ID: Final = f"req_{_ULID}"
DECISION_ID: Final = f"dec_{_ULID}"
CORRELATION_ID: Final = f"corr_{_ULID}"
IDEMPOTENCY_KEY: Final = f"authz_{_ULID}"
TASK_ID: Final = f"task_{_ULID}"
SESSION_ID: Final = f"session_{_ULID}"
APPROVAL_ID: Final = f"apr_{_ULID}"
CAUSATION_ID: Final = f"cause_{_ULID}"
RESOURCE_HASH: Final = f"sha256:{'0' * 64}"


def _target(**changes: object) -> ActionTarget:
    values: dict[str, object] = {
        "kind": "tool",
        "service": "inventory-api",
        "resource": "inventory-api:/items/42",
    }
    values.update(changes)
    return ActionTarget.model_validate(values)


def _task(**changes: object) -> TaskContext:
    values: dict[str, object] = {
        "task_id": TASK_ID,
        "session_id": SESSION_ID,
    }
    values.update(changes)
    return TaskContext.model_validate(values)


def _request(**changes: object) -> ActionRequest:
    values: dict[str, object] = {
        "action_id": ACTION_ID,
        "request_id": REQUEST_ID,
        "correlation_id": CORRELATION_ID,
        "idempotency_key": IDEMPOTENCY_KEY,
        "action": "tool:invoke",
        "target": _target(),
        "task": _task(),
        "side_effect": "read_only",
    }
    values.update(changes)
    return ActionRequest.model_validate(values)


def test_public_models_preserve_the_approved_client_visible_fields() -> None:
    request = _request()

    assert request.action_id == ACTION_ID
    assert request.request_id == REQUEST_ID
    assert request.correlation_id == CORRELATION_ID
    assert request.idempotency_key == IDEMPOTENCY_KEY
    assert request.action == "tool:invoke"
    assert request.target == _target()
    assert request.task == _task()
    assert request.side_effect == "read_only"


def test_request_ids_may_be_deferred_to_the_canonical_builder() -> None:
    request = _request(action_id=None, request_id=None)

    assert request.action_id is None
    assert request.request_id is None


def test_optional_causation_and_resume_ids_are_propagated() -> None:
    request = _request(
        causation_id=CAUSATION_ID,
        resume_from_approval_id=APPROVAL_ID,
    )

    assert request.causation_id == CAUSATION_ID
    assert request.resume_from_approval_id == APPROVAL_ID


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    [
        (_target, "kind", 1),
        (_target, "service", 1),
        (_target, "resource", 1),
        (_task, "task_id", 1),
        (_task, "session_id", 1),
        (_request, "correlation_id", 1),
        (_request, "idempotency_key", 1),
        (_request, "action", 1),
        (_request, "side_effect", 1),
    ],
)
def test_models_do_not_coerce_scalar_inputs(
    factory: object, field: str, value: object
) -> None:
    callable_factory = cast(Any, factory)
    with pytest.raises(ModelValidationError):
        callable_factory(**{field: value})


@pytest.mark.parametrize("factory", [_target, _task, _request])
def test_models_forbid_unknown_fields(factory: object) -> None:
    callable_factory = cast(Any, factory)
    with pytest.raises(ModelValidationError):
        callable_factory(unknown="must-not-be-ignored")


@pytest.mark.parametrize("value", ["host-tool", "TOOL", "mcp_tool"])
def test_target_kind_uses_the_generated_protocol_vocabulary(value: str) -> None:
    with pytest.raises(ModelValidationError):
        _target(kind=value)


@pytest.mark.parametrize("value", ["inventory:read", "tool.invoke", "unknown"])
def test_action_uses_the_generated_protocol_vocabulary(value: str) -> None:
    with pytest.raises(ModelValidationError):
        _request(action=value)


def test_structural_action_target_pairing_matches_the_generated_schema() -> None:
    with pytest.raises(ModelValidationError):
        _request(action="shell:exec", target=_target(kind="tool"))


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    [
        (_target, "resource", "inventory-api:/../secret"),
        (_task, "task_id", "task_not-a-protocol-id"),
        (_request, "request_id", "req_not-a-protocol-id"),
        (_request, "correlation_id", "corr_not-a-protocol-id"),
        (_request, "idempotency_key", "authz_not-a-protocol-id"),
        (_request, "causation_id", "cause_not-a-protocol-id"),
        (_request, "resume_from_approval_id", "apr_not-a-protocol-id"),
    ],
)
def test_scalar_constraints_are_owned_by_generated_protocol_types(
    factory: object, field: str, value: str
) -> None:
    callable_factory = cast(Any, factory)
    with pytest.raises(ModelValidationError):
        callable_factory(**{field: value})


def test_models_are_frozen_at_every_public_nesting_level() -> None:
    request = _request()

    with pytest.raises(ModelValidationError):
        setattr(request, "action", "web:fetch")
    with pytest.raises(ModelValidationError):
        setattr(request.target, "service", "other-service")
    with pytest.raises(ModelValidationError):
        setattr(request.task, "task_id", f"task_{'1' * 26}")


def test_model_copy_revalidates_updates_and_rejects_unknown_fields() -> None:
    request = _request()

    updated = request.model_copy(update={"side_effect": "write"})
    assert updated.side_effect == "write"
    assert updated is not request

    for update in (
        {"side_effect": 1},
        {"unknown": "Bearer sk-copy-secret"},
        {
            "target": {
                "kind": "invalid-kind",
                "service": "inventory-api",
                "resource": "prompt=ignore command=rm-rf",
            }
        },
    ):
        with pytest.raises(ModelValidationError) as caught:
            request.model_copy(update=update)
        assert "sk-copy-secret" not in str(caught.value)
        assert "ignore" not in repr(caught.value)


def test_model_copy_revalidates_tampered_nested_instances() -> None:
    target = _target()
    object.__setattr__(target, "kind", "invalid-kind")
    request = _request()
    object.__setattr__(request, "target", target)

    with pytest.raises(ModelValidationError):
        request.model_copy()


def test_unsafe_model_construction_is_disabled() -> None:
    with pytest.raises(ModelValidationError):
        ActionTarget.model_construct(
            kind="invalid-kind",
            service="Bearer sk-construct-secret",
            resource="https://private.example",
        )

    with pytest.raises(ModelValidationError):
        ActionTarget.construct(
            kind="invalid-kind",
            service="Bearer sk-construct-secret",
            resource="https://private.example",
        )


def test_python_copy_operations_revalidate_models() -> None:
    request = _request()

    shallow = copy.copy(request)
    deep = copy.deepcopy(request)

    assert shallow == request
    assert deep == request
    assert shallow is not request
    assert deep is not request


def test_public_model_rendering_redacts_resource_and_nested_values() -> None:
    raw_material = (
        "Bearer sk-render-secret https://private.example "
        "prompt=ignore-guard command=rm-rf"
    )
    target = _target(resource=raw_material)
    request = _request(target=target)

    for model in (target, request):
        for rendered in (str(model), repr(model)):
            assert raw_material not in rendered
            assert "sk-render-secret" not in rendered
            assert "private.example" not in rendered
            assert "ignore-guard" not in rendered
            assert "rm-rf" not in rendered


def test_public_validation_entrypoints_raise_only_safe_typed_errors() -> None:
    raw_material = (
        "Bearer sk-validation-secret https://private.example "
        "prompt=ignore-guard command=rm-rf"
    )
    invalid = {
        "kind": "invalid-kind",
        "service": "inventory-api",
        "resource": raw_material,
        "rawPayload": raw_material,
    }

    entrypoints: tuple[Callable[[], object], ...] = (
        lambda: cast(Any, ActionTarget)(**invalid),
        lambda: ActionTarget.model_validate(invalid),
        lambda: ActionTarget.model_validate_json(json.dumps(invalid)),
        lambda: ActionTarget.model_validate_strings(invalid),
    )
    for entrypoint in entrypoints:
        with pytest.raises(ModelValidationError) as caught:
            entrypoint()
        error = caught.value
        assert not hasattr(error, "errors")
        assert not hasattr(error, "json")
        for rendered in (str(error), repr(error)):
            assert "sk-validation-secret" not in rendered
            assert "private.example" not in rendered
            assert "ignore-guard" not in rendered
            assert "rm-rf" not in rendered
        assert error.__cause__ is None
        assert error.__context__ is None


def test_pydantic_config_hides_input_in_direct_core_error_strings() -> None:
    assert ActionTarget.model_config["hide_input_in_errors"] is True


def test_wrappers_accept_the_corresponding_generated_structural_types() -> None:
    generated_target = generated.ActionTarget(
        kind=generated.TargetKind.TOOL,
        service="inventory-api",
        resource=generated.SafeText("inventory-api:/items/42"),
        resource_hash=generated.SHA256Digest(RESOURCE_HASH),
    )
    generated_task = generated.TaskBinding(
        task_id=generated.TaskID(TASK_ID),
        session_id=generated.SessionID(SESSION_ID),
    )
    generated_request = generated.ActionRequest(
        schema_version=generated.SchemaVersion("1"),
        action_id=generated.ActionID(ACTION_ID),
        request_id=generated.RequestID(REQUEST_ID),
        correlation_id=generated.CorrelationID(CORRELATION_ID),
        idempotency_key=generated.AuthorizationIdempotencyKey(IDEMPOTENCY_KEY),
        adapter=generated.Adapter(
            id="python-sdk",
            version=generated.SemanticVersion("0.2.0"),
            host_version=generated.SemanticVersion("3.12.0"),
        ),
        task=generated_task,
        action=generated.ActionName.TOOL_INVOKE,
        target=generated_target,
        side_effect=generated.SideEffect.READ_ONLY,
        occurred_at=generated.RFC3339Timestamp("2026-07-26T00:00:00Z"),
        context=generated.ActionContext(),
    )

    assert ActionTarget.from_protocol(generated_target) == _target()
    assert TaskContext.from_protocol(generated_task) == _task()
    assert ActionRequest.from_protocol(generated_request) == _request()


def test_wrappers_accept_structurally_valid_raw_wire_enum_strings() -> None:
    generated_target = generated.ActionTarget(
        kind=cast(Any, "tool"),
        service="inventory-api",
        resource=generated.SafeText("inventory-api:/items/42"),
        resource_hash=generated.SHA256Digest(RESOURCE_HASH),
    )
    generated_request = generated.ActionRequest(
        schema_version=generated.SchemaVersion("1"),
        action_id=generated.ActionID(ACTION_ID),
        request_id=generated.RequestID(REQUEST_ID),
        correlation_id=generated.CorrelationID(CORRELATION_ID),
        idempotency_key=generated.AuthorizationIdempotencyKey(IDEMPOTENCY_KEY),
        adapter=generated.Adapter(
            id="python-sdk",
            version=generated.SemanticVersion("0.2.0"),
            host_version=generated.SemanticVersion("3.12.0"),
        ),
        task=generated.TaskBinding(
            task_id=generated.TaskID(TASK_ID),
            session_id=generated.SessionID(SESSION_ID),
        ),
        action=cast(Any, "tool:invoke"),
        target=generated_target,
        side_effect=cast(Any, "read_only"),
        occurred_at=generated.RFC3339Timestamp("2026-07-26T00:00:00Z"),
        context=generated.ActionContext(),
    )

    assert ActionTarget.from_protocol(generated_target) == _target()
    assert ActionRequest.from_protocol(generated_request) == _request()


def test_protocol_wrapper_factories_fail_with_safe_validation_errors() -> None:
    raw_material = (
        "Bearer sk-protocol-secret https://private.example "
        "prompt=ignore-guard command=rm-rf"
    )
    generated_target = generated.ActionTarget(
        kind=cast(Any, "invalid-kind"),
        service="inventory-api",
        resource=generated.SafeText(raw_material),
        resource_hash=generated.SHA256Digest(RESOURCE_HASH),
    )

    with pytest.raises(ModelValidationError) as caught:
        ActionTarget.from_protocol(generated_target)

    rendered_traceback = "".join(traceback.format_exception(caught.value))
    assert "sk-protocol-secret" not in rendered_traceback
    assert "private.example" not in rendered_traceback
    assert "ignore-guard" not in rendered_traceback
    assert "rm-rf" not in rendered_traceback
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_outcome_enum_is_the_generated_wire_enum() -> None:
    assert DecisionOutcome is generated.DecisionOutcome
    assert tuple(DecisionOutcome) == (
        DecisionOutcome.ALLOW,
        DecisionOutcome.DENY,
        DecisionOutcome.APPROVAL_REQUIRED,
    )
    assert [outcome.value for outcome in DecisionOutcome] == [
        "allow",
        "deny",
        "approval_required",
    ]


@pytest.mark.parametrize(
    ("error_type", "code", "retryable"),
    [
        (InvalidRequest, "invalid_request", False),
        (MissingIdentity, "missing_identity", False),
        (UnsupportedProtocol, "unsupported_protocol", False),
        (AuthenticationFailed, "authentication_failed", False),
        (AuthorizationUnavailable, "authorization_unavailable", True),
        (InvalidDecision, "invalid_decision", False),
        (IdempotencyConflict, "idempotency_conflict", False),
        (ApprovalExpired, "approval_expired", False),
        (ApprovalScopeMismatch, "approval_scope_mismatch", False),
        (CredentialRevoked, "credential_revoked", False),
        (PolicyDenied, "policy_denied", False),
        (ApprovalRequired, "approval_required", False),
        (ModelValidationError, "invalid_request", False),
    ],
)
def test_typed_errors_have_stable_canonical_fields(
    error_type: type[PaloNexusError], code: str, retryable: bool
) -> None:
    error = error_type(
        request_id=REQUEST_ID,
        decision_id=DECISION_ID,
        correlation_id=CORRELATION_ID,
    )

    assert error.code == code
    assert error.message
    assert error.request_id == REQUEST_ID
    assert error.decision_id == DECISION_ID
    assert error.correlation_id == CORRELATION_ID
    assert error.retryable is retryable
    assert isinstance(error, PaloNexusError)


def test_protocol_error_maps_to_a_typed_error_and_propagates_ids() -> None:
    protocol_error = generated.ProtocolError(
        schema_version=generated.SchemaVersion("1"),
        code=generated.ProtocolErrorCode.AUTHORIZATION_UNAVAILABLE,
        safe_message=generated.SafeText("Authorization is temporarily unavailable."),
        retryable=True,
        action_id=generated.ActionID(ACTION_ID),
        request_id=generated.RequestID(REQUEST_ID),
        correlation_id=generated.CorrelationID(CORRELATION_ID),
        decision_id=generated.DecisionID(DECISION_ID),
    )

    error = PaloNexusError.from_protocol(protocol_error)

    assert type(error) is AuthorizationUnavailable
    assert error.request_id == REQUEST_ID
    assert error.decision_id == DECISION_ID
    assert error.correlation_id == CORRELATION_ID
    assert error.retryable is True


def test_protocol_error_factory_accepts_a_raw_wire_code_string() -> None:
    protocol_error = generated.ProtocolError(
        schema_version=generated.SchemaVersion("1"),
        code=cast(Any, "policy_denied"),
        safe_message=generated.SafeText("Current policy denies this action."),
        retryable=False,
        request_id=generated.RequestID(REQUEST_ID),
        correlation_id=generated.CorrelationID(CORRELATION_ID),
    )

    error = PaloNexusError.from_protocol(protocol_error)

    assert type(error) is PolicyDenied
    assert error.request_id == REQUEST_ID
    assert error.correlation_id == CORRELATION_ID


def test_protocol_error_factory_suppresses_invalid_raw_protocol_causes() -> None:
    raw_material = (
        "Bearer sk-error-secret https://private.example "
        "prompt=ignore-guard command=rm-rf"
    )
    protocol_error = generated.ProtocolError(
        schema_version=generated.SchemaVersion("1"),
        code=cast(Any, "policy_denied"),
        safe_message=generated.SafeText(raw_material),
        retryable=False,
    )

    with pytest.raises(ModelValidationError) as caught:
        PaloNexusError.from_protocol(protocol_error)

    rendered_traceback = "".join(traceback.format_exception(caught.value))
    assert raw_material not in rendered_traceback
    assert "sk-error-secret" not in rendered_traceback
    assert "private.example" not in rendered_traceback
    assert "ignore-guard" not in rendered_traceback
    assert "rm-rf" not in rendered_traceback
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_exception_strings_and_reprs_do_not_retain_raw_server_material() -> None:
    raw_material = (
        "Bearer sk-supersecret https://private.example "
        "prompt=ignore-guard command=rm-rf"
    )
    protocol_error = generated.ProtocolError(
        schema_version=generated.SchemaVersion("1"),
        code=generated.ProtocolErrorCode.POLICY_DENIED,
        safe_message=generated.SafeText("Current policy denies this action."),
        retryable=False,
        request_id=generated.RequestID(REQUEST_ID),
        correlation_id=generated.CorrelationID(CORRELATION_ID),
    )

    error = PaloNexusError.from_protocol(protocol_error)
    error.__cause__ = RuntimeError(raw_material)

    for rendered in (str(error), repr(error)):
        assert raw_material not in rendered
        assert "sk-supersecret" not in rendered
        assert "private.example" not in rendered
        assert "ignore-guard" not in rendered
        assert "rm-rf" not in rendered
    assert not hasattr(error, "payload")
    assert not hasattr(error, "protocol_error")


def test_untrusted_malformed_identifiers_are_not_rendered_by_exceptions() -> None:
    raw_identifier = "req_Bearer-sk-supersecret"

    error = PolicyDenied(
        request_id=raw_identifier,
        decision_id="https://private.example",
        correlation_id="prompt=ignore-guard",
    )

    assert error.request_id is None
    assert error.decision_id is None
    assert error.correlation_id is None
    assert raw_identifier not in str(error)
    assert raw_identifier not in repr(error)


def test_exception_contract_fields_are_immutable() -> None:
    error = PolicyDenied(
        request_id=REQUEST_ID,
        decision_id=DECISION_ID,
        correlation_id=CORRELATION_ID,
    )

    for name, value in (
        ("code", "allow"),
        ("message", "Bearer sk-mutation-secret"),
        ("request_id", None),
        ("decision_id", None),
        ("correlation_id", None),
        ("retryable", True),
        ("payload", "Bearer sk-mutation-secret"),
    ):
        with pytest.raises(AttributeError):
            setattr(error, name, value)


@pytest.mark.parametrize(
    "error_type",
    [
        PaloNexusError,
        InvalidRequest,
        MissingIdentity,
        UnsupportedProtocol,
        AuthenticationFailed,
        AuthorizationUnavailable,
        InvalidDecision,
        IdempotencyConflict,
        ApprovalExpired,
        ApprovalScopeMismatch,
        CredentialRevoked,
        PolicyDenied,
        ApprovalRequired,
        ModelValidationError,
    ],
)
def test_typed_errors_are_pickle_and_copy_safe(
    error_type: type[PaloNexusError],
) -> None:
    error = error_type(
        request_id=REQUEST_ID,
        decision_id=DECISION_ID,
        correlation_id=CORRELATION_ID,
    )

    restored = pickle.loads(pickle.dumps(error))
    assert type(restored) is error_type
    assert (
        restored.code,
        restored.message,
        restored.request_id,
        restored.decision_id,
        restored.correlation_id,
        restored.retryable,
    ) == (
        error.code,
        error.message,
        error.request_id,
        error.decision_id,
        error.correlation_id,
        error.retryable,
    )
    assert copy.copy(error) is error
    assert copy.deepcopy(error) is error


def test_top_level_exports_are_intentional_and_exclude_generated_internals() -> None:
    expected = {
        "ActionRequest",
        "ActionRequestBuilder",
        "ActionTarget",
        "ApprovalExpired",
        "ApprovalRequired",
        "ApprovalScopeMismatch",
        "AsyncAuthorizationClient",
        "AsyncCredentialProvider",
        "AuthenticationFailed",
        "AuthorizationClient",
        "AuthorizationDecision",
        "AuthorizationUnavailable",
        "CompletionState",
        "Credential",
        "CredentialAcquisitionCancelled",
        "CredentialUnavailable",
        "CredentialRevoked",
        "DecisionOutcome",
        "EphemeralKeyStore",
        "IdempotencyConflict",
        "InvalidDecision",
        "InvalidCredentialDeadline",
        "InvalidKeyIdentifier",
        "InvalidKeyMaterial",
        "InvalidRequest",
        "KeyNotFound",
        "KeyStore",
        "KeyStoreClosed",
        "KeyStoreCorrupt",
        "KeyStoreError",
        "KeyStoreUnavailable",
        "MissingIdentity",
        "ModelValidationError",
        "PaloNexusError",
        "PolicyDenied",
        "Redactor",
        "RetryDecision",
        "RetryFailure",
        "RetryPolicy",
        "RetryPolicyError",
        "RetryReason",
        "SyncCredentialProvider",
        "TaskContext",
        "UnsupportedProtocol",
        "atask",
        "task",
    }

    assert set(palonexus.__all__) == expected
    assert not hasattr(palonexus, "generated")
    assert not hasattr(palonexus, "ProtocolError")
