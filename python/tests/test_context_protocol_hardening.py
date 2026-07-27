# SPDX-License-Identifier: MIT
"""Adversarial Task 2 tests for preparation, IDs, context, and isolation."""

from __future__ import annotations

import contextvars
import copy
import dataclasses
import importlib.util
import inspect
import multiprocessing
import os
import pickle
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from palonexus import (
    ActionRequest,
    ActionRequestBuilder,
    ActionTarget,
    ApprovalScopeMismatch,
    ModelValidationError,
    TaskContext,
    task,
)
from palonexus.context import _MonotonicIdentifierGenerator, current_task


def _test_builder(
) -> ActionRequestBuilder:
    return ActionRequestBuilder(
        adapter_id="python-sdk",
        adapter_version="0.2.0-alpha.1",
        host_version="3.12.0",
    )


def _context() -> TaskContext:
    return TaskContext(
        task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY0",
        session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY0",
    )


def _path_action(
    builder: ActionRequestBuilder,
    *,
    path: str = "/workspace/one",
) -> tuple[Any, Any]:
    target = builder.prepare_path_target(
        service="workspace",
        path=path,
        cwd="/workspace",
    )
    intent = builder.new(
        action="file:write",
        target=target,
        side_effect="write",
        task_context=_context(),
    )
    return target, builder.build(intent, prepared_target=target)


def test_prepared_types_are_not_public_or_constructible() -> None:
    import palonexus.protocol as protocol

    assert protocol.__all__ == ["ActionRequestBuilder"]
    assert not hasattr(protocol, "PreparedTarget")
    assert not hasattr(protocol, "PreparedAction")

    builder = _test_builder()
    target = builder.prepare_path_target(
        service="workspace",
        path="/workspace/file",
        cwd="/workspace",
    )
    forged = object.__new__(type(target))
    with pytest.raises(ModelValidationError):
        builder.new(
            action="file:read",
            target=forged,
            side_effect="read_only",
            task_context=_context(),
        )


def test_secret_envelope_blocks_introspection_copy_and_serialization() -> None:
    secret = "synthetic-hardening-secret"
    builder = _test_builder()
    target = builder.prepare_url_target(
        service="inventory",
        value=f"https://example.test/run?token={secret}",
    )

    assert secret not in repr(target)
    assert secret not in str(target)
    with pytest.raises(TypeError):
        vars(target)
    with pytest.raises(TypeError):
        dataclasses.asdict(target)
    with pytest.raises(TypeError):
        copy.copy(target)
    with pytest.raises(TypeError):
        copy.deepcopy(target)
    with pytest.raises(TypeError):
        pickle.dumps(target)
    if importlib.util.find_spec("cloudpickle") is not None:
        import cloudpickle

        with pytest.raises(TypeError):
            cloudpickle.dumps(target)
    assert all(secret not in repr(value) for _, value in inspect.getmembers(target))


def test_tampered_safe_metadata_cannot_unlock_execution() -> None:
    builder = _test_builder()
    _, prepared = _path_action(builder)
    object.__setattr__(
        prepared,
        "_client_scope_hash",
        "sha256:" + ("0" * 64),
    )
    with pytest.raises(ModelValidationError):
        prepared.consume()


def test_preparation_breaks_input_aliases_and_consumes_exactly_once() -> None:
    source = {"nested": {"token": "synthetic-alias-secret"}, "items": [1, 2]}
    builder = _test_builder()
    target = builder.prepare_mcp_target(
        server="github",
        tool="issues.create",
        tool_input=source,
    )
    source["nested"]["token"] = "mutated"
    source["items"].append(3)
    intent = builder.new(
        action="mcp:call",
        target=target,
        side_effect="external",
        task_context=_context(),
    )
    prepared = builder.build(intent, prepared_target=target)

    with pytest.raises(ModelValidationError):
        target.consume()
    execution = prepared.consume()
    assert execution == {
        "server": "github",
        "tool": "issues.create",
        "input": {
            "items": [1, 2],
            "nested": {"token": "synthetic-alias-secret"},
        },
    }
    with pytest.raises(ModelValidationError):
        prepared.consume()
    prepared.close()


def test_closed_or_tampered_preparation_fails_before_wire_use() -> None:
    builder = _test_builder()
    target = builder.prepare_shell_target(
        service="workspace",
        command="echo synthetic-secret",
    )
    target.close()
    with pytest.raises(ModelValidationError):
        builder.new(
            action="shell:exec",
            target=target,
            side_effect="write",
            task_context=_context(),
        )


@pytest.mark.parametrize(
    "field",
    ("action_id", "correlation_id"),
)
@pytest.mark.parametrize("value", ("", " ", "\t", "not-an-id"))
def test_explicit_invalid_identifiers_are_never_replaced(
    field: str,
    value: str,
) -> None:
    builder = _test_builder()
    target = builder.prepare_path_target(
        service="workspace",
        path="/workspace/file",
        cwd="/workspace",
    )
    arguments: dict[str, object] = {
        "action": "file:read",
        "target": target,
        "side_effect": "read_only",
        "task_context": _context(),
        field: value,
    }
    with pytest.raises(ModelValidationError):
        builder.new(**arguments)  # type: ignore[arg-type]


def test_attempt_identifiers_cannot_be_caller_selected() -> None:
    parameters = inspect.signature(ActionRequestBuilder.new).parameters
    assert "request_id" not in parameters
    assert "idempotency_key" not in parameters


class _DuplicateGenerator:
    def new(self, _kind: str) -> str:
        return "req_01J5ABCDEFGHJKMNPQRSTVWXY0"


def test_duplicate_generated_required_ids_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("palonexus.protocol._new_identifier", _DuplicateGenerator().new)
    builder = _test_builder()
    target = builder.prepare_path_target(
        service="workspace",
        path="/workspace/file",
        cwd="/workspace",
    )
    with pytest.raises(ModelValidationError):
        builder.new(
            action="file:read",
            target=target,
            side_effect="read_only",
            task_context=_context(),
        )


def test_production_builder_rejects_test_injection() -> None:
    with pytest.raises(TypeError):
        ActionRequestBuilder(
            adapter_id="python-sdk",
            adapter_version="0.2.0-alpha.1",
            host_version="3.12.0",
            _clock=lambda: datetime.now(UTC),  # type: ignore[call-arg]
        )
    assert not hasattr(ActionRequestBuilder, "_for_testing")
    assert not hasattr(_MonotonicIdentifierGenerator, "_for_testing")


def _fork_child(generator: Any, connection: Any) -> None:
    connection.send(generator.new("request"))
    connection.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_generator_reseeds_after_fork() -> None:
    generator = _MonotonicIdentifierGenerator()
    parent_before = generator.new("request")
    context = multiprocessing.get_context("fork")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_fork_child,
        args=(generator, child_connection),
    )
    process.start()
    child_value = parent_connection.recv()
    process.join(10)

    assert process.exitcode == 0
    assert child_value not in {parent_before, generator.new("request")}


def test_random_source_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_size: int) -> bytes:
        raise OSError("entropy unavailable")

    monkeypatch.setattr("palonexus.context.secrets.token_bytes", fail)
    generator = _MonotonicIdentifierGenerator()
    with pytest.raises(RuntimeError, match="entropy"):
        generator.new("request")


def test_cross_context_exit_does_not_consume_owner_token() -> None:
    scope = task(_context())
    assert scope.__enter__() == _context()
    other = contextvars.copy_context()
    with pytest.raises(ValueError):
        other.run(scope.__exit__, None, None, None)

    assert current_task() == _context()
    assert scope.__exit__(None, None, None) is False
    assert current_task() is None
    with pytest.raises(RuntimeError):
        scope.__exit__(None, None, None)
    with pytest.raises(RuntimeError):
        scope.__enter__()


def test_import_does_not_mutate_idna_process_globals() -> None:
    script = """
import idna.core
before = idna.core.unicodedata
import palonexus
assert idna.core.unicodedata is before
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_concurrent_idna_canonicalization_does_not_mutate_globals() -> None:
    import idna.core
    from palonexus._canonicalize import canonicalize_url

    before = idna.core.unicodedata
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(
            pool.map(
                canonicalize_url,
                ["https://xn--8g0n.example/path"] * 64,
            )
        )

    assert len(set(values)) == 1
    assert idna.core.unicodedata is before


def test_resume_requires_fresh_normalization_and_exact_prior_identity() -> None:
    builder = _test_builder()
    _first_target, original = _path_action(builder)
    current = builder.new(
        action="file:write",
        target=builder.prepare_path_target(
            service="workspace",
            path="/workspace/one",
            cwd="/workspace",
        ),
        side_effect="write",
        task_context=_context(),
        action_id=str(original.request.action_id),
        correlation_id=str(original.request.correlation_id),
    )
    resumed = builder.resume(
        original,
        current,
        prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
        approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
    )

    assert resumed.request.causation_id == "dec_01J5ABCDEFGHJKMNPQRSTVWXY3"
    assert resumed.request.resume_from_approval_id == (
        "apr_01J5ABCDEFGHJKMNPQRSTVWXY2"
    )
    assert resumed.request.action_id == original.request.action_id
    assert resumed.request.correlation_id == original.request.correlation_id
    assert resumed.request.task == original.request.task
    assert resumed.request.request_id != original.request.request_id
    assert resumed.request.idempotency_key != original.request.idempotency_key
    with pytest.raises(ModelValidationError):
        original.consume()
    assert resumed.consume() == "/workspace/one"

    with pytest.raises(ModelValidationError):
        builder.resume(
            original,
            current,
            prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
            approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
        )


def test_resume_rejects_mutated_scope_with_typed_error() -> None:
    builder = _test_builder()
    _target, original = _path_action(builder)
    changed_target = builder.prepare_path_target(
        service="workspace",
        path="/workspace/two",
        cwd="/workspace",
    )
    changed = builder.new(
        action="file:write",
        target=changed_target,
        side_effect="write",
        task_context=_context(),
        action_id=str(original.request.action_id),
        correlation_id=str(original.request.correlation_id),
    )
    with pytest.raises(ApprovalScopeMismatch):
        builder.resume(
            original,
            changed,
            prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
            approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
        )
    assert original.consume() == "/workspace/one"


def test_resume_final_nonce_failure_preserves_original_and_wipes_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import palonexus.protocol as protocol

    secret = "resume-atomicity-secret"
    builder = _test_builder()
    target = builder.prepare_shell_target(
        service="workspace",
        command=f"echo {secret}",
    )
    intent = builder.new(
        action="shell:exec",
        target=target,
        side_effect="write",
        task_context=_context(),
    )
    original = builder.build(intent, prepared_target=target)
    current = ActionRequest(
        action_id=str(original.request.action_id),
        request_id="req_01J5ABCDEFGHJKMNPQRSTVWXY4",
        correlation_id=str(original.request.correlation_id),
        idempotency_key="authz_01J5ABCDEFGHJKMNPQRSTVWXY5",
        action="shell:exec",
        target=intent.target,
        task=_context(),
        side_effect="write",
    )

    real_entropy = protocol.secrets.token_bytes
    nonce_calls = 0

    def fail_final_nonce(size: int) -> bytes:
        nonlocal nonce_calls
        if size == 16:
            nonce_calls += 1
            if nonce_calls == 3:
                raise OSError(f"entropy failed near {secret}")
        return real_entropy(size)

    wiped: list[bytes] = []
    real_wipe = protocol._wipe

    def observe_wipe(buffer: bytearray) -> None:
        wiped.append(bytes(buffer))
        real_wipe(buffer)

    monkeypatch.setattr(protocol.secrets, "token_bytes", fail_final_nonce)
    monkeypatch.setattr(protocol, "_wipe", observe_wipe)

    try:
        builder.resume(
            original,
            current,
            prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
            approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
        )
    except ModelValidationError:
        rendered = traceback.format_exc()
    else:
        pytest.fail("resume unexpectedly succeeded")

    assert secret not in rendered
    assert "OSError" not in rendered
    assert any(secret.encode() in value for value in wiped)
    assert original.consume() == f"echo {secret}"


def test_resume_fresh_id_failure_preserves_original_without_raw_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import palonexus.protocol as protocol

    builder = _test_builder()
    _target, original = _path_action(builder)
    current = ActionRequest(
        action_id=str(original.request.action_id),
        request_id="req_01J5ABCDEFGHJKMNPQRSTVWXY4",
        correlation_id=str(original.request.correlation_id),
        idempotency_key="authz_01J5ABCDEFGHJKMNPQRSTVWXY5",
        action="file:write",
        target=ActionTarget(
            kind="local-action",
            service="workspace",
            resource="path:/workspace/one",
        ),
        task=_context(),
        side_effect="write",
    )

    def fail_id(_kind: str) -> str:
        raise OSError("identifier-secret")

    monkeypatch.setattr(protocol, "_new_identifier", fail_id)
    try:
        builder.resume(
            original,
            current,
            prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
            approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
        )
    except ModelValidationError:
        rendered = traceback.format_exc()
    else:
        pytest.fail("resume unexpectedly succeeded")
    assert "identifier-secret" not in rendered
    assert original.consume() == "/workspace/one"
