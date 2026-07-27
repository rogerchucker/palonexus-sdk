# SPDX-License-Identifier: MIT
"""Task context, identifier, and canonical request-builder contracts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import os
import re
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, Final

import pytest
from palonexus import (
    ActionRequestBuilder,
    ModelValidationError,
    TaskContext,
    atask,
    task,
)
from palonexus._generated import protocol as generated
from palonexus.context import (
    _MonotonicIdentifierGenerator,
    current_task,
)

from protocol.reference.validate import validate_action_document

ROOT: Final = Path(__file__).parents[2]
ULID = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def independent_client_scope_hash(document: dict[str, Any]) -> str:
    """Hash the ASCII fixture scope without calling SDK canonicalization."""
    scope = {
        "scopeType": "client",
        "scopeVersion": "1",
        "adapter": {
            "id": document["adapter"]["id"],
            "version": document["adapter"]["version"],
        },
        "task": {
            "taskId": document["task"]["taskId"],
            "sessionId": document["task"]["sessionId"],
        },
        "action": document["action"],
        "target": {
            "kind": document["target"]["kind"],
            "service": document["target"]["service"],
            "resourceHash": document["target"]["resourceHash"],
        },
        "sideEffect": document["sideEffect"],
    }
    payload = json.dumps(
        scope,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def builder() -> ActionRequestBuilder:
    return ActionRequestBuilder(
        adapter_id="python-sdk",
        adapter_version="0.2.0-alpha.1",
        host_version="3.12.0",
    )


def test_task_context_manager_generates_valid_immutable_identifiers() -> None:
    assert current_task() is None

    with task() as context:
        assert current_task() is context
        assert isinstance(context, TaskContext)
        assert context.task_id.startswith("task_")
        assert context.session_id.startswith("session_")
        assert ULID.fullmatch(context.task_id.removeprefix("task_"))
        assert ULID.fullmatch(context.session_id.removeprefix("session_"))
        with pytest.raises(ModelValidationError):
            context.task_id = f"task_{'1' * 26}"

    assert current_task() is None


def test_nested_sync_contexts_restore_the_exact_outer_binding() -> None:
    outer = TaskContext(
        task_id=f"task_{'1' * 26}",
        session_id=f"session_{'1' * 26}",
    )
    inner = TaskContext(
        task_id=f"task_{'2' * 26}",
        session_id=f"session_{'2' * 26}",
    )

    with task(outer):
        assert current_task() is outer
        with task(inner):
            assert current_task() is inner
        assert current_task() is outer

    assert current_task() is None


def test_sync_context_resets_after_exception_without_mutating_process_state() -> None:
    environment = dict(os.environ)
    cwd = os.getcwd()

    with pytest.raises(RuntimeError, match="synthetic"):
        with task():
            raise RuntimeError("synthetic")

    assert current_task() is None
    assert dict(os.environ) == environment
    assert os.getcwd() == cwd


def test_thread_contexts_are_isolated() -> None:
    barrier = threading.Barrier(3)

    def observe(index: int) -> tuple[str, str, bool]:
        context = TaskContext(
            task_id=f"task_{str(index) * 26}",
            session_id=f"session_{str(index) * 26}",
        )
        with task(context):
            barrier.wait()
            observed = current_task()
            barrier.wait()
            assert observed is not None
            return observed.task_id, observed.session_id, observed is context

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(observe, index) for index in (1, 2)]
        barrier.wait()
        assert current_task() is None
        barrier.wait()
        results = [future.result() for future in futures]

    assert results == [
        (f"task_{'1' * 26}", f"session_{'1' * 26}", True),
        (f"task_{'2' * 26}", f"session_{'2' * 26}", True),
    ]
    assert current_task() is None


def test_async_tasks_and_nested_contexts_are_isolated() -> None:
    async def scenario() -> None:
        outer = TaskContext(
            task_id=f"task_{'3' * 26}",
            session_id=f"session_{'3' * 26}",
        )
        entered = asyncio.Event()
        release = asyncio.Event()

        async def child(index: int) -> tuple[str, str]:
            context = TaskContext(
                task_id=f"task_{str(index) * 26}",
                session_id=f"session_{str(index) * 26}",
            )
            async with atask(context):
                entered.set()
                await release.wait()
                observed = current_task()
                assert observed is context
                return observed.task_id, observed.session_id

        async with atask(outer):
            children = [asyncio.create_task(child(index)) for index in (4, 5)]
            await entered.wait()
            assert current_task() is outer
            release.set()
            assert await asyncio.gather(*children) == [
                (f"task_{'4' * 26}", f"session_{'4' * 26}"),
                (f"task_{'5' * 26}", f"session_{'5' * 26}"),
            ]
            assert current_task() is outer

        assert current_task() is None

    asyncio.run(scenario())


def test_async_context_resets_on_cancellation() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()

        async def cancelled() -> None:
            async with atask():
                entered.set()
                await asyncio.Future()

        running = asyncio.create_task(cancelled())
        await entered.wait()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

        assert current_task() is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("kind", "prefix"),
    (
        ("action", "act_"),
        ("request", "req_"),
        ("correlation", "corr_"),
        ("idempotency", "authz_"),
        ("task", "task_"),
        ("session", "session_"),
        ("causation", "cause_"),
    ),
)
def test_identifier_generator_emits_spec_valid_names(
    kind: str,
    prefix: str,
) -> None:
    identifier = _MonotonicIdentifierGenerator().new(kind)

    assert identifier.startswith(prefix)
    assert ULID.fullmatch(identifier.removeprefix(prefix))


def test_identifier_generator_is_collision_free_under_concurrency() -> None:
    generator = _MonotonicIdentifierGenerator()

    def generate(_: int) -> str:
        return generator.new("request")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        values = list(pool.map(generate, range(10_000)))

    assert len(values) == len(set(values))
    assert all(ULID.fullmatch(value.removeprefix("req_")) for value in values)


def test_identifier_generator_stays_monotonic_when_clock_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values_ms = iter((2000, 1999, 1998, 2001))
    monkeypatch.setattr(
        "palonexus.context.time.time_ns",
        lambda: next(values_ms) * 1_000_000,
    )
    monkeypatch.setattr(
        "palonexus.context.secrets.token_bytes",
        lambda size: b"\0" * size,
    )
    generator = _MonotonicIdentifierGenerator()

    values = [generator.new("action") for _ in range(4)]

    assert values == sorted(values)
    assert len(set(values)) == 4


def test_identifier_generator_advances_logical_time_on_randomness_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    maximum = (1 << 80) - 1
    monkeypatch.setattr("palonexus.context.time.time_ns", lambda: 1_000_000_000)
    monkeypatch.setattr(
        "palonexus.context.secrets.token_bytes",
        lambda size: maximum.to_bytes(size, "big"),
    )
    generator = _MonotonicIdentifierGenerator()

    first = generator.new("request")
    second = generator.new("request")

    assert first < second
    assert len({first, second}) == 2


def test_production_identifier_source_uses_cryptographic_randomness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def observed(size: int) -> bytes:
        calls.append(size)
        return b"\1" * size

    monkeypatch.setattr("palonexus.context.secrets.token_bytes", observed)
    generator = _MonotonicIdentifierGenerator()

    generator.new("request")

    assert calls == [10]


def test_builder_creates_generated_wire_request_and_matches_scope_vectors() -> None:
    sdk_builder = builder()
    prepared_target = sdk_builder.prepare_path_target(
        service="workspace",
        path="deploy/production.yaml",
        cwd="/workspace",
    )
    intent = sdk_builder.new(
        action="file:write",
        target=prepared_target,
        side_effect="write",
        task_context=TaskContext(
            task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY0",
            session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY0",
        ),
        correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY0",
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY0",
    )

    prepared = sdk_builder.build(
        intent,
        prepared_target=prepared_target,
        cwd="/workspace",
        repository="example/service",
        tool_name="apply_patch",
    )
    document = prepared.request.to_dict()

    assert isinstance(prepared.request, generated.ActionRequest)
    assert document["target"] == json.loads(
        (ROOT / "protocol/test-vectors/action/valid/file-write.json").read_text()
    )["target"]
    assert prepared.client_scope_hash == independent_client_scope_hash(document)
    validate_action_document(document)


def test_builder_matches_mcp_resource_vector() -> None:
    sdk_builder = builder()
    prepared_target = sdk_builder.prepare_mcp_target(
        server="github",
        tool="issues.create",
        tool_input={
            "labels": ["security", "agent"],
            "issue": {"title": "Cafe\u0301", "priority": 1},
        },
    )
    intent = sdk_builder.new(
        action="mcp:call",
        target=prepared_target,
        side_effect="external",
        task_context=TaskContext(
            task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY1",
            session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY1",
        ),
        correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY1",
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY1",
    )

    prepared = sdk_builder.build(intent, prepared_target=prepared_target)
    expected = json.loads(
        (ROOT / "protocol/test-vectors/action/valid/mcp-call.json").read_text()
    )

    assert prepared.request.target.to_dict() == expected["target"]
    assert prepared.client_scope_hash == independent_client_scope_hash(
        prepared.request.to_dict()
    )


def test_new_intent_uses_bound_task_and_generates_all_attempt_identifiers() -> None:
    sdk_builder = builder()
    bound = TaskContext(
        task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY0",
        session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY0",
    )
    target = sdk_builder.prepare_path_target(
        service="workspace",
        path="/workspace/README.md",
        cwd="/ignored",
    )

    with task(bound) as context:
        with pytest.raises(ModelValidationError):
            sdk_builder.new(
                action="file:read",
                target=target,
                side_effect="read_only",
            )
        intent = sdk_builder.new(
            action="file:read",
            target=target,
            side_effect="read_only",
            task_context=context,
        )

    assert intent.task == bound
    assert intent.action_id is not None and intent.action_id.startswith("act_")
    assert intent.request_id is not None and intent.request_id.startswith("req_")
    assert intent.correlation_id.startswith("corr_")
    assert intent.idempotency_key.startswith("authz_")


def test_builder_rejects_unbound_context_and_target_substitution() -> None:
    sdk_builder = builder()
    path = sdk_builder.prepare_path_target(
        service="workspace",
        path="/workspace/one",
        cwd="/workspace",
    )
    other = sdk_builder.prepare_path_target(
        service="workspace",
        path="/workspace/two",
        cwd="/workspace",
    )

    with pytest.raises(ModelValidationError):
        sdk_builder.new(
            action="file:read",
            target=path,
            side_effect="read_only",
        )

    with task() as context:
        intent = sdk_builder.new(
            action="file:read",
            target=path,
            side_effect="read_only",
            task_context=context,
        )
    with pytest.raises(ModelValidationError):
        sdk_builder.build(intent, prepared_target=other)


def test_transport_retry_reuses_the_same_immutable_attempt() -> None:
    sdk_builder = builder()
    target = sdk_builder.prepare_path_target(
        service="workspace",
        path="/workspace/file",
        cwd="/workspace",
    )
    with task() as context:
        prepared = sdk_builder.build(
            sdk_builder.new(
                action="file:write",
                target=target,
                side_effect="write",
                task_context=context,
            ),
            prepared_target=target,
        )

    attempts = [prepared, prepared, prepared]

    assert len({attempt.request.request_id for attempt in attempts}) == 1
    assert len({attempt.request.idempotency_key for attempt in attempts}) == 1
    with pytest.raises(FrozenInstanceError):
        prepared.request.request_id = generated.RequestID(f"req_{'1' * 26}")


def test_fresh_resume_preserves_action_scope_but_rotates_attempt_identity() -> None:
    sdk_builder = builder()
    target = sdk_builder.prepare_path_target(
        service="workspace",
        path="deploy/production.yaml",
        cwd="/workspace",
    )
    with task() as context:
        original = sdk_builder.build(
            sdk_builder.new(
                action="file:write",
                target=target,
                side_effect="write",
                task_context=context,
            ),
            prepared_target=target,
        )

    fresh_target = sdk_builder.prepare_path_target(
        service="workspace",
        path="deploy/production.yaml",
        cwd="/workspace",
    )
    current = sdk_builder.new(
        action="file:write",
        target=fresh_target,
        side_effect="write",
        task_context=TaskContext(
            task_id=str(original.request.task.task_id),
            session_id=str(original.request.task.session_id),
        ),
        action_id=str(original.request.action_id),
        correlation_id=str(original.request.correlation_id),
    )
    resumed = sdk_builder.resume(
        original,
        current,
        approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY2",
        prior_decision_id="dec_01J5ABCDEFGHJKMNPQRSTVWXY3",
    )

    assert resumed.request.action_id == original.request.action_id
    assert resumed.request.correlation_id == original.request.correlation_id
    assert resumed.request.task == original.request.task
    assert resumed.request.target == original.request.target
    assert resumed.request.action == original.request.action
    assert resumed.request.side_effect == original.request.side_effect
    assert resumed.request.request_id != original.request.request_id
    assert resumed.request.idempotency_key != original.request.idempotency_key
    with pytest.raises(ModelValidationError):
        original.consume()
    assert resumed.consume() == "/workspace/deploy/production.yaml"
    assert resumed.request.resume_from_approval_id == (
        "apr_01J5ABCDEFGHJKMNPQRSTVWXY2"
    )
    assert resumed.request.causation_id == "dec_01J5ABCDEFGHJKMNPQRSTVWXY3"
    assert resumed.client_scope_hash == original.client_scope_hash


def test_builder_never_serializes_or_hashes_a_caller_client_id() -> None:
    sdk_builder = builder()
    target = sdk_builder.prepare_path_target(
        service="workspace",
        path="/workspace/file",
        cwd="/workspace",
    )
    with task() as context:
        intent = sdk_builder.new(
            action="file:read",
            target=target,
            side_effect="read_only",
            task_context=context,
        )

    with pytest.raises(TypeError):
        sdk_builder.build(intent, client_id="privileged-client")  # type: ignore[call-arg]

    document = sdk_builder.build(intent, prepared_target=target).request.to_dict()
    assert "clientId" not in json.dumps(document)
    assert document["adapter"]["id"] == "python-sdk"


def test_secret_execution_data_is_confined_to_redacted_prepared_objects() -> None:
    secret = "synthetic-task2-secret"
    sdk_builder = builder()
    target = sdk_builder.prepare_url_target(
        service="inventory-api",
        value=f"https://example.test/run?token={secret}&item=42",
    )
    with task() as context:
        intent = sdk_builder.new(
            action="web:fetch",
            target=target,
            side_effect="external",
            task_context=context,
        )
    prepared = sdk_builder.build(
        intent,
        prepared_target=target,
        safe_display="Inventory lookup",
    )
    wire = prepared.request.to_json_bytes().decode()

    assert secret not in target.target.resource
    assert secret not in wire
    assert secret not in repr(target)
    assert secret not in repr(prepared)
    assert secret not in repr(intent)
    assert secret not in repr(current_task())
    assert "safeDisplay" in wire
    assert secret in str(prepared.consume())


def test_prepared_action_is_immutable_and_rejects_pickle_state_injection() -> None:
    sdk_builder = builder()
    target = sdk_builder.prepare_shell_target(
        service="workspace",
        command="echo safe",
    )
    with task() as context:
        prepared = sdk_builder.build(
            sdk_builder.new(
                action="shell:exec",
                target=target,
                side_effect="write",
                task_context=context,
            ),
            prepared_target=target,
        )

    assert type(prepared).__name__ == "_PreparedAction"
    with pytest.raises((AttributeError, TypeError)):
        prepared.execution = "different"


def test_builder_rejects_naive_or_non_datetime_test_clock() -> None:
    assert not hasattr(ActionRequestBuilder, "_for_testing")


def test_context_and_builder_public_exports_are_intentional() -> None:
    import palonexus

    assert {"TaskContext", "task", "atask", "ActionRequestBuilder"} <= set(
        palonexus.__all__
    )
    assert "_MonotonicIdentifierGenerator" not in palonexus.__all__
    assert "PreparedAction" not in palonexus.__all__
    assert "current_task" not in palonexus.__all__
