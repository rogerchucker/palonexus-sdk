# SPDX-License-Identifier: MIT
"""Testing-only scripted transports and loopback decision-server contracts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import io
import json
import socket
import threading
import time
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from palonexus import (
    ActionRequestBuilder,
    ApprovalExpired,
    AsyncAuthorizationClient,
    AuthorizationClient,
    AuthorizationUnavailable,
    IdempotencyConflict,
    InvalidRequest,
    RetryPolicy,
    TaskContext,
    _canonicalize,
)
from palonexus._generated import protocol as wire
from palonexus.credentials import Credential
from palonexus.testing import (
    AsyncFakeTransport,
    FakeTransport,
    FrozenClock,
    MockDecisionServer,
    ScriptedEngine,
)
from palonexus.transports import (
    AsyncHTTPAuthorizationTransport,
    HTTPAuthorizationTransport,
    HTTPTransportConfig,
)

ROOT = Path(__file__).parents[2]
ACTION = ROOT / "protocol/test-vectors/action/valid/file-write.json"
_HOSTILE_SECRET = "TOPSECRET-CALLBACK-VALUE"


def request(*, key: str | None = None, action: str | None = None) -> wire.ActionRequest:
    document = json.loads(ACTION.read_text())
    if key is not None:
        document["idempotencyKey"] = key
    if action is not None:
        document["action"] = action
    return wire.parse_action(document)


def scope(value: wire.ActionRequest) -> str:
    return _canonicalize.client_scope_hash(value.to_dict())


def prepared() -> Any:
    builder = ActionRequestBuilder(
        adapter_id="testing-example",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )
    target = builder.prepare_path_target(
        service="workspace",
        path="example.txt",
        cwd="/workspace",
    )
    return builder.build(
        builder.new(
            action="file:write",
            target=target,
            side_effect="write",
            task_context=TaskContext(
                task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
                session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
            ),
            action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY8",
            correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
        ),
        prepared_target=target,
    )


def engine(*outcomes: Any, capacity: int = 16) -> ScriptedEngine:
    return ScriptedEngine(
        *outcomes,
        testing_only=True,
        clock=FrozenClock("2026-07-25T20:00:00Z"),
        id_source=iter(
            f"{prefix}_01J5ABCDEFGHJKMNPQRSTVWXY{i:X}"
            for i in range(16)
            for prefix in ("dec", "audit", "apr")
        ).__next__,
        idempotency_capacity=capacity,
        idempotency_ttl=60,
    )


def test_testing_only_capability_is_mandatory() -> None:
    with pytest.raises(TypeError):
        ScriptedEngine()  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        ScriptedEngine(testing_only=False)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        MockDecisionServer(engine(), testing_only=False)  # type: ignore[arg-type]


def test_scripted_sync_and_async_outcomes_are_exact_and_recorded_safely() -> None:
    scripted = engine(
        ScriptedEngine.allow(reason_code="fixture_allowed"),
        ScriptedEngine.deny(reason_code="fixture_denied"),
    )
    sync = FakeTransport(scripted, testing_only=True)
    async_transport = AsyncFakeTransport(scripted, testing_only=True)
    first = request()

    allowed = sync.decide(first, client_scope_hash=scope(first))
    denied = asyncio.run(
        async_transport.decide(
            request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9"),
            client_scope_hash=scope(request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")),
        )
    )

    assert str(allowed.outcome) == "allow"
    assert allowed.reason_code == "fixture_allowed"
    assert str(denied.outcome) == "deny"
    calls = scripted.recorded_calls
    assert len(calls) == 2
    assert calls[0].canonical_request_hash.startswith("sha256:")
    assert calls[0].request["context"] == {"parameters": None}
    with pytest.raises(TypeError):
        calls[0].request["action"] = "changed"  # type: ignore[index]


def test_idempotency_replays_exact_result_and_conflicts_fail_closed() -> None:
    scripted = engine(ScriptedEngine.allow())
    transport = FakeTransport(scripted, testing_only=True)
    original = request()
    first = transport.decide(original, client_scope_hash=scope(original))
    second = transport.decide(original, client_scope_hash=scope(original))
    assert first is second
    changed = request(action="file:delete")
    with pytest.raises(IdempotencyConflict):
        transport.decide(changed, client_scope_hash=scope(changed))


def test_idempotency_capacity_fails_closed_without_evicting_live_entries() -> None:
    scripted = engine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        capacity=1,
    )
    transport = FakeTransport(scripted, testing_only=True)
    original = request()
    transport.decide(original, client_scope_hash=scope(original))
    different = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
    with pytest.raises(AuthorizationUnavailable):
        transport.decide(different, client_scope_hash=scope(different))


def test_approval_lifecycle_is_deterministic_and_terminal() -> None:
    scripted = engine(ScriptedEngine.approval_required())
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    decision = transport.decide(value, client_scope_hash=scope(value))
    assert decision.approval is not None
    pending = transport.request_approval(
        value,
        decision_id=str(decision.decision_id),
        authoritative_scope_hash=str(decision.authoritative_scope_hash),
        approval_id=str(decision.approval.approval_id),
    )
    approved = scripted.resolve_approval(
        str(pending.approval_id),
        status="approved",
        reviewer_ref="subject:test-reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    assert str(approved.status) == "approved"
    assert transport.get_approval(str(pending.approval_id)) is approved
    with pytest.raises(IdempotencyConflict):
        scripted.resolve_approval(
            str(pending.approval_id),
            status="denied",
            reviewer_ref="subject:test-reviewer",
            resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY5",
        )


def test_approval_creation_is_bound_to_issued_decision_and_request() -> None:
    scripted = engine(ScriptedEngine.approval_required(), ScriptedEngine.allow())
    transport = FakeTransport(scripted, testing_only=True)
    original = request()
    decision = transport.decide(original, client_scope_hash=scope(original))
    assert decision.approval is not None
    kwargs = {
        "decision_id": str(decision.decision_id),
        "authoritative_scope_hash": str(decision.authoritative_scope_hash),
        "approval_id": str(decision.approval.approval_id),
    }
    first = transport.request_approval(original, **kwargs)
    assert transport.request_approval(original, **kwargs) is first

    changed = request(action="file:delete")
    with pytest.raises(IdempotencyConflict):
        transport.request_approval(changed, **kwargs)
    with pytest.raises(IdempotencyConflict):
        transport.request_approval(
            original,
            **{**kwargs, "authoritative_scope_hash": "sha256:" + "f" * 64},
        )
    allowed_request = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
    allowed = transport.decide(
        allowed_request, client_scope_hash=scope(allowed_request)
    )
    with pytest.raises(IdempotencyConflict):
        transport.request_approval(
            allowed_request,
            decision_id=str(allowed.decision_id),
            authoritative_scope_hash=str(allowed.authoritative_scope_hash),
            approval_id="apr_01J5ABCDEFGHJKMNPQRSTVWXY9",
        )


def test_exact_approval_create_replays_after_decision_approval_expiry() -> None:
    clock = FrozenClock("2026-07-25T20:00:00Z")
    scripted = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.approval_required(),
        testing_only=True,
        clock=clock,
    )
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    decision = transport.decide(value, client_scope_hash=scope(value))
    assert decision.approval is not None
    kwargs = {
        "decision_id": str(decision.decision_id),
        "authoritative_scope_hash": str(decision.authoritative_scope_hash),
        "approval_id": str(decision.approval.approval_id),
    }
    created = transport.request_approval(value, **kwargs)
    clock.advance(901)
    assert transport.request_approval(value, **kwargs) is created

    other = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
    other_decision = transport.decide(other, client_scope_hash=scope(other))
    assert other_decision.approval is not None
    clock.advance(901)
    with pytest.raises(ApprovalExpired):
        transport.request_approval(
            other,
            decision_id=str(other_decision.decision_id),
            authoritative_scope_hash=str(other_decision.authoritative_scope_hash),
            approval_id=str(other_decision.approval.approval_id),
        )


def test_rejected_approval_create_is_not_recorded() -> None:
    scripted = engine(ScriptedEngine.approval_required())
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    decision = transport.decide(value, client_scope_hash=scope(value))
    before = scripted.recorded_calls
    assert decision.approval is not None
    with pytest.raises(IdempotencyConflict):
        transport.request_approval(
            value,
            decision_id=str(decision.decision_id),
            authoritative_scope_hash="sha256:" + "f" * 64,
            approval_id=str(decision.approval.approval_id),
        )
    assert scripted.recorded_calls == before


@pytest.mark.parametrize(
    ("status", "reviewer"),
    [
        ("approved", "subject:test-reviewer"),
        ("denied", "subject:test-reviewer"),
        ("cancelled", None),
        ("expired", None),
    ],
)
def test_every_approval_terminal_state_has_one_exact_transition(
    status: str, reviewer: str | None
) -> None:
    scripted = engine(ScriptedEngine.approval_required())
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    decision = transport.decide(value, client_scope_hash=scope(value))
    assert decision.approval is not None
    pending = transport.request_approval(
        value,
        decision_id=str(decision.decision_id),
        authoritative_scope_hash=str(decision.authoritative_scope_hash),
        approval_id=str(decision.approval.approval_id),
    )
    terminal = scripted.resolve_approval(
        str(pending.approval_id),
        status=status,  # type: ignore[arg-type]
        reviewer_ref=reviewer,
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    assert str(terminal.status) == status
    assert terminal.action_id == pending.action_id
    assert terminal.authoritative_scope_hash == pending.authoritative_scope_hash
    expected_error = ApprovalExpired if status == "expired" else IdempotencyConflict
    with pytest.raises(expected_error):
        scripted.resolve_approval(
            str(pending.approval_id),
            status="cancelled",
            reviewer_ref=None,
            resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY5",
        )


def test_resolution_idempotency_replays_and_conflicts_globally() -> None:
    scripted = engine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.approval_required(),
    )
    transport = FakeTransport(scripted, testing_only=True)

    def create(value: wire.ActionRequest) -> wire.ApprovalRecord:
        decision = transport.decide(value, client_scope_hash=scope(value))
        assert decision.approval is not None
        return transport.request_approval(
            value,
            decision_id=str(decision.decision_id),
            authoritative_scope_hash=str(decision.authoritative_scope_hash),
            approval_id=str(decision.approval.approval_id),
        )

    first = create(request())
    second = create(request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9"))
    key = "approval_01J5ABCDEFGHJKMNPQRSTVWXY4"
    resolved = scripted.resolve_approval(
        str(first.approval_id),
        status="approved",
        reviewer_ref="subject:test-reviewer",
        resolution_idempotency_key=key,
    )
    assert (
        scripted.resolve_approval(
            str(first.approval_id),
            status="approved",
            reviewer_ref="subject:test-reviewer",
            resolution_idempotency_key=key,
        )
        is resolved
    )
    with pytest.raises(IdempotencyConflict):
        scripted.resolve_approval(
            str(second.approval_id),
            status="approved",
            reviewer_ref="subject:test-reviewer",
            resolution_idempotency_key=key,
        )
    with pytest.raises(IdempotencyConflict):
        scripted.resolve_approval(
            str(first.approval_id),
            status="denied",
            reviewer_ref="subject:test-reviewer",
            resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY5",
        )


def test_expiry_transition_is_atomic_idempotent_and_precedes_resolution() -> None:
    clock = FrozenClock("2026-07-25T20:00:00Z")
    scripted = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
        clock=clock,
    )
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    decision = transport.decide(value, client_scope_hash=scope(value))
    assert decision.approval is not None
    pending = transport.request_approval(
        value,
        decision_id=str(decision.decision_id),
        authoritative_scope_hash=str(decision.authoritative_scope_hash),
        approval_id=str(decision.approval.approval_id),
    )
    clock.advance(900)
    results: list[wire.ApprovalRecord] = []
    barrier = threading.Barrier(3)

    def observe() -> None:
        barrier.wait()
        results.append(transport.get_approval(str(pending.approval_id)))

    observers = [threading.Thread(target=observe) for _ in range(2)]
    for observer in observers:
        observer.start()
    barrier.wait()
    for observer in observers:
        observer.join()
    first, second = results
    assert first is second
    assert str(first.status) == "expired"
    assert first.resolution_idempotency_key is not None
    with pytest.raises(ApprovalExpired):
        scripted.resolve_approval(
            str(pending.approval_id),
            status="approved",
            reviewer_ref="subject:test-reviewer",
            resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY9",
        )


def test_async_transport_has_decision_and_approval_parity() -> None:
    async def scenario() -> None:
        scripted = engine(ScriptedEngine.approval_required())
        transport = AsyncFakeTransport(scripted, testing_only=True)
        value = request()
        decision = await transport.decide(value, client_scope_hash=scope(value))
        assert decision.approval is not None
        pending = await transport.request_approval(
            value,
            decision_id=str(decision.decision_id),
            authoritative_scope_hash=str(decision.authoritative_scope_hash),
            approval_id=str(decision.approval.approval_id),
        )
        assert await transport.get_approval(str(pending.approval_id)) is pending
        await transport.aclose()

    asyncio.run(scenario())


def test_idempotency_expiry_is_clock_controlled() -> None:
    clock = FrozenClock("2026-07-25T20:00:00Z")
    scripted = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.deny(),
        testing_only=True,
        clock=clock,
        idempotency_capacity=1,
        idempotency_ttl=10,
    )
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    first = transport.decide(value, client_scope_hash=scope(value))
    assert str(first.outcome) == "allow"
    clock.advance(11)
    second = transport.decide(value, client_scope_hash=scope(value))
    assert str(second.outcome) == "deny"


def test_delay_uses_completion_clock_for_timestamps_and_ttl() -> None:
    clock = FrozenClock("2026-07-25T20:00:00Z")

    def advance_during_delay() -> None:
        time.sleep(0.01)
        clock.advance(20)

    scripted = ScriptedEngine(
        ScriptedEngine.delay(0.03, ScriptedEngine.allow()),
        ScriptedEngine.deny(),
        testing_only=True,
        clock=clock,
        idempotency_capacity=1,
        idempotency_ttl=10,
    )
    thread = threading.Thread(target=advance_during_delay)
    thread.start()
    value = request()
    first = FakeTransport(scripted, testing_only=True).decide(
        value, client_scope_hash=scope(value)
    )
    thread.join()
    assert str(first.server_time) == "2026-07-25T20:00:20Z"
    assert (
        FakeTransport(scripted, testing_only=True).decide(
            value, client_scope_hash=scope(value)
        )
        is first
    )


def test_concurrent_same_key_consumes_one_scripted_outcome() -> None:
    scripted = engine(
        ScriptedEngine.delay(0.02, ScriptedEngine.allow()),
        ScriptedEngine.deny(),
    )
    transport = FakeTransport(scripted, testing_only=True)
    value = request()
    barrier = threading.Barrier(3)
    results: list[wire.AuthorizationDecision] = []

    def invoke() -> None:
        barrier.wait()
        results.append(transport.decide(value, client_scope_hash=scope(value)))

    threads = [threading.Thread(target=invoke) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert len(results) == 2
    assert results[0] is results[1]
    different = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
    assert (
        str(transport.decide(different, client_scope_hash=scope(different)).outcome)
        == "deny"
    )


class _CredentialProvider:
    def get_credential(self, **_: object) -> Credential:
        return Credential(
            "testing-token",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class _AsyncCredentialProvider:
    async def get_credential(self, **_: object) -> Credential:
        return Credential(
            "testing-token",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


def test_loopback_mock_server_serves_real_sync_and_async_http_transports() -> None:
    scripted = engine(ScriptedEngine.allow(), ScriptedEngine.deny())
    before = {thread.ident for thread in threading.enumerate()}
    with MockDecisionServer(scripted, testing_only=True) as server:
        assert server.host == "127.0.0.1"
        assert server.port > 0
        config = HTTPTransportConfig.for_local_testing(
            origin=server.origin,
            testing_only=True,
        )
        sync = HTTPAuthorizationTransport(
            config=config,
            credential_provider=_CredentialProvider(),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        async_transport = AsyncHTTPAuthorizationTransport(
            config=config,
            credential_provider=_AsyncCredentialProvider(),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        value = request()
        try:
            result = sync.decide(value, client_scope_hash=scope(value))
            assert str(result.outcome) == "allow"
            assert (
                str(
                    asyncio.run(
                        async_transport.decide(
                            request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9"),
                            client_scope_hash=scope(
                                request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
                            ),
                        )
                    ).outcome
                )
                == "deny"
            )
        finally:
            sync.close()
            asyncio.run(async_transport.aclose())
    assert server.closed
    assert server.thread_ident not in {
        thread.ident for thread in threading.enumerate() if thread.ident not in before
    }


def test_loopback_server_runs_public_sync_and_async_client_examples() -> None:
    scripted = engine(ScriptedEngine.allow(), ScriptedEngine.allow())
    with MockDecisionServer(scripted, testing_only=True) as server:
        config = HTTPTransportConfig.for_local_testing(
            origin=server.origin,
            testing_only=True,
        )
        sync_transport = HTTPAuthorizationTransport(
            config=config,
            credential_provider=_CredentialProvider(),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        async_transport = AsyncHTTPAuthorizationTransport(
            config=config,
            credential_provider=_AsyncCredentialProvider(),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        sync_client = AuthorizationClient(sync_transport)
        async_client = AsyncAuthorizationClient(async_transport)
        first = prepared()
        second = prepared()
        try:
            assert sync_client.authorize(first).outcome.value == "allow"
            assert asyncio.run(async_client.authorize(second)).outcome.value == "allow"
        finally:
            sync_client.close()
            asyncio.run(async_client.aclose())
            sync_transport.close()
            asyncio.run(async_transport.aclose())


def test_loopback_server_preserves_safe_typed_outage_errors() -> None:
    scripted = engine(ScriptedEngine.outage())
    with MockDecisionServer(scripted, testing_only=True) as server:
        transport = HTTPAuthorizationTransport(
            config=HTTPTransportConfig.for_local_testing(
                origin=server.origin,
                testing_only=True,
            ),
            credential_provider=_CredentialProvider(),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        try:
            with pytest.raises(AuthorizationUnavailable) as caught:
                transport.decide(request(), client_scope_hash=scope(request()))
            assert caught.value.__cause__ is None
            assert caught.value.__context__ is None
        finally:
            transport.close()


def test_mock_server_rejects_non_loopback_and_malformed_wire_requests() -> None:
    scripted = engine(ScriptedEngine.allow())
    with pytest.raises(ValueError):
        MockDecisionServer(
            scripted,
            testing_only=True,
            host="0.0.0.0",
        )
    with MockDecisionServer(scripted, testing_only=True) as server:
        with socket.create_connection((server.host, server.port)) as sock:
            sock.sendall(
                b"POST /v1/authorization/decisions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Content-Type: application/json\r\n\r\n0\r\n\r\n"
            )
            assert b"400" in sock.recv(512).split(b"\r\n", 1)[0]
        response = httpx.get(
            f"{server.origin}/v1/authorization/decisions",
            trust_env=False,
        )
        assert response.status_code == 405
        assert (
            httpx.post(
                f"{server.origin}/not-a-decision-path",
                content=b"{}",
                headers={"Content-Type": "application/json"},
                trust_env=False,
            ).status_code
            == 404
        )
        assert (
            httpx.post(
                f"{server.origin}/v1/authorization/decisions",
                content=b"{}",
                headers={"Content-Type": "text/plain"},
                trust_env=False,
            ).status_code
            == 400
        )
        assert (
            httpx.post(
                f"{server.origin}/v1/authorization/decisions",
                content=b'{"x":1,"x":2}',
                headers={"Content-Type": "application/json"},
                trust_env=False,
            ).status_code
            == 400
        )


def test_async_cancellation_drains_delayed_worker() -> None:
    async def scenario() -> None:
        scripted = engine(
            ScriptedEngine.delay(1.0, ScriptedEngine.allow()),
            ScriptedEngine.deny(),
        )
        transport = AsyncFakeTransport(scripted, testing_only=True)
        value = request()
        task = asyncio.create_task(
            transport.decide(value, client_scope_hash=scope(value))
        )
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        different = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXY9")
        result = await transport.decide(different, client_scope_hash=scope(different))
        assert str(result.outcome) == "allow"
        last = request(key="authz_01J5ABCDEFGHJKMNPQRSTVWXYA")
        assert (
            str((await transport.decide(last, client_scope_hash=scope(last))).outcome)
            == "deny"
        )

    asyncio.run(scenario())


def test_hostile_callbacks_and_scripted_errors_are_sanitized() -> None:
    def hostile_clock() -> datetime:
        raise RuntimeError(_HOSTILE_SECRET)

    scripted = ScriptedEngine(
        ScriptedEngine.allow(),
        testing_only=True,
        clock=hostile_clock,
    )
    with pytest.raises(InvalidRequest) as caught:
        FakeTransport(scripted, testing_only=True).decide(
            request(), client_scope_hash=scope(request())
        )
    rendered = "".join(
        traceback.TracebackException.from_exception(
            caught.value, capture_locals=True
        ).format()
    )
    assert _HOSTILE_SECRET not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None

    unsafe = engine(ScriptedEngine.error(RuntimeError(_HOSTILE_SECRET)))
    with pytest.raises(AuthorizationUnavailable) as unsafe_caught:
        FakeTransport(unsafe, testing_only=True).decide(
            request(), client_scope_hash=scope(request())
        )
    assert _HOSTILE_SECRET not in repr(unsafe_caught.value)
    assert unsafe_caught.value.__cause__ is None
    assert unsafe_caught.value.__context__ is None

    class UnsafeBase(BaseException):
        pass

    unsafe_base = engine(ScriptedEngine.error(UnsafeBase(_HOSTILE_SECRET)))
    with pytest.raises(AuthorizationUnavailable):
        FakeTransport(unsafe_base, testing_only=True).decide(
            request(), client_scope_hash=scope(request())
        )


def test_hostile_frozen_clock_id_and_cancel_inputs_do_not_escape() -> None:
    class HostileText(str):
        def replace(self, *_: object, **__: object) -> str:
            raise RuntimeError(_HOSTILE_SECRET)

        def __repr__(self) -> str:
            return _HOSTILE_SECRET

    with pytest.raises(InvalidRequest) as frozen_caught:
        FrozenClock(HostileText("2026-07-25T20:00:00Z"))
    frozen_rendered = "".join(
        traceback.TracebackException.from_exception(
            frozen_caught.value, capture_locals=True
        ).format()
    )
    assert _HOSTILE_SECRET not in frozen_rendered

    def hostile_id() -> str:
        raise RuntimeError(_HOSTILE_SECRET)

    scripted = ScriptedEngine(
        ScriptedEngine.allow(),
        testing_only=True,
        clock=FrozenClock("2026-07-25T20:00:00Z"),
        id_source=hostile_id,
    )
    with pytest.raises(InvalidRequest) as id_caught:
        scripted.decide(request(), client_scope_hash=scope(request()))
    id_rendered = "".join(
        traceback.TracebackException.from_exception(
            id_caught.value, capture_locals=True
        ).format()
    )
    assert _HOSTILE_SECRET not in id_rendered
    assert id_caught.value.__cause__ is None
    assert id_caught.value.__context__ is None

    def hostile_cancel() -> bool:
        raise RuntimeError(_HOSTILE_SECRET)

    with pytest.raises(concurrent.futures.CancelledError) as cancel_caught:
        engine(ScriptedEngine.allow()).decide(
            request(),
            client_scope_hash=scope(request()),
            cancelled=hostile_cancel,
        )
    assert cancel_caught.value.__cause__ is None
    assert cancel_caught.value.__context__ is None


def test_direct_engine_decide_failure_has_no_secret_package_locals() -> None:
    def hostile_id() -> str:
        raise RuntimeError(_HOSTILE_SECRET)

    scripted = ScriptedEngine(
        ScriptedEngine.allow(),
        testing_only=True,
        id_source=hostile_id,
    )
    with pytest.raises(InvalidRequest) as caught:
        scripted.decide(request(), client_scope_hash=scope(request()))
    rendered = "".join(
        traceback.TracebackException.from_exception(
            caught.value, capture_locals=True
        ).format()
    )
    assert _HOSTILE_SECRET not in rendered
    assert "resource%22" not in rendered


def test_async_cancelled_approval_create_does_not_record_or_mutate() -> None:
    async def scenario() -> None:
        entered = threading.Event()
        release = threading.Event()
        clock = FrozenClock("2026-07-25T20:00:00Z")

        def blocking_clock() -> datetime:
            entered.set()
            release.wait()
            return clock()

        scripted = ScriptedEngine(
            ScriptedEngine.approval_required(),
            testing_only=True,
            clock=clock,
        )
        value = request()
        decision = scripted.decide(value, client_scope_hash=scope(value))
        assert decision.approval is not None
        scripted._clock = blocking_clock
        before = scripted.recorded_calls
        transport = AsyncFakeTransport(scripted, testing_only=True)
        task = asyncio.create_task(
            transport.request_approval(
                value,
                decision_id=str(decision.decision_id),
                authoritative_scope_hash=str(decision.authoritative_scope_hash),
                approval_id=str(decision.approval.approval_id),
            )
        )
        await asyncio.to_thread(entered.wait)
        task.cancel()
        releaser = threading.Timer(0.01, release.set)
        releaser.start()
        with pytest.raises(asyncio.CancelledError):
            await task
        releaser.join()
        assert scripted.recorded_calls == before
        with pytest.raises(AuthorizationUnavailable):
            scripted.get_approval(str(decision.approval.approval_id))

    asyncio.run(scenario())


def test_async_decide_cancellation_and_commit_are_linearized() -> None:
    async def cancellation_wins() -> None:
        at_commit = threading.Event()
        release_commit = threading.Event()

        def before_commit(operation: str) -> None:
            if operation == "decide":
                at_commit.set()
                release_commit.wait()

        scripted = ScriptedEngine(
            ScriptedEngine.allow(),
            testing_only=True,
            before_commit=before_commit,
        )
        transport = AsyncFakeTransport(scripted, testing_only=True)
        value = request()
        task = asyncio.create_task(
            transport.decide(value, client_scope_hash=scope(value))
        )
        await asyncio.to_thread(at_commit.wait)
        task.cancel("cancel-wins")
        await asyncio.sleep(0)
        release_commit.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert caught.value.args == ("cancel-wins",)
        assert scripted.recorded_calls == ()
        assert (
            str(
                FakeTransport(scripted, testing_only=True)
                .decide(value, client_scope_hash=scope(value))
                .outcome
            )
            == "allow"
        )

    async def commit_wins() -> None:
        at_commit = threading.Event()
        release_commit = threading.Event()
        committed = threading.Event()
        release_worker = threading.Event()

        def before_commit(operation: str) -> None:
            if operation == "decide":
                at_commit.set()
                release_commit.wait()

        def after_commit(operation: str) -> None:
            if operation == "decide":
                committed.set()
                release_worker.wait()

        scripted = ScriptedEngine(
            ScriptedEngine.allow(),
            testing_only=True,
            before_commit=before_commit,
            after_commit=after_commit,
        )
        transport = AsyncFakeTransport(scripted, testing_only=True)
        value = request()
        task = asyncio.create_task(
            transport.decide(value, client_scope_hash=scope(value))
        )
        await asyncio.to_thread(at_commit.wait)
        release_commit.set()
        await asyncio.to_thread(committed.wait)
        task.cancel("too-late")
        await asyncio.sleep(0)
        release_worker.set()
        result = await task
        assert str(result.outcome) == "allow"
        assert len(scripted.recorded_calls) == 1

    asyncio.run(cancellation_wins())
    asyncio.run(commit_wins())


def test_async_expiry_cancellation_and_commit_are_linearized() -> None:
    def prepared() -> tuple[ScriptedEngine, FrozenClock, str]:
        clock = FrozenClock("2026-07-25T20:00:00Z")
        scripted = ScriptedEngine(
            ScriptedEngine.approval_required(),
            testing_only=True,
            clock=clock,
        )
        value = request()
        decision = scripted.decide(value, client_scope_hash=scope(value))
        assert decision.approval is not None
        pending = scripted.request_approval(
            value,
            decision_id=str(decision.decision_id),
            authoritative_scope_hash=str(decision.authoritative_scope_hash),
            approval_id=str(decision.approval.approval_id),
        )
        clock.advance(900)
        return scripted, clock, str(pending.approval_id)

    async def cancellation_wins() -> None:
        scripted, _, approval_id = prepared()
        before = scripted.recorded_calls
        at_commit = threading.Event()
        release_commit = threading.Event()

        def before_commit(operation: str) -> None:
            if operation == "get_approval":
                at_commit.set()
                release_commit.wait()

        scripted._before_commit = before_commit
        task = asyncio.create_task(
            AsyncFakeTransport(scripted, testing_only=True).get_approval(approval_id)
        )
        await asyncio.to_thread(at_commit.wait)
        task.cancel("expiry-cancelled")
        await asyncio.sleep(0)
        release_commit.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert scripted.recorded_calls == before
        assert str(scripted.get_approval(approval_id).status) == "expired"

    async def commit_wins() -> None:
        scripted, _, approval_id = prepared()
        at_commit = threading.Event()
        release_commit = threading.Event()
        committed = threading.Event()
        release_worker = threading.Event()

        def before_commit(operation: str) -> None:
            if operation == "get_approval":
                at_commit.set()
                release_commit.wait()

        def after_commit(operation: str) -> None:
            if operation == "get_approval":
                committed.set()
                release_worker.wait()

        scripted._before_commit = before_commit
        scripted._after_commit = after_commit
        task = asyncio.create_task(
            AsyncFakeTransport(scripted, testing_only=True).get_approval(approval_id)
        )
        await asyncio.to_thread(at_commit.wait)
        release_commit.set()
        await asyncio.to_thread(committed.wait)
        task.cancel("expiry-too-late")
        await asyncio.sleep(0)
        release_worker.set()
        assert str((await task).status) == "expired"

    asyncio.run(cancellation_wins())
    asyncio.run(commit_wins())


def test_mock_server_sanitizes_engine_callback_failures() -> None:
    def hostile_clock() -> datetime:
        raise RuntimeError(_HOSTILE_SECRET)

    scripted = ScriptedEngine(
        ScriptedEngine.allow(),
        testing_only=True,
        clock=hostile_clock,
    )
    with MockDecisionServer(scripted, testing_only=True) as server:
        response = httpx.post(
            f"{server.origin}/v1/authorization/decisions",
            content=_canonicalize.canonical_json(request().to_dict()),
            headers={"Content-Type": "application/json"},
            trust_env=False,
        )
    assert response.status_code == 503
    assert _HOSTILE_SECRET not in response.text


def test_direct_control_exceptions_propagate_and_delays_obey_cancellation() -> None:
    marker = KeyboardInterrupt()
    scripted = engine(ScriptedEngine.error(marker))
    with pytest.raises(KeyboardInterrupt) as caught:
        FakeTransport(scripted, testing_only=True).decide(
            request(), client_scope_hash=scope(request())
        )
    assert caught.value is marker
    assert marker.__cause__ is None
    assert marker.__context__ is None

    delayed = engine(ScriptedEngine.delay(1.0, ScriptedEngine.allow()))
    with pytest.raises(concurrent.futures.CancelledError):
        FakeTransport(delayed, testing_only=True).decide(
            request(),
            client_scope_hash=scope(request()),
            cancelled=lambda: True,
        )


def test_mock_server_closes_half_open_and_slow_connections_within_bound() -> None:
    scripted = engine(ScriptedEngine.allow())
    server = MockDecisionServer(
        scripted,
        testing_only=True,
        connection_timeout=0.1,
    ).start()
    sockets: list[socket.socket] = []
    try:
        half_open = socket.create_connection((server.host, server.port))
        half_open.sendall(b"POST /v1/authorization/decisions HTTP/1.1\r\n")
        sockets.append(half_open)
        incomplete = socket.create_connection((server.host, server.port))
        incomplete.sendall(
            b"POST /v1/authorization/decisions HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 100\r\n\r\n{}"
        )
        sockets.append(incomplete)
        slow = socket.create_connection((server.host, server.port))
        slow.sendall(b"P")
        sockets.append(slow)
        time.sleep(0.2)
        slow.settimeout(0.2)
        assert slow.recv(1) == b""
        oversized = socket.create_connection((server.host, server.port))
        oversized.sendall(b"GET / HTTP/1.1\r\nX-Test: " + b"x" * 70_000 + b"\r\n\r\n")
        oversized.settimeout(0.5)
        assert b"431" in oversized.recv(512).split(b"\r\n", 1)[0]
        oversized.close()
        started = time.monotonic()
        closers = [threading.Thread(target=server.close) for _ in range(3)]
        for closer in closers:
            closer.start()
        for closer in closers:
            closer.join()
        assert time.monotonic() - started < 1.0
        assert server.closed
    finally:
        server.close()
        for connection in sockets:
            connection.close()


def test_mock_server_disconnect_stress_is_silent_and_leak_free() -> None:
    before = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("palonexus-mock")
    }
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        for _ in range(40):
            server = MockDecisionServer(
                engine(ScriptedEngine.allow()),
                testing_only=True,
                connection_timeout=0.05,
            ).start()
            connection = socket.create_connection((server.host, server.port))
            connection.sendall(
                b"POST /v1/authorization/decisions HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
                b"Content-Length: 100\r\n\r\n{}"
            )
            connection.close()
            server.close()
    assert stderr.getvalue() == ""
    assert {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("palonexus-mock")
    } == before


def test_testing_package_has_no_embedded_policy_or_private_environment_names() -> None:
    root = Path(__file__).parents[1] / "src/palonexus/testing"
    source = "\n".join(
        path.read_text(encoding="utf-8").lower() for path in root.glob("*.py")
    )
    forbidden = (
        "evaluate_policy",
        "role_allow",
        "resource_allow",
        "cluster.local",
        "10.",
        "192.168.",
    )
    assert not any(token in source for token in forbidden)
