from __future__ import annotations

import json
import socket
import threading

import pytest
from palonexus.developer.context import ActionDenied, ActionExpired, AgentContext
from palonexus.developer.guard import MAX_ENVELOPE_BYTES, GuardProtocol


def test_context_sends_one_bounded_descriptor_bound_canonical_action() -> None:
    parent, child = socket.socketpair()
    seen: list[dict] = []
    guard = GuardProtocol(
        run_id="run-1",
        descriptor_digest="a" * 64,
        input_digest="b" * 64,
        runtime_lease_id="runtime-1",
        invoke=lambda envelope: (
            seen.append(envelope)
            or {
                "status": "approved",
                "receipt": {"receipt_id": "receipt-1"},
                "result": {"assessment": {"risk": "low", "score": 0.2}},
            }
        ),
    )
    thread = threading.Thread(target=guard.serve_once, args=(parent,))
    thread.start()
    result = AgentContext.from_fd(child.detach()).actions.invoke(
        "release.assessment.publish",
        "release/demo",
        {"assessment": {"risk": "low", "score": 0.2}},
    )
    thread.join(timeout=2)
    assert result.receipt == {"receipt_id": "receipt-1"}
    assert seen == [
        {
            "schema_version": "palonexus.action-envelope/v1",
            "run_id": "run-1",
            "descriptor_digest": "a" * 64,
            "input_digest": "b" * 64,
            "runtime_lease_id": "runtime-1",
            "action": "release.assessment.publish",
            "resource": "release/demo",
            "payload": {"assessment": {"risk": "low", "score": 0.2}},
        }
    ]


@pytest.mark.parametrize(
    "status,error", [("denied", ActionDenied), ("expired", ActionExpired)]
)
def test_context_maps_terminal_outcomes(status, error) -> None:
    parent, child = socket.socketpair()
    guard = GuardProtocol(
        run_id="run",
        descriptor_digest="a" * 64,
        input_digest="b" * 64,
        runtime_lease_id="lease",
        invoke=lambda _: {"status": status, "reason": "policy"},
    )
    thread = threading.Thread(target=guard.serve_once, args=(parent,))
    thread.start()
    with pytest.raises(error):
        AgentContext.from_fd(child.detach()).actions.invoke("a", "r", {})
    thread.join(timeout=2)


def test_guard_rejects_bad_envelopes_without_cloud_call() -> None:
    calls = []
    guard = GuardProtocol(
        run_id="run",
        descriptor_digest="a" * 64,
        input_digest="b" * 64,
        runtime_lease_id="lease",
        invoke=lambda value: calls.append(value),
    )
    for raw in (b'{"action":"a","action":"b"}\n', b"x" * (MAX_ENVELOPE_BYTES + 1)):
        parent, child = socket.socketpair()
        thread = threading.Thread(target=guard.serve_once, args=(parent,))
        thread.start()
        child.sendall(raw)
        child.shutdown(socket.SHUT_WR)
        response = child.recv(4096)
        thread.join(timeout=2)
        assert json.loads(response)["status"] == "contract_error"
    assert calls == []
