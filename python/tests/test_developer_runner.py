from __future__ import annotations

from pathlib import Path

import pytest
from palonexus.developer.context import CapabilityDenied
from palonexus.developer.runner import Runner, RunnerResult


def test_runner_uses_exact_descriptor_callable_and_child_has_no_credentials(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        "def review_release(change, context):\n"
        "    outcome = context.actions.invoke(\n"
        "        'release.assessment.publish', 'release/demo',\n"
        "        {'assessment': {'risk': change['risk'], 'score': 0.2}},\n"
        "    )\n"
        "    return outcome.result\n"
    )
    descriptor = {
        "module": "agent",
        "symbol": "review_release",
        "input_schema": {
            "type": "object",
            "required": ["risk"],
            "additionalProperties": False,
            "properties": {"risk": {"type": "string"}},
        },
        "output_schema": {"type": "object"},
    }
    runner = Runner(
        guard_invoke=lambda envelope: {
            "status": "approved",
            "receipt": {"receipt_id": "r1"},
            "result": {"ok": True},
        },
        child_environment={"PATH": "/usr/bin:/bin"},
    )
    result = runner.run(
        project=tmp_path,
        agent_file=tmp_path / "agent.py",
        descriptor=descriptor,
        input_value={"risk": "low"},
        run_id="run-1",
        descriptor_digest="a" * 64,
        input_digest="b" * 64,
        runtime_lease_id="lease-1",
    )
    assert result == RunnerResult(
        output={"ok": True},
        receipt={"receipt_id": "r1"},
        runtime_guarded="observed",
        runtime_isolated="not_configured",
    )
    assert not any(
        name in runner.last_child_environment
        for name in (
            "PNXS_DEVELOPER_TOKEN",
            "PNXS_AGENT_PRIVATE_KEY",
            "PNXS_RUNTIME_LEASE",
            "AUTHORIZATION",
        )
    )


def test_runner_detach_returns_only_after_action_persistence_and_wait_reattaches() -> (
    None
):
    created = []
    runner = Runner(
        guard_invoke=lambda envelope: (
            created.append(envelope) or {"status": "pending", "action_id": "action-1"}
        ),
        child_environment={},
    )
    result = runner.detach_persisted_action({"action": "release.assessment.publish"})
    assert (
        result == {"status": "pending", "action_id": "action-1"} and len(created) == 1
    )
    waits = []
    outcome = runner.wait(
        "action-1",
        lambda action_id: (
            waits.append(action_id)
            or {"status": "approved", "receipt": {"receipt_id": "r1"}}
        ),
    )
    assert (
        outcome["receipt"]["receipt_id"] == "r1"
        and waits == ["action-1"]
        and len(created) == 1
    )


def test_detached_child_pending_is_a_normal_persisted_result(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "def review_release(change, context):\n"
        "    outcome = context.actions.invoke(\n"
        "        'release.assessment.publish', 'release/demo', change)\n"
        "    return outcome.result\n"
    )
    runner = Runner(
        guard_invoke=lambda _envelope: {"status": "pending", "action_id": "action-1"}
    )
    result = runner.run(
        project=tmp_path,
        agent_file=tmp_path / "agent.py",
        descriptor={
            "module": "agent",
            "symbol": "review_release",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
        },
        input_value={"risk": "low"},
        run_id="run-1",
        descriptor_digest="a" * 64,
        input_digest="b" * 64,
        runtime_lease_id="lease-1",
        detach=True,
    )
    assert result.pending_action_id == "action-1" and result.output is None


def test_runner_preserves_terminal_capability_denial_from_child(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "def review_release(change, context):\n"
        "    context.actions.invoke(\n"
        "        'release.assessment.publish', 'release/demo', change\n"
        "    )\n"
        "    return {'unreachable': True}\n"
    )
    runner = Runner(
        guard_invoke=lambda _envelope: {
            "status": "capability_denied",
            "reason": "OUTSIDE_RUN_GRANT",
        }
    )
    with pytest.raises(CapabilityDenied, match="OUTSIDE_RUN_GRANT") as denied:
        runner.run(
            project=tmp_path,
            agent_file=tmp_path / "agent.py",
            descriptor={
                "module": "agent",
                "symbol": "review_release",
                "input_schema": {"type": "object"},
                "output_schema": {"type": "object"},
            },
            input_value={"risk": "low"},
            run_id="run-1",
            descriptor_digest="a" * 64,
            input_digest="b" * 64,
            runtime_lease_id="lease-1",
        )
    assert denied.value.reason_code == "OUTSIDE_RUN_GRANT"
