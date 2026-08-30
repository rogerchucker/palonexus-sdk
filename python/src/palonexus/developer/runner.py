# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .context import CapabilityDenied
from .guard import GuardProtocol


@dataclass(frozen=True)
class RunnerResult:
    output: Any
    receipt: dict[str, Any] | None
    runtime_guarded: str
    runtime_isolated: str
    pending_action_id: str | None = None
    pending_spawn_request_id: str | None = None


class Runner:
    def __init__(
        self,
        *,
        guard_invoke: Callable[[dict[str, Any]], dict[str, Any]],
        child_environment: dict[str, str] | None = None,
    ) -> None:
        self.guard_invoke = guard_invoke
        self.child_environment = dict(child_environment or {})
        self.last_child_environment: dict[str, str] = {}

    def run(
        self,
        *,
        project: Path,
        agent_file: Path,
        descriptor: dict[str, Any],
        input_value: dict[str, Any],
        run_id: str,
        descriptor_digest: str,
        input_digest: str,
        runtime_lease_id: str,
        detach: bool = False,
    ) -> RunnerResult:
        project = project.resolve()
        expected = (project / (descriptor["module"] + ".py")).resolve()
        if agent_file.resolve() != expected or not expected.is_file():
            raise ValueError("agent file is not the descriptor entrypoint")
        _validate_object(input_value, descriptor.get("input_schema", {}))
        parent, child = socket.socketpair()
        guard = GuardProtocol(
            run_id=run_id,
            descriptor_digest=descriptor_digest,
            input_digest=input_digest,
            runtime_lease_id=runtime_lease_id,
            invoke=self.guard_invoke,
        )
        thread = threading.Thread(target=guard.serve_once, args=(parent,), daemon=True)
        thread.start()
        env = {
            key: value
            for key, value in self.child_environment.items()
            if key.upper()
            not in {
                "PNXS_DEVELOPER_TOKEN",
                "PNXS_AGENT_PRIVATE_KEY",
                "PNXS_RUNTIME_LEASE",
                "AUTHORIZATION",
            }
            and not key.upper().startswith("PNXS_CREDENTIAL")
        }
        env["PNXS_GUARD_FD"] = str(child.fileno())
        self.last_child_environment = dict(env)
        script = "\n".join(
            (
                "import importlib,json,os,sys",
                "from palonexus.developer.context import AgentContext",
                "from palonexus.developer.context import ActionPending",
                "from palonexus.developer.context import CapabilityDenied",
                "from palonexus.developer.context import SubagentSpawnPending",
                "sys.path.insert(0,os.getcwd())",
                "module=importlib.import_module(sys.argv[1])",
                "fn=getattr(module,sys.argv[2])",
                "value=json.loads(sys.stdin.read())",
                "context=AgentContext.from_fd(int(os.environ['PNXS_GUARD_FD']))",
                "try:",
                " outcome=fn(value,context)",
                " print(json.dumps(outcome,sort_keys=True,separators=(',',':')))",
                "except ActionPending as pending:",
                " print(json.dumps({'__pnxs_pending_action_id__':pending.action_id},",
                "  sort_keys=True,separators=(',',':')))",
                "except CapabilityDenied as denied:",
                " print(json.dumps({'__pnxs_capability_denied__':str(denied)},",
                "  sort_keys=True,separators=(',',':')))",
                "except SubagentSpawnPending as pending:",
                " print(json.dumps({",
                "  '__pnxs_pending_spawn_request_id__':pending.spawn_request_id},",
                "  sort_keys=True,separators=(',',':')))",
            )
        )
        process = subprocess.run(
            [sys.executable, "-c", script, descriptor["module"], descriptor["symbol"]],
            cwd=project,
            env=env,
            input=json.dumps(input_value),
            text=True,
            capture_output=True,
            pass_fds=(child.fileno(),),
            timeout=60,
        )
        child.close()
        thread.join(timeout=2)
        if process.returncode != 0:
            raise RuntimeError("guarded agent process failed")
        output = json.loads(process.stdout)
        if (
            isinstance(output, dict)
            and set(output) == {"__pnxs_capability_denied__"}
            and isinstance(output["__pnxs_capability_denied__"], str)
        ):
            raise CapabilityDenied(output["__pnxs_capability_denied__"])
        if (
            detach
            and isinstance(output, dict)
            and set(output) == {"__pnxs_pending_action_id__"}
        ):
            return RunnerResult(
                output=None,
                receipt=None,
                runtime_guarded="observed",
                runtime_isolated="not_configured",
                pending_action_id=output["__pnxs_pending_action_id__"],
            )
        if (
            detach
            and isinstance(output, dict)
            and set(output) == {"__pnxs_pending_spawn_request_id__"}
        ):
            return RunnerResult(
                output=None,
                receipt=None,
                runtime_guarded="observed",
                runtime_isolated="not_configured",
                pending_spawn_request_id=output["__pnxs_pending_spawn_request_id__"],
            )
        # The approved outcome is the only response the sample callable returns;
        # retain its receipt from the guard result without exposing credentials.
        receipt: dict[str, Any] | None = {"receipt_id": "unknown"}
        if (
            isinstance(output, dict)
            and output.get("receipt")
            and isinstance(output["receipt"], dict)
        ):
            receipt = output.pop("receipt")
        elif (guard.last_response or {}).get("status") == "spawn_result":
            receipt = None
        else:
            response = guard.last_response or {}
            if response.get("status") != "approved" or not isinstance(
                response.get("receipt"), dict
            ):
                raise RuntimeError("guarded action did not return a receipt")
            receipt = response["receipt"]
        _validate_object(output, descriptor.get("output_schema", {}))
        return RunnerResult(
            output=output,
            receipt=receipt,
            runtime_guarded="observed",
            runtime_isolated="not_configured",
        )

    def detach_persisted_action(self, envelope: dict[str, Any]) -> dict[str, Any]:
        result = self.guard_invoke(envelope)
        if (
            not isinstance(result, dict)
            or result.get("status") != "pending"
            or not result.get("action_id")
        ):
            raise RuntimeError("action was not durably persisted")
        return result

    def wait(
        self, action_id: str, poll: Callable[[str], dict[str, Any]]
    ) -> dict[str, Any]:
        return poll(action_id)


def _validate_object(value: Any, schema: dict[str, Any]) -> None:
    if schema.get("type") == "object":
        if not isinstance(value, dict):
            raise ValueError("schema validation failed")
        required = schema.get("required", [])
        if any(key not in value for key in required):
            raise ValueError("schema validation failed")
        if schema.get("additionalProperties") is False and set(value) - set(
            schema.get("properties", {})
        ):
            raise ValueError("schema validation failed")
