# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from typing import Any


class ActionError(RuntimeError):
    pass


class ActionDenied(ActionError):
    pass


class CapabilityDenied(ActionDenied):
    """The command is outside effective authority and cannot be human-approved."""

    def __init__(self, reason_code: str, message: str | None = None):
        self.reason_code = reason_code
        super().__init__(message or reason_code)


class ActionExpired(ActionError):
    pass


class ActionUnavailable(ActionError):
    pass


class ActionPending(ActionError):
    def __init__(self, action_id: str):
        self.action_id = action_id
        super().__init__("action pending")


class ActionContractError(ActionError):
    pass


@dataclass(frozen=True)
class ActionOutcome:
    result: Any
    receipt: dict[str, Any]


class Actions:
    def __init__(self, transport: socket.socket):
        self._transport = transport

    def invoke(
        self, action: str, resource: str, payload: dict[str, Any]
    ) -> ActionOutcome:
        if not all(
            isinstance(value, str) and value and value == value.strip()
            for value in (action, resource)
        ) or not isinstance(payload, dict):
            raise ActionContractError("invalid canonical action")
        raw = (
            json.dumps(
                {"action": action, "resource": resource, "payload": payload},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            + b"\n"
        )
        self._transport.sendall(raw)
        response = _read_line(self._transport, 1 << 20)
        try:
            value = json.loads(response, object_pairs_hook=_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            raise ActionContractError("guard response is invalid") from error
        status = value.get("status") if isinstance(value, dict) else None
        if (
            status == "approved"
            and set(value) == {"status", "receipt", "result"}
            and isinstance(value["receipt"], dict)
        ):
            return ActionOutcome(value["result"], value["receipt"])
        if (
            status == "pending"
            and set(value) == {"status", "action_id"}
            and isinstance(value["action_id"], str)
            and value["action_id"]
        ):
            raise ActionPending(value["action_id"])
        reason = (
            value.get("reason", "action refused")
            if isinstance(value, dict)
            else "action refused"
        )
        errors = {
            "denied": ActionDenied,
            "capability_denied": CapabilityDenied,
            "expired": ActionExpired,
            "unavailable": ActionUnavailable,
            "contract_error": ActionContractError,
        }
        error_type = (
            errors.get(status, ActionContractError)
            if isinstance(status, str)
            else ActionContractError
        )
        raise error_type(str(reason))


_MCP_NAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,127})?")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class MCP:
    """Thin MCP normalization facade over the governed local action guard."""

    def __init__(self, actions: Actions):
        self._actions = actions

    def call(
        self,
        *,
        server: str,
        tool: str,
        schema_digest: str,
        resource: str,
        arguments: dict[str, Any],
    ) -> ActionOutcome:
        if (
            not isinstance(server, str)
            or _MCP_NAME.fullmatch(server) is None
            or not isinstance(tool, str)
            or _MCP_NAME.fullmatch(tool) is None
            or not isinstance(schema_digest, str)
            or _SHA256.fullmatch(schema_digest) is None
        ):
            raise ActionContractError("invalid MCP tool identity")
        return self._actions.invoke(
            f"mcp:{server}/{tool}/{schema_digest}", resource, arguments
        )


class AgentContext:
    def __init__(self, transport: socket.socket):
        self.actions = Actions(transport)
        self.mcp = MCP(self.actions)

    @classmethod
    def from_fd(cls, fd: int) -> AgentContext:
        return cls(socket.socket(fileno=fd))


def _read_line(sock: socket.socket, maximum: int) -> bytes:
    chunks = []
    size = 0
    while True:
        chunk = sock.recv(min(65536, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            raise ActionContractError("guard response is too large")
        if b"\n" in chunk:
            break
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ActionContractError("guard response is incomplete")
    return raw[:-1]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value
