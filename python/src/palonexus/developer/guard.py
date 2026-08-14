# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import socket
from collections.abc import Callable
from typing import Any

MAX_ENVELOPE_BYTES = 256 * 1024


class GuardProtocol:
    def __init__(
        self,
        *,
        run_id: str,
        descriptor_digest: str,
        input_digest: str,
        runtime_lease_id: str,
        invoke: Callable[[dict[str, Any]], dict[str, Any]],
    ):
        self.run_id = run_id
        self.descriptor_digest = descriptor_digest
        self.input_digest = input_digest
        self.runtime_lease_id = runtime_lease_id
        self.invoke = invoke
        self.last_response: dict[str, Any] | None = None

    def serve_once(self, transport: socket.socket) -> None:
        try:
            raw = _read_line(transport, MAX_ENVELOPE_BYTES)
            request = json.loads(raw, object_pairs_hook=_pairs)
            if (
                not isinstance(request, dict)
                or set(request) != {"action", "resource", "payload"}
                or not isinstance(request["payload"], dict)
            ):
                raise ValueError("invalid action envelope")
            envelope = {
                "schema_version": "palonexus.action-envelope/v1",
                "run_id": self.run_id,
                "descriptor_digest": self.descriptor_digest,
                "input_digest": self.input_digest,
                "runtime_lease_id": self.runtime_lease_id,
                **request,
            }
            response = self.invoke(envelope)
            if not isinstance(response, dict) or "status" not in response:
                raise ValueError("invalid cloud outcome")
        except Exception:
            response = {
                "status": "contract_error",
                "reason": "canonical action contract rejected",
            }
        self.last_response = response
        try:
            transport.sendall(
                json.dumps(
                    response,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode()
                + b"\n"
            )
        finally:
            transport.close()


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
            raise ValueError("action envelope too large")
        if b"\n" in chunk:
            break
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("action envelope incomplete")
    return raw[:-1]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate action field")
        value[key] = item
    return value
