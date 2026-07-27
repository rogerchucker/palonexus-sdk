# SPDX-License-Identifier: MIT
"""Loopback-only HTTP decision server for SDK integration tests."""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final, Literal, Self

from .._generated import protocol as wire
from ..errors import PaloNexusError
from .fake_transport import ScriptedEngine

_DECISION_PATH: Final[str] = "/v1/authorization/decisions"


def _error_document(error: PaloNexusError) -> bytes:
    document: dict[str, object] = {
        "schemaVersion": "1",
        "code": error.code,
        "safeMessage": error.message,
        "retryable": error.retryable,
    }
    if error.request_id is not None:
        document["requestId"] = error.request_id
    if error.decision_id is not None:
        document["decisionId"] = error.decision_id
    if error.correlation_id is not None:
        document["correlationId"] = error.correlation_id
    return json.dumps(document, separators=(",", ":")).encode()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        engine: ScriptedEngine,
        connection_timeout: float,
    ) -> None:
        self.engine = engine
        self.connection_timeout = connection_timeout
        self._active: dict[socket.socket, threading.Timer] = {}
        self._active_lock = threading.Lock()
        super().__init__(address, _Handler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(self.connection_timeout)
        timer = threading.Timer(
            self.connection_timeout,
            self._expire_connection,
            args=(connection,),
        )
        timer.daemon = True
        with self._active_lock:
            self._active[connection] = timer
        timer.start()
        return connection, address

    def _expire_connection(self, connection: socket.socket) -> None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            connection.close()
        except OSError:
            pass

    def close_request(self, request: Any) -> None:
        with self._active_lock:
            timer = self._active.pop(request, None)
        if timer is not None:
            timer.cancel()
        super().close_request(request)

    def close_active(self) -> None:
        with self._active_lock:
            active = tuple(self._active.items())
            self._active.clear()
        for connection, timer in active:
            timer.cancel()
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def serve_bounded(self) -> None:
        self.serve_forever(poll_interval=0.01)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._send(405)

    def do_PUT(self) -> None:
        self._send(405)

    def do_DELETE(self) -> None:
        self._send(405)

    def do_PATCH(self) -> None:
        self._send(405)

    def do_HEAD(self) -> None:
        self._send(405)

    def do_OPTIONS(self) -> None:
        self._send(405)

    def do_POST(self) -> None:
        if self.path != _DECISION_PATH:
            self._send(404)
            return
        if (
            self.headers.get("Transfer-Encoding") is not None
            or self.headers.get("Content-Encoding") is not None
            or len(self.headers.get_all("Content-Length", [])) != 1
            or len(self.headers.get_all("Content-Type", [])) != 1
            or self.headers.get_content_type() != "application/json"
            or self.headers.get_content_charset() not in {None, "utf-8"}
        ):
            self._send(400)
            return
        try:
            raw_length = self.headers["Content-Length"]
            if (
                raw_length is None
                or not raw_length.isascii()
                or not raw_length.isdigit()
            ):
                raise ValueError
            length = int(raw_length)
            if length < 1 or length > wire.MAX_WIRE_BYTES:
                raise ValueError
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError
            request = wire.parse_action_json(body)
            scope_hash = self.headers.get("X-Palonexus-Client-Scope-Hash")
            if scope_hash is None:
                # Task 4 binds the scope in its request headers under this exact name.
                scope_hash = self.headers.get("PaloNexus-Client-Scope-Hash")
            if scope_hash is None:
                from .. import _canonicalize

                scope_hash = _canonicalize.client_scope_hash(request.to_dict())
            decision = self.server.engine.decide(
                request,
                client_scope_hash=scope_hash,
            )
            self._send(
                200,
                json.dumps(decision.to_dict(), separators=(",", ":")).encode(),
            )
        except PaloNexusError as error:
            status = 409 if error.code == "idempotency_conflict" else 503
            self._send(status, _error_document(error))
        except Exception:
            self._send(400)


class MockDecisionServer:
    """Owned loopback server; construction is deliberately test-capability gated."""

    __slots__ = (
        "_server",
        "_thread",
        "_closed",
        "_started",
        "_state_lock",
        "_stopped",
    )

    def __init__(
        self,
        engine: ScriptedEngine,
        *,
        testing_only: Literal[True],
        host: str = "127.0.0.1",
        port: int = 0,
        connection_timeout: float = 1.0,
    ) -> None:
        if testing_only is not True or type(engine) is not ScriptedEngine:
            raise ValueError("testing_only=True and a ScriptedEngine are required")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("host must be an IP-literal loopback address") from None
        if not address.is_loopback or address.version != 4:
            raise ValueError("host must be an IPv4 loopback address")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            raise ValueError("port is invalid")
        if (
            isinstance(connection_timeout, bool)
            or not isinstance(connection_timeout, (int, float))
            or not math.isfinite(connection_timeout)
            or connection_timeout < 0.01
            or connection_timeout > 5.0
        ):
            raise ValueError("connection_timeout is invalid")
        self._server = _Server(
            (host, port),
            engine,
            float(connection_timeout),
        )
        self._thread = threading.Thread(
            target=self._server.serve_bounded,
            name="palonexus-mock-decision-server",
            daemon=False,
        )
        self._closed = False
        self._started = False
        self._state_lock = threading.RLock()
        self._stopped = threading.Event()

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    @property
    def thread_ident(self) -> int | None:
        return self._thread.ident

    def start(self) -> Self:
        with self._state_lock:
            if self._closed:
                raise RuntimeError("server is closed")
            if not self._started:
                self._thread.start()
                self._started = True
        return self

    def close(self) -> None:
        owner = False
        with self._state_lock:
            if not self._closed:
                self._closed = True
                owner = True
            started = self._started
        if not owner:
            self._stopped.wait()
            return
        try:
            self._server.close_active()
            if started:
                self._server.shutdown()
            self._server.server_close()
            if started:
                self._thread.join()
        finally:
            self._stopped.set()

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *args: object) -> None:
        del args
        self.close()


__all__ = ["MockDecisionServer"]
